package runner

import (
	"context"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/projectdiscovery/ratelimit"
)

// Adaptive tuning defaults. The controller only adjusts scan parameters
// (rate / timeout / retries); it never fragments packets or randomizes
// source ports — there is no low-level evasion here.
const (
	adaptiveInterval     = 3 * time.Second // controller tick interval
	adaptiveMinSamples   = 200             // min probes in a window before reacting
	adaptiveRateFloor    = 50              // never throttle below this (pps)
	adaptiveRateRecover  = 1.15            // additive increase when network is healthy
	adaptiveRateDecrease = 0.5             // multiplicative decrease on congestion/loss
	adaptiveTimeoutMin   = 500 * time.Millisecond
	adaptiveTimeoutMax   = 5 * time.Second
	adaptiveRetriesMin   = 1
	adaptiveRetriesMax   = 8
)

// tuning is a snapshot of the live-adjustable scan parameters.
type tuning struct {
	Rate    int
	Timeout time.Duration
	Retries int
}

func (t tuning) String() string {
	return "rate=" + strconv.Itoa(t.Rate) + "pps timeout=" + t.Timeout.Round(time.Millisecond).String() + " retries=" + strconv.Itoa(t.Retries)
}

// AdaptiveTuner periodically reads probe telemetry (loss + RTT) and adapts
// the send rate, response timeout and number of retry rounds. It also keeps
// the diagnostic counters that are printed at the end of the scan.
type AdaptiveTuner struct {
	stats   *scan.ProbeStats
	limiter *ratelimit.Limiter

	baseRate    int // user-requested rate, treated as the upper bound
	baseTimeout time.Duration
	baseRetries int

	rateCeiling int // current adaptive upper bound (AIMD), <= baseRate

	prev scan.Snapshot // cumulative counters at previous tick

	mu              sync.Mutex
	cur             tuning
	retransmissions int      // total extra (retry) rounds actually executed
	retransGain     int      // newly open (ip,port) pairs attributed to retries
	adjustments     []string // human-readable parameter changes
	openBeforeRound int
	openCountFn     func() int

	wg       sync.WaitGroup
	cancelFn context.CancelFunc
}

// NewAdaptiveTuner wires the tuner to the scan stats, rate limiter and
// options. baseRate is the user-specified rate and is never exceeded.
func NewAdaptiveTuner(stats *scan.ProbeStats, limiter *ratelimit.Limiter, opts *Options) *AdaptiveTuner {
	baseRate := opts.Rate
	if baseRate <= 0 {
		baseRate = DefaultRateSynScan
	}
	baseTimeout := opts.GetTimeout()
	baseRetries := opts.Retries
	if baseRetries < adaptiveRetriesMin {
		baseRetries = DefaultRetriesSynScan
	}
	return &AdaptiveTuner{
		stats:       stats,
		limiter:     limiter,
		baseRate:    baseRate,
		baseTimeout: baseTimeout,
		baseRetries: baseRetries,
		rateCeiling: baseRate,
		cur:         tuning{Rate: baseRate, Timeout: baseTimeout, Retries: baseRetries},
	}
}

// SetOpenCountFn supplies the live count of open (ip,port) pairs, used to
// measure how much each retransmission round recovered.
func (t *AdaptiveTuner) SetOpenCountFn(fn func() int) {
	t.mu.Lock()
	t.openCountFn = fn
	t.mu.Unlock()
}

// Start launches the background control loop.
func (t *AdaptiveTuner) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	t.cancelFn = cancel
	t.wg.Add(1)
	go t.loop(ctx)
	gologger.Info().Msgf("Adaptive mode enabled: tuning rate/timeout/retries from live loss & RTT (base %s)", t.cur)
}

// Stop terminates the control loop.
func (t *AdaptiveTuner) Stop() {
	if t.cancelFn != nil {
		t.cancelFn()
	}
	t.wg.Wait()
}

// EffectiveRetries returns the current adapted number of retry rounds.
func (t *AdaptiveTuner) EffectiveRetries() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cur.Retries
}

// EffectiveTimeout returns the current adapted response timeout.
func (t *AdaptiveTuner) EffectiveTimeout() time.Duration {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.cur.Timeout
}

// RoundStart marks the beginning of a scan round (0-based).
func (t *AdaptiveTuner) RoundStart(roundNo int) {
	t.mu.Lock()
	t.openBeforeRound = t.openCount()
	t.mu.Unlock()
}

// RoundEnd marks the end of a scan round. Rounds after the first are
// retransmissions; the new open ports they produced are the retransmission
// gain (proof that extra rounds help on this network).
func (t *AdaptiveTuner) RoundEnd(roundNo int) {
	if roundNo <= 0 {
		return
	}
	t.mu.Lock()
	t.retransmissions++
	if gain := t.openCount() - t.openBeforeRound; gain > 0 {
		t.retransGain += gain
	}
	t.mu.Unlock()
}

func (t *AdaptiveTuner) openCount() int {
	if t.openCountFn != nil {
		return t.openCountFn()
	}
	return 0
}

func (t *AdaptiveTuner) loop(ctx context.Context) {
	defer t.wg.Done()
	ticker := time.NewTicker(adaptiveInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.tick()
		}
	}
}

func (t *AdaptiveTuner) tick() {
	snap := t.stats.Snapshot()
	win := windowDiff(t.prev, snap)
	t.prev = snap

	// Wait until enough traffic has been observed to judge the network.
	if win.sent < adaptiveMinSamples {
		return
	}

	rtt := win.avgRTT()
	loss := win.lossRate()

	t.mu.Lock()
	next := t.cur
	var msgs []string

	// --- Rate: AIMD, bounded by the user's requested rate ---
	switch {
	case loss > 0.30:
		// severe loss/congestion: back off hard
		next.Rate = maxInt(adaptiveRateFloor, int(float64(next.Rate)*adaptiveRateDecrease))
		t.rateCeiling = next.Rate
	case loss > 0.12 || (rtt > 0 && rtt > t.baseTimeout):
		// moderate loss or latency exceeding timeout: ease off
		next.Rate = maxInt(adaptiveRateFloor, int(float64(next.Rate)*0.75))
		t.rateCeiling = next.Rate
	default:
		// healthy: probe for more bandwidth up to the user ceiling
		cand := int(float64(next.Rate) * adaptiveRateRecover)
		if cand > t.rateCeiling {
			t.rateCeiling = minInt(t.baseRate, cand)
		}
		next.Rate = t.rateCeiling
	}

	// --- Timeout: track RTT so slow links don't strand responses ---
	if rtt > 0 {
		target := time.Duration(float64(rtt) * 3.0)
		switch {
		case loss > 0.12:
			target = time.Duration(float64(target) * 1.5)
			next.Timeout = clampDuration(maxDuration(next.Timeout, target), adaptiveTimeoutMin, adaptiveTimeoutMax)
		case target > next.Timeout:
			next.Timeout = clampDuration(target, adaptiveTimeoutMin, adaptiveTimeoutMax)
		case target < next.Timeout/2 && next.Timeout > t.baseTimeout:
			// network recovered: relax back toward the base timeout
			next.Timeout = clampDuration(next.Timeout*3/4, adaptiveTimeoutMin, adaptiveTimeoutMax)
		}
	}

	// --- Retries: lossy networks need more rounds ---
	switch {
	case loss > 0.25 && next.Retries < adaptiveRetriesMax:
		next.Retries++
	case loss < 0.05 && next.Retries > t.baseRetries:
		next.Retries--
	}

	if next != t.cur {
		msgs = diff(t.cur, next)
		t.cur = next
		t.apply(next)
	}
	adjustCount := len(msgs)
	t.mu.Unlock()

	for _, m := range msgs {
		gologger.Info().Msgf("Adaptive: %s (window loss=%.1f%% rtt=%s)", m, loss*100, rtt.Round(time.Millisecond))
	}
	if adjustCount > 0 {
		t.mu.Lock()
		t.adjustments = append(t.adjustments, msgs...)
		t.mu.Unlock()
	}
}

func (t *AdaptiveTuner) apply(n tuning) {
	// Rate is applied live through the limiter (atomic). Timeout and
	// retries are read by the scan loop through EffectiveTimeout /
	// EffectiveRetries; we deliberately do not mutate the shared Options
	// struct here to avoid a data race with the main scan goroutine.
	if t.limiter != nil {
		t.limiter.SetLimit(uint(n.Rate))
	}
}

// Report prints the end-of-scan diagnostic statistics so the user can
// judge whether the network was suitable for scanning.
func (t *AdaptiveTuner) Report() {
	snap := t.stats.Snapshot()
	loss := lossRateTotal(snap)
	avgRTT := snap.AvgRTT

	t.mu.Lock()
	retrans := t.retransmissions
	gain := t.retransGain
	final := t.cur
	adjusts := len(t.adjustments)
	t.mu.Unlock()

	var b strings.Builder
	b.WriteString("\nAdaptive scan diagnostics\n")
	b.WriteString("  probes sent:      " + strconv.FormatUint(snap.Sent, 10) + "\n")
	b.WriteString("  responses:        " + strconv.FormatUint(snap.Acked, 10) + " (open) / " + strconv.FormatUint(snap.Rst, 10) + " (closed/rst) / " + strconv.FormatUint(snap.Failed, 10) + " (send errors)\n")
	b.WriteString("  estimated loss:   " + pct(loss) + " of probes unanswered\n")
	if avgRTT > 0 {
		b.WriteString("  avg RTT:          " + avgRTT.Round(time.Microsecond).String() + "\n")
	} else {
		b.WriteString("  avg RTT:          n/a (no matched RTT samples)\n")
	}
	b.WriteString("  retransmissions:  " + strconv.Itoa(retrans) + " extra round(s)")
	if gain > 0 {
		b.WriteString(", recovered " + strconv.Itoa(gain) + " open port(s) that earlier rounds missed")
	}
	b.WriteString("\n")
	b.WriteString("  final params:     " + final.String() + "\n")
	b.WriteString("  adjustments:      " + strconv.Itoa(adjusts) + " parameter change(s)\n")
	b.WriteString("  network verdict:  " + networkVerdict(loss, avgRTT, snap.Failed))

	gologger.Info().Msgf("%s", b.String())
}

// networkVerdict maps the observed conditions to a human-readable verdict.
func networkVerdict(loss float64, rtt time.Duration, failed uint64) string {
	switch {
	case failed > 0 && loss > 0.5:
		return "POOR - many probes failed to send or were lost; scan results are likely incomplete, reduce rate or check connectivity"
	case loss > 0.3:
		return "POOR - high packet loss; results may miss ports, adaptive mode throttled rate and added retries"
	case loss > 0.12:
		return "FAIR - noticeable loss/latency; consider lowering -rate or scanning at a less congested time"
	case rtt > 500*time.Millisecond:
		return "FAIR - high latency; timeouts were extended, expect slower scanning"
	default:
		return "GOOD - low loss and latency, scan results should be reliable"
	}
}

// ---- windowed counters ----

type winStats struct {
	sent   uint64
	acked  uint64
	rst    uint64
	failed uint64
	rttN   uint64
	rttSum time.Duration
}

func windowDiff(prev, cur scan.Snapshot) winStats {
	return winStats{
		sent:   diffU(prev.Sent, cur.Sent),
		acked:  diffU(prev.Acked, cur.Acked),
		rst:    diffU(prev.Rst, cur.Rst),
		failed: diffU(prev.Failed, cur.Failed),
		rttN:   diffU(prev.RTTCount, cur.RTTCount),
		rttSum: cur.RTTSum - prev.RTTSum,
	}
}

// lossRate estimates the fraction of probes that got no response. On SYN
// scans most closed/filtered ports stay silent, so a high "unanswered"
// share is partly structural; the controller reacts only when that share
// is high enough to also indicate congestion/loss, and cross-checks with
// RTT. The estimate is intentionally conservative.
func (w winStats) lossRate() float64 {
	if w.sent == 0 {
		return 0
	}
	answered := w.acked + w.rst
	if answered > w.sent {
		answered = w.sent
	}
	return 1 - float64(answered)/float64(w.sent)
}

func (w winStats) avgRTT() time.Duration {
	if w.rttN == 0 {
		return 0
	}
	return time.Duration(int64(w.rttSum) / int64(w.rttN))
}

func lossRateTotal(s scan.Snapshot) float64 {
	if s.Sent == 0 {
		return 0
	}
	answered := s.Acked + s.Rst
	if answered > s.Sent {
		answered = s.Sent
	}
	return 1 - float64(answered)/float64(s.Sent)
}

func diffU(prev, cur uint64) uint64 {
	if cur > prev {
		return cur - prev
	}
	return 0
}

func diff(before, after tuning) []string {
	var msgs []string
	if after.Rate != before.Rate {
		msgs = append(msgs, "rate "+dir(after.Rate, before.Rate)+" "+strconv.Itoa(before.Rate)+"->"+strconv.Itoa(after.Rate)+"pps")
	}
	if after.Timeout != before.Timeout {
		msgs = append(msgs, "timeout "+dirDur(after.Timeout, before.Timeout)+" "+before.Timeout.Round(time.Millisecond).String()+"->"+after.Timeout.Round(time.Millisecond).String())
	}
	if after.Retries != before.Retries {
		msgs = append(msgs, "retries "+dir(after.Retries, before.Retries)+" "+strconv.Itoa(before.Retries)+"->"+strconv.Itoa(after.Retries))
	}
	return msgs
}

func dir(after, before int) string {
	if after < before {
		return "decreased"
	}
	return "increased"
}

func dirDur(after, before time.Duration) string {
	if after < before {
		return "decreased"
	}
	return "increased"
}

func pct(f float64) string { return strconv.Itoa(int(f*100+0.5)) + "%" }

func clampDuration(d, lo, hi time.Duration) time.Duration {
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

func maxDuration(a, b time.Duration) time.Duration {
	if a > b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
