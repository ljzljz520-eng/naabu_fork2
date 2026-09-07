package runner

import (
	"context"
	"testing"
	"time"

	"github.com/projectdiscovery/naabu/v2/pkg/scan"
	"github.com/projectdiscovery/ratelimit"
)

func newTestTuner(t *testing.T, rate int) (*AdaptiveTuner, *ratelimit.Limiter) {
	t.Helper()
	stats := scan.ResetProbeStats()
	limiter := ratelimit.New(context.Background(), uint(rate), time.Second)
	opts := &Options{
		Rate:     rate,
		Retries:  3,
		Timeout:  time.Second,
		ScanType: ConnectScan,
	}
	tun := NewAdaptiveTuner(stats, limiter, opts)
	return tun, limiter
}

// simulateWindow records sent probes with a given fraction answered via
// SYN-ACK (which also produces RTT samples) and the rest via RST.
func simulateWindow(sent, acked, rst int) {
	for i := 1; i <= sent; i++ {
		scan.RecordSynSent(uint32(i))
	}
	for i := 1; i <= acked; i++ {
		scan.RecordSynAck(uint32(i) + 1) // ack = seq+1
	}
	for i := 0; i < rst; i++ {
		scan.RecordRst()
	}
}

func TestAdaptive_HighLoss_ThrottlesAndAddsRetries(t *testing.T) {
	tun, limiter := newTestTuner(t, 1000)

	// 1000 probes sent, only 100 answered -> ~90% loss.
	simulateWindow(1000, 100, 0)
	tun.tick()

	if got := tun.EffectiveRetries(); got != 4 {
		t.Fatalf("expected retries to increase to 4 on high loss, got %d", got)
	}
	if got := limiter.GetLimit(); got != 500 {
		t.Fatalf("expected rate to be halved to 500 on severe loss, got %d", got)
	}
}

func TestAdaptive_HealthyNetwork_StaysAtBaseRate(t *testing.T) {
	tun, limiter := newTestTuner(t, 1000)

	// 1000 probes, 950 answered -> ~5% loss (healthy).
	simulateWindow(1000, 800, 150)
	tun.tick()

	if got := limiter.GetLimit(); got != 1000 {
		t.Fatalf("expected rate to stay at base 1000 on healthy network, got %d", got)
	}
	if got := tun.EffectiveRetries(); got != 3 {
		t.Fatalf("expected retries to stay at 3 on healthy network, got %d", got)
	}
}

func TestAdaptive_RecoversAfterCongestion(t *testing.T) {
	tun, _ := newTestTuner(t, 1000)

	// First window: severe loss -> back off and add a retry round.
	simulateWindow(1000, 50, 0)
	tun.tick()
	if got := tun.EffectiveRetries(); got != 4 {
		t.Fatalf("expected retries 4 after congestion, got %d", got)
	}

	// Second window: very healthy (98% answered) -> retries relax back.
	simulateWindow(1000, 980, 0)
	tun.tick()
	if got := tun.EffectiveRetries(); got != 3 {
		t.Fatalf("expected retries to relax back to 3 on recovery, got %d", got)
	}
	if rate := tun.EffectiveRetries(); rate < 3 {
		t.Fatalf("retries should not drop below base, got %d", rate)
	}
}

func TestAdaptive_RTTMeasuredFromSynAck(t *testing.T) {
	stats := scan.ResetProbeStats()
	scan.RecordSynSent(42)
	time.Sleep(2 * time.Millisecond)
	scan.RecordSynAck(43) // ack = seq(42) + 1

	snap := stats.Snapshot()
	if snap.Sent != 1 || snap.Acked != 1 {
		t.Fatalf("unexpected counters: sent=%d acked=%d", snap.Sent, snap.Acked)
	}
	if snap.RTTCount != 1 {
		t.Fatalf("expected 1 RTT sample, got %d", snap.RTTCount)
	}
	if snap.AvgRTT < time.Millisecond {
		t.Fatalf("expected RTT >= 1ms, got %s", snap.AvgRTT)
	}
}

func TestAdaptive_ReportCounters(t *testing.T) {
	tun, _ := newTestTuner(t, 1000)
	simulateWindow(500, 300, 100)
	tun.tick()

	snap := tun.stats.Snapshot()
	if snap.Sent != 500 {
		t.Fatalf("expected 500 sent, got %d", snap.Sent)
	}
	// answered = 300 ack + 100 rst = 400 -> loss 20%
	w := windowDiff(scan.Snapshot{}, snap)
	if got := w.lossRate(); got < 0.19 || got > 0.21 {
		t.Fatalf("expected ~0.20 loss, got %f", got)
	}
}
