package scan

import (
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// probeTTL bounds how long a sent-probe timestamp is kept while waiting
// for its SYN-ACK. Entries older than this are evicted on read, so the
// pending map cannot grow unbounded on a lossy network.
const probeTTL = 10 * time.Second

// ProbeStats collects lightweight, in-flight telemetry about outbound
// probes and inbound responses. It is used by the adaptive tuner to
// estimate loss rate and RTT; it does not alter any packet and performs
// no fragmentation or source-port evasion.
//
// All methods are safe for concurrent use. A nil *ProbeStats is a valid
// no-op receiver so the packet hot path can call them unconditionally
// without a feature-flag branch.
type ProbeStats struct {
	sent    atomic.Uint64 // probes handed to the socket (SYN / CONNECT dial)
	acked   atomic.Uint64 // SYN-ACK / successful connect responses
	rst     atomic.Uint64 // TCP RST responses (closed/filtered ports)
	failed  atomic.Uint64 // send / dial errors
	rtCount atomic.Uint64
	rtSum   atomic.Int64 // sum of RTT in nanoseconds

	mu      sync.Mutex
	pending map[uint32]int64 // seq -> send time (unix nano)
}

// package-level singleton; nil until EnableProbeStats is called.
var globalProbeStats *ProbeStats

// EnableProbeStats turns on probe telemetry collection and returns the
// shared stats instance. It is safe to call once at scan start.
func EnableProbeStats() *ProbeStats {
	if globalProbeStats != nil {
		return globalProbeStats
	}
	ps := &ProbeStats{pending: make(map[uint32]int64, 1<<16)}
	globalProbeStats = ps
	return ps
}

// GetProbeStats returns the active stats instance, or nil when adaptive
// mode is disabled.
func GetProbeStats() *ProbeStats { return globalProbeStats }

// ResetProbeStats clears the global probe telemetry and returns a fresh
// instance. Intended for tests that need a deterministic starting state.
func ResetProbeStats() *ProbeStats {
	globalProbeStats = &ProbeStats{pending: make(map[uint32]int64, 1<<16)}
	return globalProbeStats
}

// NextSeq returns the next shared TCP sequence number. Both the standard
// gopacket sender and the fast zero-copy sender must draw sequence numbers
// from here so that a SYN-ACK acknowledgement can be matched back to a send
// timestamp. It only allocates a number; SYN probes additionally call
// RecordSynSent (plain ACK packets must not be tracked as probes).
func NextSeq() uint32 { return tcpsequencer.Next() }

// RecordSynSent records a SYN probe as sent and remembers its send time so
// the matching SYN-ACK can produce an RTT sample.
func RecordSynSent(seq uint32) {
	if ps := globalProbeStats; ps != nil {
		ps.trackSent(seq)
	}
}

// trackSent records a probe as sent. For SYN scans, seq is the packet's
// TCP sequence number (used for RTT matching); for CONNECT scans pass 0.
func (ps *ProbeStats) trackSent(seq uint32) {
	ps.sent.Add(1)
	if seq == 0 {
		return
	}
	now := time.Now().UnixNano()
	ps.mu.Lock()
	ps.pending[seq] = now
	ps.evictLocked(now)
	ps.mu.Unlock()
}

// RecordConnectSent records a CONNECT-scan dial attempt (no seq).
func RecordConnectSent() {
	if ps := globalProbeStats; ps != nil {
		ps.sent.Add(1)
	}
}

// RecordConnectResult records a CONNECT-scan dial outcome. A successful
// dial counts as an open response; a fast rejection (connection refused)
// counts as a RST; a timeout means no response came back and is left as
// an unanswered probe (driving the loss signal).
func RecordConnectResult(open bool, err error) {
	ps := globalProbeStats
	if ps == nil {
		return
	}
	switch {
	case open:
		ps.acked.Add(1)
	case isNetTimeout(err):
		// no response within the dial deadline -> treated as loss
	default:
		ps.rst.Add(1)
	}
}

// isNetTimeout reports whether err is a network timeout (deadline
// exceeded / i/o timeout), as opposed to a connection refused RST.
func isNetTimeout(err error) bool {
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) {
		return ne.Timeout()
	}
	return false
}

// RecordSendFailure records a low-level send error.
func RecordSendFailure() {
	if ps := globalProbeStats; ps != nil {
		ps.failed.Add(1)
	}
}

// RecordSynAck matches a SYN-ACK (whose acknowledgement number is seq+1)
// to its send timestamp and records the round-trip time.
func RecordSynAck(ack uint32) {
	ps := globalProbeStats
	if ps == nil {
		return
	}
	ps.acked.Add(1)
	ps.matchRTT(ack - 1)
}

// RecordRst records a TCP RST response.
func RecordRst() {
	if ps := globalProbeStats; ps != nil {
		ps.rst.Add(1)
	}
}

func (ps *ProbeStats) matchRTT(seq uint32) {
	now := time.Now().UnixNano()
	ps.mu.Lock()
	sentAt, ok := ps.pending[seq]
	if ok {
		delete(ps.pending, seq)
	}
	ps.evictLocked(now)
	ps.mu.Unlock()
	if ok && now > sentAt {
		ps.rtSum.Add(now - sentAt)
		ps.rtCount.Add(1)
	}
}

// evictLocked drops pending entries older than probeTTL. Caller holds mu.
func (ps *ProbeStats) evictLocked(now int64) {
	cutoff := now - int64(probeTTL)
	// Amortized cleanup: only scan when the map is reasonably large.
	if len(ps.pending) < 4096 {
		return
	}
	for seq, t := range ps.pending {
		if t < cutoff {
			delete(ps.pending, seq)
		}
	}
}

// Snapshot is a point-in-time, cumulative view of the probe telemetry.
type Snapshot struct {
	Sent     uint64
	Acked    uint64
	Rst      uint64
	Failed   uint64
	RTTCount uint64
	RTTSum   time.Duration // cumulative sum of all RTT samples
	AvgRTT   time.Duration
}

// Snapshot returns the cumulative counters since the scan started.
func (ps *ProbeStats) Snapshot() Snapshot {
	if ps == nil {
		return Snapshot{}
	}
	snap := Snapshot{
		Sent:   ps.sent.Load(),
		Acked:  ps.acked.Load(),
		Rst:    ps.rst.Load(),
		Failed: ps.failed.Load(),
	}
	sum := ps.rtSum.Load()
	if n := ps.rtCount.Load(); n > 0 {
		snap.RTTCount = n
		snap.RTTSum = time.Duration(sum)
		snap.AvgRTT = time.Duration(sum / int64(n))
	}
	return snap
}
