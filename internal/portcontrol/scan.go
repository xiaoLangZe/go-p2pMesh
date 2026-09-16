package portcontrol

import (
	"sync"
	"time"
)

// Scanner implements invariant I10 layers 2 and 3 (§8.4):
//
//   - layer 2 per-source rate limiting of probes to *unconfigured* ports
//     (10/s, burst 20; configured-port traffic is never counted or throttled
//     — the controller's Decide handles those before the scanner is asked);
//   - layer 3 anomaly detection: one source touching 100+ distinct
//     unconfigured ports inside 60s is reported (audit + master) and
//     blacklisted for 5 minutes.
//
// Layer 1 (silent drop) and layer 4 (never rely on address secrecy) are the
// caller's contract: the scanner only decides whether a probe is *recorded*,
// never what the network replies.
type Scanner struct {
	mu sync.Mutex

	// window is the anomaly accounting window.
	window time.Duration
	// threshold is the distinct-port count that marks a scan.
	threshold int
	// rate and burst bound per-source probe admission (permits/s, tokens).
	rate  float64
	burst int
	// blacklist holds the source key to its un-blacklist time.
	blacklist    map[string]time.Time
	blacklistFor time.Duration

	// ports tracks, per source, the set of distinct probed ports with the
	// last time each was seen.
	ports map[string]map[int]time.Time
	// buckets is the per-source token bucket.
	buckets map[string]*tokenBucket

	// OnAnomaly fires once per blacklisting event so the caller can audit
	// and report to the master. May be nil.
	OnAnomaly func(source string, distinctPorts int)

	// now is the clock; injectable for tests.
	now func() time.Time
}

// ProbeDisposition reports what the caller should do about one probe to an
// unconfigured port. Every disposition means the packet is dropped
// silently; the value only governs accounting (I10: the scan defence must
// be invisible to the prober).
type ProbeDisposition string

const (
	// ProbeExempt: same-room probe — drop, no accounting, no blacklist
	// (§8.1.1 同房间豁免).
	ProbeExempt ProbeDisposition = "exempt"
	// ProbeRecorded: out-of-room probe within rate limits — drop, recorded.
	ProbeRecorded ProbeDisposition = "recorded"
	// ProbeRateLimited: out-of-room probe over rate — drop, unrecorded.
	ProbeRateLimited ProbeDisposition = "rate_limited"
	// ProbeBlacklisted: source on the 5-minute blacklist — drop, unrecorded.
	ProbeBlacklisted ProbeDisposition = "blacklisted"
)

// NewScanner creates a Scanner with the design defaults (§8.4):
// 60s window, 100-port threshold, 10/s rate with burst 20, 5-minute
// blacklist.
func NewScanner() *Scanner {
	return &Scanner{
		window:       60 * time.Second,
		threshold:    100,
		rate:         10,
		burst:        20,
		blacklist:    make(map[string]time.Time),
		blacklistFor: 5 * time.Minute,
		ports:        make(map[string]map[int]time.Time),
		buckets:      make(map[string]*tokenBucket),
		now:          time.Now,
	}
}

// Probe records an attempt on an *unconfigured* port. The caller must have
// already established via Controller.Decide that no rule covers the port;
// probes to configured ports must never reach this method — that would
// throttle legitimate traffic (§8.4 layer 2's explicit scope).
func (s *Scanner) Probe(source string, port int, sameRoom bool) ProbeDisposition {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()

	// Lazy-expire blacklist entries.
	if until, ok := s.blacklist[source]; ok {
		if now.Before(until) {
			return ProbeBlacklisted
		}
		delete(s.blacklist, source)
		delete(s.ports, source)
		delete(s.buckets, source)
	}

	// Same-room exemption: drop silently, count nothing, never blacklist.
	if sameRoom {
		return ProbeExempt
	}

	// Record the distinct port and prune the window.
	set := s.ports[source]
	if set == nil {
		set = make(map[int]time.Time)
		s.ports[source] = set
	}
	set[port] = now
	for p, t := range set {
		if now.Sub(t) > s.window {
			delete(set, p)
		}
	}

	// Anomaly: too many distinct unconfigured ports inside the window.
	if len(set) >= s.threshold {
		s.blacklist[source] = now.Add(s.blacklistFor)
		delete(s.ports, source)
		delete(s.buckets, source)
		if s.OnAnomaly != nil {
			s.OnAnomaly(source, len(set))
		}
		return ProbeBlacklisted
	}

	// Rate limit: one token per recorded probe.
	b := s.buckets[source]
	if b == nil {
		b = newTokenBucket(s.rate, float64(s.burst), now)
		s.buckets[source] = b
	}
	if !b.take(now) {
		return ProbeRateLimited
	}
	return ProbeRecorded
}

// BlacklistSecondsLeft reports remaining blacklist time for a source, for
// observability. Negative or zero when not blacklisted.
func (s *Scanner) BlacklistSecondsLeft(source string) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	until, ok := s.blacklist[source]
	if !ok {
		return 0
	}
	return until.Sub(s.now()).Seconds()
}

// tokenBucket is a classic token bucket with continuous refill.
type tokenBucket struct {
	rate   float64 // tokens per second
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucket(rate, burst float64, now time.Time) *tokenBucket {
	return &tokenBucket{rate: rate, burst: burst, tokens: burst, last: now}
}

func (b *tokenBucket) take(now time.Time) bool {
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Blacklisted is kept exported for the control plane: the 5-minute local
// blacklist is also how the node decides to stop answering a source's DHT
// pings after a scan burst (I10 layer 3's "重复则本地拉黑").