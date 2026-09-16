// Package relay implements the server-side relay from DESIGN.md §18.
//
// Transit moved off the clients and onto servers (A5): every server that is
// not the root relays opaque, end-to-end-encrypted traffic between peers
// that cannot establish any direct or peer-forwarded path. The relay never
// decrypts — the session keys required to do so exist only at the two ends
// (§18.3).
//
// Three hard rules are encoded here:
//
//   - I9: the root never relays. A root-configured Hub refuses all
//     forwarding, even if someone registers endpoints on it.
//   - Conditional availability: relaying is a capability of *non-root*
//     servers; a deployment with only a root server has no relay and the
//     "some pairs unreachable" limit applies again.
//   - Master priority isolation: when the master relays, forwarding draws
//     from a quota that can never consume the server's headroom reserved
//     for address service (§18.3).
package relay

import (
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

// ErrNotImplemented is gone from this package — see errors below.
var (
	// ErrRootNeverRelays is returned when a root-configured hub is asked to
	// forward (invariant I9).
	ErrRootNeverRelays = errors.New("relay: the root server never relays")
	// ErrNoRoute is returned when an endpoint is not registered.
	ErrNoRoute = errors.New("relay: peer endpoint not registered")
	// ErrQuotaExceeded is returned when the master's relay quota is dry.
	ErrQuotaExceeded = errors.New("relay: master relay quota exceeded")
)

// Sink is where forwarded bytes go: a tunnel writer on the server side.
type Sink interface {
	io.Writer
}

// Hub is the in-process relay core. The transport layer (control-plane
// connection) delivers opaque packets to the Hub via Deliver; the Hub
// routes them to the registered Sink of the destination node.
//
// Routing state is nothing but a node→sink table plus accounting — the
// relay holds no session keys and no authority (I2/I3: it makes no
// judgements and derives no capabilities).
type Hub struct {
	mu      sync.Mutex
	isRoot  bool
	sinks   map[string]Sink
	quota   *tokenBucket
	quotaOn bool // master: quota-capped forwarding
	now     func() time.Time
}

// NewHub creates a relay hub.
//
//   - isRoot must be true when this server is the root: the hub will then
//     refuse every forwarding operation (I9).
//   - masterQuota > 0 enables the master priority quota: forwarding is
//     capped at that many bytes per second so the address service always
//     keeps headroom (§18.3).
func NewHub(isRoot bool, masterQuota int64) *Hub {
	h := &Hub{
		isRoot: isRoot,
		sinks:  make(map[string]Sink),
		now:    time.Now,
	}
	if masterQuota > 0 {
		h.quota = newByteBucket(masterQuota)
		h.quotaOn = true
	}
	return h
}

// Root reports whether this hub refuses to relay (I9).
func (h *Hub) Root() bool { return h.isRoot }

// Quotaed reports whether forwarding is quota-capped (master mode).
func (h *Hub) Quotaed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.quotaOn
}

// Register attaches a sink for a node. Re-registering replaces the sink.
// Registration is refused on a root hub as a first line of the I9 rule:
// the root carries no relay state at all.
func (h *Hub) Register(nodeID string, s Sink) error {
	if s == nil {
		return errors.New("relay: nil sink")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.isRoot {
		return ErrRootNeverRelays
	}
	h.sinks[nodeID] = s
	return nil
}

// Unregister detaches a node's sink.
func (h *Hub) Unregister(nodeID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.sinks, nodeID)
}

// Peers returns the registered node IDs (observability only).
func (h *Hub) Peers() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]string, 0, len(h.sinks))
	for id := range h.sinks {
		out = append(out, id)
	}
	return out
}

// Deliver forwards an opaque payload from one node to another.
//
// The payload is treated as ciphertext: the hub performs no inspection
// beyond routing, exactly the zero-knowledge contract of §18.3. Errors:
// ErrRootNeverRelays on a root hub, ErrQuotaExceeded when the master quota
// is dry, ErrNoRoute when the destination has no sink, or the sink's own
// write error.
func (h *Hub) Deliver(from, to string, payload []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.isRoot {
		return ErrRootNeverRelays
	}
	sink, ok := h.sinks[to]
	if !ok {
		return ErrNoRoute
	}
	if h.quotaOn && !h.quota.take(int64(len(payload)), h.now()) {
		return ErrQuotaExceeded
	}
	if _, err := sink.Write(payload); err != nil {
		return fmt.Errorf("relay: write to %s: %w", to, err)
	}
	return nil
}

// tokenBucket is a bytes-per-second quota with a small burst allowance.
type tokenBucket struct {
	rate   float64 // bytes per second
	burst  float64
	tokens float64
	last   time.Time
}

func newByteBucket(rate int64) *tokenBucket {
	return &tokenBucket{rate: float64(rate), burst: float64(rate), tokens: float64(rate)}
}

func (b *tokenBucket) take(n int64, now time.Time) bool {
	if b.last.IsZero() {
		b.last = now
		b.tokens = b.burst
	}
	elapsed := now.Sub(b.last).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.burst {
		b.tokens = b.burst
	}
	b.last = now
	if b.tokens < float64(n) {
		return false
	}
	b.tokens -= float64(n)
	return true
}