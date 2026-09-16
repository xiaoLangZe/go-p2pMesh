package relay

import (
	"bytes"
	"sync"
	"testing"
	"time"
)

// memSink records writes to a buffer.
type memSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *memSink) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *memSink) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.buf.Bytes()...)
}

// TestRootNeverRelays checks invariant I9 at the API surface.
func TestRootNeverRelays(t *testing.T) {
	h := NewHub(true, 0)
	if !h.Root() {
		t.Fatal("hub must report root mode")
	}
	if err := h.Register("a", &memSink{}); err != ErrRootNeverRelays {
		t.Errorf("Register on root: got %v, want ErrRootNeverRelays", err)
	}
	if err := h.Deliver("a", "b", []byte("x")); err != ErrRootNeverRelays {
		t.Errorf("Deliver on root: got %v, want ErrRootNeverRelays", err)
	}
}

// TestRelayForwardsOpaque checks end-to-end forwarding between two peers.
func TestRelayForwardsOpaque(t *testing.T) {
	h := NewHub(false, 0)
	dst := &memSink{}
	if err := h.Register("b", dst); err != nil {
		t.Fatalf("Register b: %v", err)
	}
	payload := []byte("opaque ciphertext — the relay must not inspect this")
	if err := h.Deliver("a", "b", payload); err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	if got := dst.Bytes(); !bytes.Equal(got, payload) {
		t.Errorf("forwarded %q, want %q", got, payload)
	}
}

// TestRelayNoRoute checks unregistered destinations fail cleanly.
func TestRelayNoRoute(t *testing.T) {
	h := NewHub(false, 0)
	if err := h.Deliver("a", "ghost", []byte("x")); err != ErrNoRoute {
		t.Errorf("Deliver to unregistered: got %v, want ErrNoRoute", err)
	}
}

// TestMasterQuota checks §18.3 priority isolation: the master's forwarding
// is quota-capped so address service keeps headroom.
func TestMasterQuota(t *testing.T) {
	h := NewHub(false, 100) // 100 B/s
	dst := &memSink{}
	h.Register("b", dst)

	clock := time.Unix(1000, 0)
	h.now = func() time.Time { return clock }

	// First 100 bytes pass (burst), the next exceed the bucket.
	if err := h.Deliver("a", "b", make([]byte, 100)); err != nil {
		t.Fatalf("first delivery: %v", err)
	}
	if err := h.Deliver("a", "b", make([]byte, 1)); err != ErrQuotaExceeded {
		t.Errorf("over-quota delivery: got %v, want ErrQuotaExceeded", err)
	}

	// A second later the quota refills.
	clock = clock.Add(time.Second)
	if err := h.Deliver("a", "b", make([]byte, 50)); err != nil {
		t.Errorf("delivery after refill: %v", err)
	}
}

// TestConditionalAvailability checks the honest degradation: a hub with no
// non-root relay exists reports itself via Root()/Peers, and a plain hub
// with no registrations simply fails routes rather than pretending.
func TestConditionalAvailability(t *testing.T) {
	h := NewHub(false, 0)
	if len(h.Peers()) != 0 {
		t.Fatal("new hub must have no peers")
	}
	h.Register("n1", &memSink{})
	if got := h.Peers(); len(got) != 1 || got[0] != "n1" {
		t.Errorf("Peers = %v, want [n1]", got)
	}
	h.Unregister("n1")
	if len(h.Peers()) != 0 {
		t.Error("Unregister must detach the peer")
	}
}