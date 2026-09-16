package routing

import (
	"bytes"
	"io"
	"net/netip"
	"testing"
)

// memSink is an in-memory io.WriteCloser used in tests.
type memSink struct {
	bytes.Buffer
}

func (m *memSink) Close() error { return nil }

// TestExtractDstAddrV4 verifies IPv4 destination extraction.
func TestExtractDstAddrV4(t *testing.T) {
	// Minimal IPv4 header: version 4, IHL 5 (20 bytes), dst at offset 16.
	pkt := make([]byte, 20)
	pkt[0] = 0x45 // version 4, IHL 5
	pkt[16] = 192
	pkt[17] = 0
	pkt[18] = 2
	pkt[19] = 1

	dst, err := extractDstAddr(pkt)
	if err != nil {
		t.Fatalf("extractDstAddr: %v", err)
	}
	if want := "192.0.2.1"; dst != want {
		t.Errorf("dst = %s, want %s", dst, want)
	}
}

// TestExtractDstAddrV6 verifies IPv6 destination extraction.
func TestExtractDstAddrV6(t *testing.T) {
	// Minimal IPv6 header: version 6, dst at offset 24.
	pkt := make([]byte, 40)
	pkt[0] = 0x60 // version 6

	var want [16]byte
	want[15] = 0x42 // fd00:9bd8::42
	// Set a ULA-ish address for readability
	copy(want[:2], []byte{0xfd, 0x00})
	copy(pkt[24:40], want[:])

	dst, err := extractDstAddr(pkt)
	if err != nil {
		t.Fatalf("extractDstAddr: %v", err)
	}
	exp := netip.AddrFrom16(want).String()
	if dst != exp {
		t.Errorf("dst = %s, want %s", dst, exp)
	}
}

// TestExtractDstAddrMalformed checks short/invalid packets.
func TestExtractDstAddrMalformed(t *testing.T) {
	if _, err := extractDstAddr(nil); err == nil {
		t.Error("expected error for empty packet")
	}
	if _, err := extractDstAddr([]byte{0x46}); err == nil {
		t.Error("expected error for short IPv6 packet")
	}
	if _, err := extractDstAddr([]byte{0x75}); err == nil {
		t.Error("expected error for unknown version")
	}
}

// TestRouterForward checks Forward routes a packet to the correct sink.
func TestRouterForward(t *testing.T) {
	table := NewPeerTable()
	router := NewRouter(table, nil)

	sink := &memSink{}
	table.Add(&PeerEntry{
		IPv6:   "fd00:9bd8::42",
		NodeID: "peer-1",
		RoomID: "room-a",
		Sink:   sink,
	})
	_ = router

	// Build an IPv6 packet destined to fd00:9bd8::42.
	pkt := make([]byte, 40)
	pkt[0] = 0x60
	copy(pkt[24:28], []byte{0xfd, 0x00, 0x9b, 0xd8})
	pkt[39] = 0x42 // last byte = 0x42

	if err := router.Forward(bytes.NewReader(pkt), make([]byte, 2048)); err != nil {
		t.Fatalf("Forward: %v", err)
	}

	if sink.Len() != 40 {
		t.Errorf("sink received %d bytes, want 40", sink.Len())
	}

	fwd, dropped, noRoute := router.Stats()
	if fwd != 1 {
		t.Errorf("forwarded = %d, want 1", fwd)
	}
	if dropped != 0 || noRoute != 0 {
		t.Errorf("dropped=%d noRoute=%d, want 0/0", dropped, noRoute)
	}
}

// TestRouterForwardNoRoute checks silent drop when no route exists.
func TestRouterForwardNoRoute(t *testing.T) {
	table := NewPeerTable()
	router := NewRouter(table, nil)

	pkt := make([]byte, 40)
	pkt[0] = 0x60
	copy(pkt[24:26], []byte{0xfd, 0x00})
	pkt[39] = 0xFF // no such peer

	if err := router.Forward(bytes.NewReader(pkt), make([]byte, 2048)); err != nil {
		t.Fatalf("Forward: %v", err)
	}

	_, _, noRoute := router.Stats()
	if noRoute != 1 {
		t.Errorf("noRoute = %d, want 1 (silent drop)", noRoute)
	}
}

// TestPeerTableDualKey checks both IPv6 and IPv4 lookups work.
func TestPeerTableDualKey(t *testing.T) {
	table := NewPeerTable()
	table.Add(&PeerEntry{
		IPv6:   "fd00:9bd8::42",
		IPv4:   "240.0.0.42",
		NodeID: "peer-1",
		RoomID: "room-a",
	})

	if _, ok := table.Get("fd00:9bd8::42"); !ok {
		t.Error("IPv6 lookup failed")
	}
	if _, ok := table.GetByIPv4("240.0.0.42"); !ok {
		t.Error("IPv4 lookup failed")
	}
	if _, ok := table.Get("240.0.0.42"); ok {
		t.Error("IPv4 addr should not be in IPv6 map")
	}
}

// TestPeerTableRemoveByNodeID checks removal by NodeID across both maps.
func TestPeerTableRemoveByNodeID(t *testing.T) {
	table := NewPeerTable()
	table.Add(&PeerEntry{IPv6: "fd00:9bd8::42", IPv4: "240.0.0.42", NodeID: "peer-1"})
	table.Add(&PeerEntry{IPv6: "fd00:9bd8::99", NodeID: "peer-2"})

	table.Remove("peer-1")

	if _, ok := table.Get("fd00:9bd8::42"); ok {
		t.Error("peer-1 IPv6 still present")
	}
	if _, ok := table.GetByIPv4("240.0.0.42"); ok {
		t.Error("peer-1 IPv4 still present")
	}
	if _, ok := table.Get("fd00:9bd8::99"); !ok {
		t.Error("peer-2 removed incorrectly")
	}
}

// TestTunnelLiveness checks the stale detection timer.
func TestTunnelLiveness(t *testing.T) {
	l := NewTunnelLiveness()
	if l.Stale(0) {
		t.Error("fresh liveness reports stale")
	}
	l.Touch()
	if l.Stale(0) {
		t.Error("touched liveness reports stale")
	}
}

var _ io.WriteCloser = (*memSink)(nil)
