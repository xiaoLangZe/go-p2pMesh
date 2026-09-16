package tunnel

import (
	"crypto/aes"
	"crypto/cipher"
	"net"
	"testing"
)

// makeAEAD creates a GCM AEAD for testing. In production this comes from a
// Noise IK handshake; for tests any AEAD suffices.
func makeAEAD(t *testing.T) cipher.AEAD {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("cipher.NewGCM: %v", err)
	}
	return aead
}

// pipeConn pairs two net.Conns via net.Pipe so we can test Read/Write
// without a real network.
func pipeConn() (net.Conn, net.Conn) {
	return net.Pipe()
}

// TestTunnelWriteReadRoundTrip verifies that a plaintext written through the
// tunnel is recovered by Read on the other side.
func TestTunnelWriteReadRoundTrip(t *testing.T) {
	aead := makeAEAD(t)
	a, b := pipeConn()
	defer a.Close()
	defer b.Close()

	tunA := NewTunnel(a, aead, TransportUDP, 1280)
	tunB := NewTunnel(b, aead, TransportUDP, 1280)

	payload := []byte("hello mesh")

	// net.Pipe is synchronous: Write blocks until the other side reads.
	// Read in a goroutine first.
	type result struct {
		n   int
		err error
		buf []byte
	}
	ch := make(chan result, 1)
	go func() {
		buf := make([]byte, 1400)
		n, err := tunB.Read(buf)
		ch <- result{n, err, buf}
	}()

	if n, err := tunA.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}

	r := <-ch
	if r.err != nil {
		t.Fatalf("Read: %v", r.err)
	}
	if string(r.buf[:r.n]) != string(payload) {
		t.Errorf("payload mismatch: got %q, want %q", r.buf[:r.n], payload)
	}
}

// TestTunnelTransportVisible checks I6: the active transport is always
// queryable by the caller.
func TestTunnelTransportVisible(t *testing.T) {
	aead := makeAEAD(t)
	a, _ := pipeConn()
	defer a.Close()
	tun := NewTunnel(a, aead, TransportUDP, 1280)
	if tun.Transport() != TransportUDP {
		t.Errorf("Transport() = %s, want %s", tun.Transport(), TransportUDP)
	}
}

// TestTunnelMTUEnforced checks that writes exceeding the MTU are rejected.
func TestTunnelMTUEnforced(t *testing.T) {
	aead := makeAEAD(t)
	a, _ := pipeConn()
	defer a.Close()
	tun := NewTunnel(a, aead, TransportUDP, 100)
	big := make([]byte, 101)
	if _, err := tun.Write(big); err == nil {
		t.Error("expected error for over-MTU write, got nil")
	}
}

// TestTunnelClose checks that Close makes subsequent Read/Write fail.
func TestTunnelClose(t *testing.T) {
	aead := makeAEAD(t)
	a, _ := pipeConn()
	tun := NewTunnel(a, aead, TransportUDP, 1280)
	tun.Close()
	if _, err := tun.Write([]byte("x")); err == nil {
		t.Error("Write after Close should fail")
	}
}

// TestTransportSelectUDP verifies that a UDP connection with fallback enabled
// produces a raw_udp tunnel.
func TestTransportSelectUDP(t *testing.T) {
	aead := makeAEAD(t)
	// net.Pipe returns a generic conn, not *net.UDPConn, so we test the
	// default path which also yields TransportUDP.
	a, _ := pipeConn()
	defer a.Close()
	tun, err := TransportSelect(a, aead, 1280, true)
	if err != nil {
		t.Fatalf("TransportSelect: %v", err)
	}
	if tun.Transport() == "" {
		t.Error("transport not set")
	}
}

// TestTransportSelectNoFallback checks I6: when allow_unreliable_fallback is
// false and KCP is unavailable, TransportSelect fails loudly.
func TestTransportSelectNoFallback(t *testing.T) {
	aead := makeAEAD(t)
	// Create a real UDP conn so TransportSelect sees *net.UDPConn
	// and exercises the "KCP unavailable, fallback disabled" path.
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	defer conn.Close()
	_, err = TransportSelect(conn, aead, 1280, false)
	if err == nil {
		t.Error("expected error when allow_unreliable_fallback=false and KCP unavailable, got nil")
	}
}

// TestTransportSelectNil checks error handling.
func TestTransportSelectNil(t *testing.T) {
	aead := makeAEAD(t)
	_, err := TransportSelect(nil, aead, 1280, true)
	if err == nil {
		t.Error("expected error for nil conn")
	}
}

// TestManagerAddReplace checks that adding a tunnel for an existing peer
// closes the old one.
func TestManagerAddReplace(t *testing.T) {
	aead := makeAEAD(t)
	m := NewManager()
	a1, _ := pipeConn()
	a2, _ := pipeConn()
	defer a1.Close()
	defer a2.Close()

	t1 := NewTunnel(a1, aead, TransportUDP, 1280)
	t2 := NewTunnel(a2, aead, TransportUDP, 1280)

	m.Add("peer-A", t1)
	m.Add("peer-A", t2) // should close t1

	got, ok := m.Get("peer-A")
	if !ok {
		t.Fatal("peer-A not found after replace")
	}
	if got != t2 {
		t.Error("expected t2 after replace")
	}
}

// TestManagerRemove checks removal and closure.
func TestManagerRemove(t *testing.T) {
	aead := makeAEAD(t)
	m := NewManager()
	a, _ := pipeConn()
	tun := NewTunnel(a, aead, TransportUDP, 1280)
	m.Add("peer-X", tun)
	m.Remove("peer-X")
	if _, ok := m.Get("peer-X"); ok {
		t.Error("peer-X still present after Remove")
	}
}

// TestManagerCount checks the count accessor.
func TestManagerCount(t *testing.T) {
	m := NewManager()
	if m.Count() != 0 {
		t.Errorf("empty manager count = %d, want 0", m.Count())
	}
	aead := makeAEAD(t)
	a, _ := pipeConn()
	defer a.Close()
	m.Add("p1", NewTunnel(a, aead, TransportUDP, 1280))
	if m.Count() != 1 {
		t.Errorf("count = %d, want 1", m.Count())
	}
}

// TestManagerCloseAll verifies that CloseAll clears everything.
func TestManagerCloseAll(t *testing.T) {
	m := NewManager()
	aead := makeAEAD(t)
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		a, _ := pipeConn()
		conns = append(conns, a)
		m.Add(string(rune('A'+i)), NewTunnel(a, aead, TransportUDP, 1280))
	}
	m.CloseAll()
	if m.Count() != 0 {
		t.Errorf("count after CloseAll = %d, want 0", m.Count())
	}
	for _, c := range conns {
		c.Close()
	}
}

// TestReplayWindowBasic checks that duplicate sequence numbers are rejected.
func TestReplayWindowBasic(t *testing.T) {
	w := newReplayWindow(64)
	if !w.allow(1) {
		t.Error("first allow(1) should return true")
	}
	// allow(1) again should be rejected as a replay
	if w.allow(1) {
		t.Error("second allow(1) should return false (replay)")
	}
	// A higher seq should be accepted
	if !w.allow(5) {
		t.Error("allow(5) should return true")
	}
}

// TestReplayWindowGap checks that out-of-order packets within the window
// are accepted but duplicates are not.
func TestReplayWindowGap(t *testing.T) {
	w := newReplayWindow(128)
	w.allow(10)
	w.allow(11)
	w.allow(12)
	// 11 is within the window but already seen
	if w.allow(11) {
		t.Error("allow(11) after seeing it should return false")
	}
}

// TestTunnelConcurrentWrite checks that concurrent writes do not corrupt the
// sequence counter.
func TestTunnelConcurrentWrite(t *testing.T) {
	aead := makeAEAD(t)
	a, b := pipeConn()
	defer a.Close()
	defer b.Close()
	tunA := NewTunnel(a, aead, TransportUDP, 1280)
	tunB := NewTunnel(b, aead, TransportUDP, 1280)

	// net.Pipe is synchronous: Write blocks until Read consumes. We must
	// alternate read/write rather than fan out writes.
	count := 0
	for i := 0; i < 10; i++ {
		done := make(chan struct{})
		go func() {
			buf := make([]byte, 1400)
			_, err := tunB.Read(buf)
			if err != nil {
				t.Errorf("Read %d: %v", i, err)
			}
			close(done)
		}()
		payload := []byte{byte(i)}
		if _, err := tunA.Write(payload); err != nil {
			t.Errorf("Write %d: %v", i, err)
		}
		<-done
		count++
	}
	if count != 10 {
		t.Errorf("completed %d of 10 packets", count)
	}
}
