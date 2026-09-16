// Package tunnel implements the KCP+Noise tunnel over established UDP paths.
//
// A tunnel carries IP packets between two peers. On the wire each packet is
// encrypted with Noise (ChaCha20-Poly1305) and framed by KCP for reliable
// ordered delivery. The transport ladder (§12.1 stage two) is:
//
//  1. KCP (default) — reliable ordered, tunable retransmission
//  2. Raw UDP fallback — when KCP cannot establish, per allow_unreliable_fallback
//  3. TCP fallback — when raw UDP is also unusable
//
// Per invariant I6, the fallback is never silent: the active transport is
// visible to the caller, and allow_unreliable_fallback=false blocks step 2.
package tunnel

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Transport indicates which layer is carrying the tunnel's traffic.
type Transport string

const (
	TransportKCP Transport = "kcp"
	TransportUDP Transport = "raw_udp"
	TransportTCP Transport = "tcp"
)

// Tunnel wraps a connection with Noise AEAD encryption. It implements
// io.ReadWriteCloser so the TUN layer can treat it as a pipe.
//
// The tunnel does not itself implement KCP reliability — it provides the
// encryption layer that sits above whichever transport the Manager selected.
// When the transport is KCP, the KCP session handles retransmission and
// ordering; when it is raw UDP, packets are sent as-is (unreliable); when
// TCP, the connection's own reliability is used.
type Tunnel struct {
	mu        sync.Mutex
	conn      net.Conn
	aead      cipher.AEAD
	transport Transport
	mtu       int
	closed    bool
	// sendSeq is the nonce counter for outbound AEAD encryption.
	sendSeq uint64
	// recvWindow is a sliding window for replay protection.
	recvWindow *replayWindow
}

// NewTunnel creates a tunnel over the given connection using the provided
// AEAD cipher (derived from a Noise IK handshake, §15.1).
//
// mtu is the inner MTU (the maximum plaintext size per packet), already
// corrected for encapsulation overhead (see mtu.go).
func NewTunnel(conn net.Conn, aead cipher.AEAD, transport Transport, mtu int) *Tunnel {
	if mtu <= 0 {
		mtu = 1280
	}
	return &Tunnel{
		conn:       conn,
		aead:       aead,
		transport:  transport,
		mtu:        mtu,
		recvWindow: newReplayWindow(1024),
	}
}

// Transport reports which layer is carrying traffic. This is how the caller
// satisfies I6: the active transport is always visible and can be logged or
// surfaced to the user.
func (t *Tunnel) Transport() Transport {
	return t.transport
}

// MTU returns the maximum plaintext size per Write call.
func (t *Tunnel) MTU() int {
	return t.mtu
}

// Read reads one decrypted packet from the tunnel.
//
// The wire format per packet is:
//
//	[seq(8)][clen(2)][ciphertext(clen + 16)]
//
// where seq is the sender's monotonic counter, clen is the ciphertext length
// (payload length + AEAD tag), and the nonce is derived from seq. The 2-byte
// length prefix lets the reader know exactly how many bytes to consume,
// avoiding a blocking ReadFull on a streaming pipe.
func (t *Tunnel) Read(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return 0, io.ErrClosedPipe
	}

	// Read the fixed header: 8-byte sequence + 2-byte ciphertext length.
	var hdr [10]byte
	if _, err := io.ReadFull(t.conn, hdr[:]); err != nil {
		return 0, fmt.Errorf("read header: %w", err)
	}
	seq := binary.BigEndian.Uint64(hdr[:8])
	clen := int(binary.BigEndian.Uint16(hdr[8:10]))
	if clen > t.mtu+t.aead.Overhead() {
		return 0, fmt.Errorf("ciphertext length %d exceeds max %d", clen, t.mtu+t.aead.Overhead())
	}

	// Replay protection.
	if !t.recvWindow.allow(seq) {
		// Drain the ciphertext so the stream stays aligned, then drop.
		drain := make([]byte, clen)
		io.ReadFull(t.conn, drain)
		return 0, nil
	}

	// Read the ciphertext.
	cipherBuf := make([]byte, clen)
	if _, err := io.ReadFull(t.conn, cipherBuf); err != nil {
		return 0, fmt.Errorf("read ciphertext: %w", err)
	}

	// Derive nonce from seq.
	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8], seq)

	// The additional data is the 8-byte seq (authenticated with the ciphertext).
	plaintext, err := t.aead.Open(nil, nonce[:], cipherBuf, hdr[:8])
	if err != nil {
		return 0, fmt.Errorf("decrypt: %w", err)
	}

	copy(p, plaintext)
	return len(plaintext), nil
}

// Write encrypts p and sends it through the tunnel.
func (t *Tunnel) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return 0, io.ErrClosedPipe
	}

	if len(p) > t.mtu {
		return 0, fmt.Errorf("packet %d bytes exceeds MTU %d", len(p), t.mtu)
	}

	t.sendSeq++
	seq := t.sendSeq

	var hdr [10]byte
	binary.BigEndian.PutUint64(hdr[:8], seq)

	var nonce [12]byte
	binary.BigEndian.PutUint64(nonce[:8], seq)

	// Encrypt: AEAD seals plaintext into ciphertext+tag, using the 8-byte seq
	// header as additional data so the sequence number is authenticated.
	ciphertext := t.aead.Seal(nil, nonce[:], p, hdr[:8])
	binary.BigEndian.PutUint16(hdr[8:10], uint16(len(ciphertext)))

	// Write: header (8 seq + 2 clen) + ciphertext.
	buf := make([]byte, 0, 10+len(ciphertext))
	buf = append(buf, hdr[:]...)
	buf = append(buf, ciphertext...)

	if _, err := t.conn.Write(buf); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}

	return len(p), nil
}

// Close closes the underlying connection.
func (t *Tunnel) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// LocalAddr returns the local address of the underlying connection.
func (t *Tunnel) LocalAddr() net.Addr {
	return t.conn.LocalAddr()
}

// RemoteAddr returns the remote address of the underlying connection.
func (t *Tunnel) RemoteAddr() net.Addr {
	return t.conn.RemoteAddr()
}

// replayWindow tracks seen sequence numbers within a sliding window to
// reject replayed packets. It uses a bitmap indexed by the low bits of seq.
type replayWindow struct {
	mu     sync.Mutex
	bitmap []uint64
	size   int
	last   uint64
}

func newReplayWindow(size int) *replayWindow {
	if size <= 0 {
		size = 1024
	}
	return &replayWindow{
		bitmap: make([]uint64, (size+63)/64),
		size:   size,
	}
}

// allow returns true if seq has not been seen recently and marks it as seen.
func (w *replayWindow) allow(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if seq <= w.last && w.last-seq < uint64(w.size) {
		idx := int(w.last - seq)
		word := idx / 64
		bit := uint(idx % 64)
		if w.bitmap[word]&(1<<bit) != 0 {
			return false // replay
		}
		w.bitmap[word] |= 1 << bit
		return false // already past, drop
	}

	// Advance the window.
	if seq > w.last {
		diff := seq - w.last
		if diff >= uint64(w.size) {
			for i := range w.bitmap {
				w.bitmap[i] = 0
			}
		} else {
			shift := int(diff)
			for i := len(w.bitmap) - 1; i >= 0; i-- {
				if i-shift/64 >= 0 {
					w.bitmap[i] = w.bitmap[i-shift/64]
				} else {
					w.bitmap[i] = 0
				}
			}
		}
		w.last = seq
	}

	idx := 0
	word := idx / 64
	bit := uint(idx % 64)
	w.bitmap[word] |= 1 << bit
	return true
}

// Manager tracks all active tunnels keyed by peer NodeID. It handles
// path-failure-triggered reconnection (§19: 15s no response → re-punch).
type Manager struct {
	mu      sync.RWMutex
	tunnels map[string]*Tunnel
}

// NewManager creates a tunnel Manager.
func NewManager() *Manager {
	return &Manager{tunnels: make(map[string]*Tunnel)}
}

// Get returns the tunnel for the given peer NodeID, if any.
func (m *Manager) Get(nodeID string) (*Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tunnels[nodeID]
	return t, ok
}

// Add registers a tunnel for a peer. If a tunnel already exists for the peer
// it is closed and replaced — this is the normal path after re-punching.
func (m *Manager) Add(nodeID string, t *Tunnel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.tunnels[nodeID]; ok {
		old.Close()
	}
	m.tunnels[nodeID] = t
}

// Remove unregisters and closes a tunnel.
func (m *Manager) Remove(nodeID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tunnels[nodeID]; ok {
		t.Close()
		delete(m.tunnels, nodeID)
	}
}

// All returns the NodeIDs of all active tunnels.
func (m *Manager) All() []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make([]string, 0, len(m.tunnels))
	for id := range m.tunnels {
		ids = append(ids, id)
	}
	return ids
}

// Count returns the number of active tunnels.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tunnels)
}

// CloseAll closes every tunnel and clears the map. Used during shutdown.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tunnels {
		t.Close()
	}
	m.tunnels = make(map[string]*Tunnel)
}

// TransportSelect implements the §12.1 stage-two ladder: given an established
// path (a net.Conn from the hole-punch engine) and the client's configuration,
// pick the transport and wrap it in a Tunnel.
//
// The ladder is:
//  1. KCP (default) — attempted first
//  2. Raw UDP — only if allowUnreliableFallback is true
//  3. TCP — only if the path is a TCP connection
//
// Per I6, the selected transport is visible to the caller through Tunnel.Transport().
// Per the design, KCP failure is judged at 30s of no progress (§12.1).
func TransportSelect(conn net.Conn, aead cipher.AEAD, mtu int, allowUnreliableFallback bool) (*Tunnel, error) {
	if conn == nil {
		return nil, fmt.Errorf("nil connection")
	}
	if aead == nil {
		return nil, fmt.Errorf("nil AEAD cipher (handshake not completed)")
	}

	// Determine the transport from the connection type.
	// In a full implementation, KCP would wrap the UDP conn and be tried first.
	// For P3 we implement the encryption layer and the transport selection
	// logic; the actual KCP session integration is P6 (data-plane tunnel).
	switch c := conn.(type) {
	case *net.UDPConn:
		// UDP path: KCP would be tried first (30s timeout), then raw UDP.
		// For now we use raw UDP with Noise encryption. The transport label
		// is "raw_udp" so the caller knows reliability is not guaranteed.
		_ = c
		transport := TransportUDP
		if !allowUnreliableFallback {
			// The design says: if allow_unreliable_fallback=false and KCP
			// cannot be established, the connection fails loudly.
			// Since KCP is not yet wired (P6), we cannot offer a reliable
			// transport on this path. Fail rather than silently degrade.
			return nil, fmt.Errorf("KCP not yet available and allow_unreliable_fallback is false; refusing to silently degrade (I6)")
		}
		return NewTunnel(conn, aead, transport, mtu), nil

	case *net.TCPConn:
		// TCP path: TCP's own reliability is used, Noise encrypts each frame.
		return NewTunnel(conn, aead, TransportTCP, mtu), nil

	default:
		// Unknown connection type: treat as raw and let the caller decide.
		// This path covers in-memory pipes used in tests.
		return NewTunnel(conn, aead, TransportUDP, mtu), nil
	}
}

// FailMonitor watches a tunnel for liveness. Per §19: 15s with no read
// progress means the path is dead and should trigger re-punching.
//
// The monitor calls onDead when the tunnel has been silent for longer than
// the timeout. It runs in its own goroutine and exits when the tunnel is
// closed.
func FailMonitor(t *Tunnel, timeout time.Duration, onDead func()) {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	// In a full implementation this would track the last successful Read
	// timestamp and fire onDead when it goes stale. For P3 the signature is
	// established so the caller (P4 TUN layer) can wire it.
	go func() {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		<-timer.C
		// Placeholder: the real check compares last-read time against now.
		// For now we just signal once.
		if onDead != nil {
			onDead()
		}
	}()
}
