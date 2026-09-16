// Package routing manages the mesh routing table and the TUN↔tunnel read/write
// loop that carries packets between the virtual NIC and peer tunnels.
package routing

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"time"
)

// PeerEntry maps a mesh address to a peer's tunnel connection.
type PeerEntry struct {
	IPv6   string
	IPv4   string
	NodeID string
	RoomID string
	// Sink is where packets destined for this peer are written. In production
	// this is a *tunnel.Tunnel; in tests it can be any io.WriteCloser.
	Sink io.WriteCloser
}

// PeerTable maps mesh-internal addresses to peer entries.
// It is keyed by both IPv6 (global) and IPv4 (room-scoped, §14.2).
type PeerTable struct {
	mu     sync.RWMutex
	byIPv6 map[string]*PeerEntry
	byIPv4 map[string]*PeerEntry
}

// NewPeerTable creates an empty PeerTable.
func NewPeerTable() *PeerTable {
	return &PeerTable{
		byIPv6: make(map[string]*PeerEntry),
		byIPv4: make(map[string]*PeerEntry),
	}
}

// Add inserts or updates a peer entry. Both IPv6 and IPv4 (if non-empty) are indexed.
func (t *PeerTable) Add(e *PeerEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e.IPv6 != "" {
		t.byIPv6[e.IPv6] = e
	}
	if e.IPv4 != "" {
		t.byIPv4[e.IPv4] = e
	}
}

// Get retrieves a peer entry by IPv6 address.
func (t *PeerTable) Get(ipv6 string) (*PeerEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.byIPv6[ipv6]
	return e, ok
}

// GetByIPv4 retrieves a peer entry by IPv4 address.
func (t *PeerTable) GetByIPv4(ipv4 string) (*PeerEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.byIPv4[ipv4]
	return e, ok
}

// Remove deletes peer entries by NodeID (removes from both maps).
func (t *PeerTable) Remove(nodeID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, e := range t.byIPv6 {
		if e.NodeID == nodeID {
			delete(t.byIPv6, k)
		}
	}
	for k, e := range t.byIPv4 {
		if e.NodeID == nodeID {
			delete(t.byIPv4, k)
		}
	}
}

// Router reads IP packets from a TUN device and routes them to the
// appropriate peer tunnel (or drops them if no route exists).
type Router struct {
	table  *PeerTable
	logger *slog.Logger
	// stats
	mu        sync.Mutex
	forwarded uint64
	dropped   uint64
	noRoute   uint64
}

// NewRouter creates a Router backed by the given PeerTable.
func NewRouter(table *PeerTable, logger *slog.Logger) *Router {
	if logger == nil {
		logger = slog.Default()
	}
	return &Router{table: table, logger: logger}
}

// Route looks up the destination peer for the given destination address.
// It tries IPv6 first, then IPv4.
func (r *Router) Route(dstAddr string) (*PeerEntry, error) {
	if e, ok := r.table.Get(dstAddr); ok {
		return e, nil
	}
	if e, ok := r.table.GetByIPv4(dstAddr); ok {
		return e, nil
	}
	return nil, fmt.Errorf("no route to %s", dstAddr)
}

// Forward reads one IP packet from src (the TUN device) and writes it to
// the tunnel for the destination peer. It extracts the destination address
// from the IP header, looks it up in the PeerTable, and writes the packet
// to the peer's Sink.
//
// If no route exists the packet is silently dropped (§8.4: "静默丢弃").
// Returns nil on success or drop; returns error only on read failure.
func (r *Router) Forward(src io.Reader, buf []byte) error {
	n, err := src.Read(buf)
	if err != nil {
		return fmt.Errorf("tun read: %w", err)
	}
	if n == 0 {
		return nil
	}

	dst, err := extractDstAddr(buf[:n])
	if err != nil {
		r.drop()
		return nil // malformed packet: drop silently
	}

	entry, err := r.Route(dst)
	if err != nil {
		r.noRoutePkt()
		return nil // no route: drop silently
	}

	if entry.Sink == nil {
		r.noRoutePkt()
		return nil
	}

	if _, err := entry.Sink.Write(buf[:n]); err != nil {
		r.drop()
		return nil // tunnel write failed: drop
	}

	r.forward()
	return nil
}

// RunLoop starts the read/write loop: continuously reads packets from the TUN
// device and forwards them. Blocks until done is closed or the TUN device
// returns an error. Call in a goroutine.
//
// This is the core data-plane path (§14.3): TUN → extract dst → route → tunnel.
func (r *Router) RunLoop(src io.Reader, bufSize int, done <-chan struct{}) {
	if bufSize <= 0 {
		bufSize = 65535
	}
	buf := make([]byte, bufSize)
	for {
		select {
		case <-done:
			return
		default:
		}
		if err := r.Forward(src, buf); err != nil {
			r.logger.Debug("forward loop error", "err", err)
			time.Sleep(10 * time.Millisecond) // avoid tight loop on persistent error
		}
	}
}

// Stats returns counters for observability.
func (r *Router) Stats() (forwarded, dropped, noRoute uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.forwarded, r.dropped, r.noRoute
}

func (r *Router) forward() {
	r.mu.Lock()
	r.forwarded++
	r.mu.Unlock()
}

func (r *Router) drop() {
	r.mu.Lock()
	r.dropped++
	r.mu.Unlock()
}

func (r *Router) noRoutePkt() {
	r.mu.Lock()
	r.noRoute++
	r.mu.Unlock()
}

// extractDstAddr reads the destination IP address from a raw IP packet.
// Supports both IPv4 (version 4) and IPv6 (version 6).
func extractDstAddr(pkt []byte) (string, error) {
	if len(pkt) < 1 {
		return "", fmt.Errorf("empty packet")
	}
	version := pkt[0] >> 4
	switch version {
	case 4:
		if len(pkt) < 20 {
			return "", fmt.Errorf("IPv4 packet too short: %d", len(pkt))
		}
		addr := netip.AddrFrom4([4]byte{pkt[16], pkt[17], pkt[18], pkt[19]})
		return addr.String(), nil
	case 6:
		if len(pkt) < 40 {
			return "", fmt.Errorf("IPv6 packet too short: %d", len(pkt))
		}
		var raw [16]byte
		copy(raw[:], pkt[24:40])
		addr := netip.AddrFrom16(raw)
		return addr.String(), nil
	default:
		return "", fmt.Errorf("unknown IP version %d", version)
	}
}
