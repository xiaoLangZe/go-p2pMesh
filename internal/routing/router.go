// Package routing manages the IPv6 mesh routing table.
package routing

import (
	"fmt"
	"sync"
)

// ErrNotImplemented is returned by scaffolds completed in the P1 baseline.
var ErrNotImplemented = fmt.Errorf("routing not implemented in current phase")

// PeerEntry maps an IPv6 address to a peer's tunnel connection.
type PeerEntry struct {
	IPv6   string
	NodeID string
	RoomID string
}

// PeerTable maps mesh-internal IPv6 addresses to peer connections.
type PeerTable struct {
	mu    sync.RWMutex
	peers map[string]*PeerEntry // keyed by IPv6
}

// NewPeerTable creates an empty PeerTable.
func NewPeerTable() *PeerTable {
	return &PeerTable{peers: make(map[string]*PeerEntry)}
}

// Add inserts or updates a peer entry.
func (t *PeerTable) Add(e *PeerEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.peers[e.IPv6] = e
}

// Get retrieves a peer entry by IPv6 address.
func (t *PeerTable) Get(ipv6 string) (*PeerEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.peers[ipv6]
	return e, ok
}

// Remove deletes a peer entry.
func (t *PeerTable) Remove(ipv6 string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.peers, ipv6)
}

// Router reads IP packets from the TUN device and routes them to the
// appropriate peer tunnel (or drops them if no route exists).
type Router struct {
	table *PeerTable
}

// NewRouter creates a Router backed by the given PeerTable.
func NewRouter(table *PeerTable) *Router {
	return &Router{table: table}
}

// Route looks up the destination peer for the given IPv6 address.
// Returns ErrNotImplemented if route resolution is not yet wired.
func (r *Router) Route(dstIPv6 string) (*PeerEntry, error) {
	if e, ok := r.table.Get(dstIPv6); ok {
		return e, nil
	}
	return nil, fmt.Errorf("no route to %s", dstIPv6)
}
