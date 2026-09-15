// Package servermesh implements the server-to-server gossip protocol
// for distributing the server table and node/room changes.
package servermesh

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Mesh manages connections to other bootstrap servers and gossip
// propagation of the server table.
type Mesh struct {
	mu      sync.Mutex
	table   *ServerTable
	peers   []string // known peer addresses
	logger  *slog.Logger
	localID string
}

// NewMesh creates a new server mesh with the given local server ID.
func NewMesh(localID string, logger *slog.Logger) *Mesh {
	if logger == nil {
		logger = slog.Default()
	}
	return &Mesh{
		table:   NewServerTable(),
		logger:  logger,
		localID: localID,
	}
}

// SetPeers sets the list of known peer server addresses for gossip.
func (m *Mesh) SetPeers(peers []string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.peers = peers
	m.logger.Info("mesh peers set", "count", len(peers))
}

// Peers returns the current peer list.
func (m *Mesh) Peers() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.peers))
	copy(out, m.peers)
	return out
}

// Table returns the underlying ServerTable.
func (m *Mesh) Table() *ServerTable {
	return m.table
}

// Start begins the gossip loop: periodic full sync + incremental events.
func (m *Mesh) Start(ctx context.Context) {
	// Periodic full sync every 60s.
	go m.gossipLoop(ctx, 60*time.Second)
	// Periodic cleanup of expired entries every 30s.
	go m.cleanupLoop(ctx, 30*time.Second, 90*time.Second)
}

// gossipLoop periodically pushes the full server table to all peers.
func (m *Mesh) gossipLoop(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.doGossip()
		}
	}
}

// doGossip sends the current server table to all peers.
// In the P1 baseline this is a no-op log; the actual TCP gossip
// protocol will be wired in a later phase.
func (m *Mesh) doGossip() {
	servers := m.table.List()
	m.logger.Debug("gossip round", "servers", len(servers), "peers", len(m.peers))
}

// cleanupLoop removes expired server entries.
func (m *Mesh) cleanupLoop(ctx context.Context, interval, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			removed := m.table.RemoveExpired(timeout)
			if removed > 0 {
				m.logger.Info("expired servers removed", "count", removed)
			}
		}
	}
}

// AnnounceSelf registers the local server in the table.
func (m *Mesh) AnnounceSelf(addr string, pubKey [32]byte) {
	m.table.Add(&ServerEntry{
		Addr:     addr,
		PubKey:   pubKey,
		ID:       m.localID,
		LastSeen: time.Now(),
		IsRoot:   true,
	})
}
