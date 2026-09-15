// Package servermesh implements the server-to-server gossip protocol
// for distributing the server table and node/room changes.
package servermesh

import (
	"sync"
	"time"
)

// ServerEntry represents one known bootstrap server in the mesh.
type ServerEntry struct {
	Addr     string
	PubKey   [32]byte
	ID       string
	LastSeen time.Time
	Load     int
	IsRoot   bool
}

// ServerTable holds the set of known bootstrap servers.
type ServerTable struct {
	mu      sync.RWMutex
	servers map[string]*ServerEntry // keyed by ID
}

// NewServerTable creates an empty ServerTable.
func NewServerTable() *ServerTable {
	return &ServerTable{servers: make(map[string]*ServerEntry)}
}

// Add inserts or updates a server entry.
func (t *ServerTable) Add(e *ServerEntry) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.servers[e.ID] = e
}

// Get retrieves a server entry by ID.
func (t *ServerTable) Get(id string) (*ServerEntry, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	e, ok := t.servers[id]
	return e, ok
}

// Remove deletes a server entry by ID.
func (t *ServerTable) Remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.servers, id)
}

// List returns all known server entries as a slice.
func (t *ServerTable) List() []*ServerEntry {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]*ServerEntry, 0, len(t.servers))
	for _, e := range t.servers {
		result = append(result, e)
	}
	return result
}

// RemoveExpired removes entries older than the given timeout.
func (t *ServerTable) RemoveExpired(timeout time.Duration) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := time.Now().Add(-timeout)
	removed := 0
	for id, e := range t.servers {
		if e.LastSeen.Before(cutoff) {
			delete(t.servers, id)
			removed++
		}
	}
	return removed
}
