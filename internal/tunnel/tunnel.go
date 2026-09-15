// Package tunnel implements the KCP+Noise tunnel over established UDP paths.
package tunnel

import (
	"fmt"
	"io"
	"net"
)

// ErrNotImplemented is returned by all methods in P0.
var ErrNotImplemented = fmt.Errorf("tunnel not implemented in current phase")

// Tunnel wraps a KCP session encrypted with Noise.
type Tunnel struct {
	conn   net.Conn
	cipher io.ReadWriteCloser
	mtu    int
}

// NewTunnel creates a tunnel over the given connection.
func NewTunnel(conn net.Conn, mtu int) *Tunnel {
	return &Tunnel{conn: conn, mtu: mtu}
}

// Read reads decrypted data from the tunnel.
func (t *Tunnel) Read(p []byte) (int, error) {
	return 0, ErrNotImplemented
}

// Write encrypts and sends data through the tunnel.
func (t *Tunnel) Write(p []byte) (int, error) {
	return 0, ErrNotImplemented
}

// Close closes the tunnel.
func (t *Tunnel) Close() error {
	if t.conn != nil {
		return t.conn.Close()
	}
	return nil
}

// Manager tracks all active tunnels keyed by peer NodeID.
type Manager struct {
	tunnels map[string]*Tunnel
}

// NewManager creates a tunnel Manager.
func NewManager() *Manager {
	return &Manager{tunnels: make(map[string]*Tunnel)}
}

// Get returns the tunnel for the given peer NodeID, if any.
func (m *Manager) Get(nodeID string) (*Tunnel, bool) {
	t, ok := m.tunnels[nodeID]
	return t, ok
}

// Add registers a tunnel for a peer.
func (m *Manager) Add(nodeID string, t *Tunnel) {
	m.tunnels[nodeID] = t
}

// Remove unregisters a tunnel.
func (m *Manager) Remove(nodeID string) {
	delete(m.tunnels, nodeID)
}
