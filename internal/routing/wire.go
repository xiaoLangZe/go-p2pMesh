package routing

// Placeholder documentation for future extensions:
// - room-scoped lookup (IPv4)
// - node migration tracking
//
// The core PeerTable and Router live in router.go.

import (
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/internal/tunnel"
)

// PeerEntry now carries a Sink (the tunnel) where packets are written.
// See router.go for the full definition.

// WireTunnel connects a tunnel to a peer entry in the table. It is
// the bridge between the tunnel manager (keyed by NodeID) and the routing
// table (keyed by mesh addresses). Called after a tunnel is established.
//
// Parameters:
//   - table: the PeerTable to update
//   - nodeID: the peer's node identifier
//   - ipv6, ipv4: the peer's mesh addresses (from AuthOK)
//   - tun: the established tunnel for this peer
func WireTunnel(table *PeerTable, nodeID, ipv6, ipv4, roomID string, tun *tunnel.Tunnel) {
	table.Add(&PeerEntry{
		IPv6:   ipv6,
		IPv4:   ipv4,
		NodeID: nodeID,
		RoomID: roomID,
		Sink:   tun,
	})
}

// TunnelLiveness tracks the last successful read/write timestamp for a
// tunnel so the caller can detect path failure (§19: 15s no progress → re-punch).
type TunnelLiveness struct {
	LastActivity time.Time
}

func NewTunnelLiveness() *TunnelLiveness {
	return &TunnelLiveness{LastActivity: time.Now()}
}

// Touch updates the liveness timestamp. Call after every successful read/write.
func (l *TunnelLiveness) Touch() {
	l.LastActivity = time.Now()
}

// Stale reports whether the tunnel has been silent longer than timeout.
func (l *TunnelLiveness) Stale(timeout time.Duration) bool {
	return time.Since(l.LastActivity) > timeout
}