package stun

import (
	"net"
	"time"
)

// StunClient is an RFC 5389 STUN Binding Request client.
// It connects to third-party public STUN servers (Google, Cloudflare, etc.)
// to discover the node's public (observed) address and NAT type.
type StunClient struct {
	Server  string
	Timeout time.Duration
}

// NewStunClient creates a STUN client targeting the given server.
func NewStunClient(server string, timeout time.Duration) *StunClient {
	return &StunClient{Server: server, Timeout: timeout}
}

// Binding sends a Binding Request and returns the observed public address.
func (c *StunClient) Binding(conn net.PacketConn) (observed net.Addr, err error) {
	return nil, ErrNotImplemented
}

// DetectNATType performs the full NAT classification algorithm using
// two or more STUN servers from the pool.
func DetectNATType(pool *Pool) (NATType, error) {
	return NATUnknown, ErrNotImplemented
}
