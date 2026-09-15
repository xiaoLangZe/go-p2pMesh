// Package relay implements the optional TURN relay for fallback transit.
// A relay node forwards encrypted (opaque) packets between two peers
// that cannot establish a direct P2P tunnel.  The relay never decrypts
// the payload (zero-knowledge transit).
package relay

import "fmt"

// ErrNotImplemented is returned in P0.
var ErrNotImplemented = fmt.Errorf("relay not implemented in current phase")

// Client connects to a TURN relay and forwards opaque packets.
type Client struct {
	relayAddr string
}

// NewClient creates a relay client targeting the given TURN address.
func NewClient(addr string) *Client {
	return &Client{relayAddr: addr}
}

// Allocate requests a relay allocation on the TURN server.
func (c *Client) Allocate() error {
	return ErrNotImplemented
}

// Forward sends an opaque packet through the relay.
func (c *Client) Forward(data []byte) error {
	return ErrNotImplemented
}

// Server is the relay node that accepts TURN allocations and
// forwards opaque packets between peers.
type Server struct {
	addr string
}

// NewServer creates a relay Server bound to the given address.
func NewServer(addr string) *Server {
	return &Server{addr: addr}
}

// Start begins listening for TURN allocation requests.
func (s *Server) Start() error {
	return ErrNotImplemented
}

// Stop gracefully shuts down the relay server.
func (s *Server) Stop() error { return nil }
