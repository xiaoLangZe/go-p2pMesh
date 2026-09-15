// Package bootstrap implements the control-plane connection logic.
// In P0 this package defines types and returns ErrNotImplemented.
package bootstrap

import (
	"context"
	"fmt"
	"net"
)

// ErrNotImplemented is returned by all methods in P0.
var ErrNotImplemented = fmt.Errorf("bootstrap not implemented in current phase")

// Server is the server-side control-plane handler.  It accepts TCP
// connections from clients, performs the Noise IK handshake, and routes
// control messages to the appropriate subsystems.
type Server struct {
	addr     string
	listener net.Listener
}

// NewServer creates a bootstrap Server bound to addr ("host:port").
func NewServer(addr string) *Server {
	return &Server{addr: addr}
}

// Start begins listening for incoming client connections.
func (s *Server) Start(ctx context.Context) error {
	return ErrNotImplemented
}

// Stop gracefully closes the listener.
func (s *Server) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

// Client is the client-side control-plane connector.  It dials the
// bootstrap server, performs the Noise IK handshake, and sends/receives
// control messages.
type Client struct {
	serverAddr string
	conn       net.Conn
}

// NewClient creates a bootstrap Client targeting the given server address.
func NewClient(serverAddr string) *Client {
	return &Client{serverAddr: serverAddr}
}

// Connect dials the server and performs the Noise handshake.
func (c *Client) Connect(ctx context.Context) error {
	return ErrNotImplemented
}

// Close closes the connection to the server.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}
