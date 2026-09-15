// Package api implements the server-side REST API for external
// management panels.  It provides JWT + mTLS authentication,
// rate limiting, audit logging, and CRUD endpoints for nodes, rooms,
// port rules, servers, and statistics.
package api

import (
	"fmt"
	"net/http"
)

// ErrNotImplemented is returned by scaffolds completed in the P1 baseline.
var ErrNotImplemented = fmt.Errorf("api not implemented in current phase")

// Server is the REST API HTTP server.
type Server struct {
	addr    string
	handler http.Handler
}

// NewServer creates an API server bound to the given address.
func NewServer(addr string) *Server {
	return &Server{
		addr:    addr,
		handler: http.NewServeMux(),
	}
}

// Start begins listening for HTTPS requests.
func (s *Server) Start() error {
	return ErrNotImplemented
}

// Stop gracefully shuts down the API server.
func (s *Server) Stop() error {
	return nil
}
