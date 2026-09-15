// Package server provides the public API for embedding the go-p2pmesh
// server into a third-party Go application.
//
// The server is deployed on machines with public IPv4 and handles only
// signaling, room management, node discovery, port authorization, and
// provides a REST API for external management panels.  It never forwards
// business data, never creates a virtual NIC, and never participates in
// hole punching.
//
// Usage:
//
//	srv, err := server.New(
//	    server.WithHost("0.0.0.0"),
//	    server.WithPort(29683),
//	)
//	if err != nil { log.Fatal(err) }
//	go srv.Start()
//	defer srv.Stop()
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"
)

// Server is the top-level server instance.  It owns all subsystems
// (config, storage, API, mesh, rooms, crypto, logger).
type Server struct {
	mu      sync.Mutex
	cfg     *Config
	logger  *slog.Logger
	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	// Sub-systems (populated in later phases)
	listener net.Listener
}

// New creates a new Server with the given options.  The server is not
// started until Start() is called.
func New(opts ...Option) (*Server, error) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid server config: %w", err)
	}
	logger := newLogger(cfg.LogLevel, cfg.LogFile)
	return &Server{
		cfg:    cfg,
		logger: logger,
	}, nil
}

// Start begins listening on the configured port and serving requests.
// It blocks until ctx is cancelled or Stop() is called.
// In P0, it logs the startup message and waits for a shutdown signal.
func (s *Server) Start() error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return fmt.Errorf("server already started")
	}
	s.started = true
	s.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	s.logger.Info("server starting",
		"host", s.cfg.Host,
		"port", s.cfg.Port,
		"api_port", s.cfg.APIPort,
		"db_type", s.cfg.DatabaseType,
	)

	// P0: just hold the process alive.  Subsequent phases will add
	// the real listener, bootstrap, API server, etc.
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		s.logger.Info("server context cancelled, shutting down")
	}()

	s.logger.Info("server started", "addr", fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port))
	return nil
}

// Stop gracefully shuts down the server, waiting for goroutines to exit.
func (s *Server) Stop() {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return
	}
	s.started = false
	if s.cancel != nil {
		s.cancel()
	}
	s.mu.Unlock()
	s.wg.Wait()
	s.logger.Info("server stopped")
}

// newLogger creates a slog.Logger from the configured level and file path.
// If file is empty, logs go to stdout.
func newLogger(level, file string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	opts := &slog.HandlerOptions{Level: lvl}
	// P0: log to stdout.  File logging will be wired in a later phase.
	_ = file
	return slog.New(slog.NewTextHandler(os.Stdout, opts))
}

// Config is the server runtime configuration.
type Config struct {
	Host         string
	Port         int
	APIHost      string
	APIPort      int
	APICertFile  string
	APIKeyFile   string
	JWTSecret    string
	AdminUser    string
	AdminPass    string
	DatabaseType string
	DatabaseDSN  string
	LogLevel     string
	LogFile      string
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Host:         "0.0.0.0",
		Port:         29683,
		APIHost:      "0.0.0.0",
		APIPort:      29684,
		DatabaseType: "sqlite",
		DatabaseDSN:  "data/gop2pmesh.db",
		AdminUser:    "admin",
		LogLevel:     "info",
	}
}

// Validate checks the config for obvious errors.
func (c *Config) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid server port %d", c.Port)
	}
	if c.APIPort < 1 || c.APIPort > 65535 {
		return fmt.Errorf("invalid api port %d", c.APIPort)
	}
	switch c.DatabaseType {
	case "sqlite", "mysql", "postgresql", "mongodb":
	default:
		return fmt.Errorf("unsupported database type %q", c.DatabaseType)
	}
	return nil
}

// time used to avoid an "imported and not used" if time becomes needed later.
var _ = time.Now
