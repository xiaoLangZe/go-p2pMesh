// Package server provides the public API for embedding the go-p2pmesh
// server into a third-party Go application.
//
// The server is deployed on machines with public IPv4 and handles only
// signaling, room management, node discovery, port authorization, and
// provides a REST API for external management panels.  It never forwards
// business data, never creates a virtual NIC, and never participates in
// hole punching.
package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/internal/bootstrap"
	"github.com/xiaoLangZe/go-p2pmesh/internal/crypto"
	"github.com/xiaoLangZe/go-p2pmesh/internal/servermesh"
	"github.com/xiaoLangZe/go-p2pmesh/internal/storage"
)

// Server is the top-level server instance.  It owns all subsystems
// (config, storage, API, mesh, rooms, crypto, logger).
type Server struct {
	mu       sync.Mutex
	cfg      *Config
	logger   *slog.Logger
	started  bool
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	store    storage.Store
	bootSrv  *bootstrap.Server
	mesh     *servermesh.Mesh
	certAuth *crypto.CertAuth
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

	// Initialize the storage backend.
	dbCfg := storage.DatabaseConfig{
		Type:         cfg.DatabaseType,
		DSN:          cfg.DatabaseDSN,
		MaxOpenConns: 50,
		MaxIdleConns: 10,
	}
	store, err := storage.NewStore(dbCfg)
	if err != nil {
		return nil, fmt.Errorf("create store: %w", err)
	}

	// Initialize the certificate authority.
	ca, err := crypto.NewCertAuth(nil, false)
	if err != nil {
		return nil, fmt.Errorf("create cert auth: %w", err)
	}

	// Generate a local server ID (will be replaced with a proper node ID in P6+).
	localID := "server-0001"

	// Initialize the server mesh.
	mesh := servermesh.NewMesh(localID, logger)

	// Initialize the bootstrap server.
	bootAddr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	bootSrv := bootstrap.NewServer(bootAddr, logger)

	s := &Server{
		cfg:      cfg,
		logger:   logger,
		store:    store,
		bootSrv:  bootSrv,
		mesh:     mesh,
		certAuth: ca,
	}

	return s, nil
}

// Start begins listening on the configured port and serving requests.
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

	// Start the bootstrap server.
	if err := s.bootSrv.Start(ctx); err != nil {
		return fmt.Errorf("start bootstrap: %w", err)
	}

	// Start the mesh gossip loop.
	s.mesh.Start(ctx)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		<-ctx.Done()
		s.logger.Info("server context cancelled, shutting down")
	}()

	s.logger.Info("server started", "addr", fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port))
	return nil
}

// Stop releases every resource the server holds and waits for goroutines to
// exit. It is safe to call more than once and safe to call on a server that was
// never started.
//
// Releasing regardless of whether Start() ran matters: New() already opens the
// database, so an early return here would leak the handle for the life of the
// process (and on Windows would keep the file locked).
func (s *Server) Stop() {
	s.mu.Lock()
	cancel := s.cancel
	s.cancel = nil
	wasStarted := s.started
	s.started = false

	// Detach resources under the lock so a concurrent Stop cannot double-close.
	store := s.store
	s.store = nil
	bootSrv := s.bootSrv
	s.bootSrv = nil
	s.mu.Unlock()

	if !wasStarted && store == nil && bootSrv == nil {
		return // already fully stopped
	}

	if cancel != nil {
		cancel()
	}
	if bootSrv != nil {
		_ = bootSrv.Stop()
	}
	if store != nil {
		_ = store.Close()
	}

	s.wg.Wait()
	s.logger.Info("server stopped")
}

// Store returns the underlying storage backend (for use by the API layer).
func (s *Server) Store() storage.Store { return s.store }

// Logger returns the server's logger.
func (s *Server) Logger() *slog.Logger { return s.logger }

// newLogger creates a slog.Logger from the configured level and file path.
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
//
// The API listener defaults to loopback (invariant I5: "默认不暴露"). Exposing
// the management API to the network is an explicit operator decision, because a
// reachable API widens the attack surface to whatever its auth strength is.
func DefaultConfig() *Config {
	return &Config{
		Host:         "0.0.0.0",
		Port:         29683,
		APIHost:      "127.0.0.1",
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

var _ = time.Now
var _ = net.Listen
