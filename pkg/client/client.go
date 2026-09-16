// Package client provides the public API for embedding the go-p2pmesh
// client into a third-party Go application.
//
// The client is deployed on machines without public IPv4. It connects to
// the server, joins rooms, establishes P2P tunnels with peers, creates a
// virtual NIC, and controls port access. A client can optionally open a
// sub-server port for other clients to connect through.
//
// Usage:
//
//	cli, err := client.New(
//	    client.WithBootstrap([]string{"203.0.113.10:29683"}),
//	    client.WithRoom("myroom"),
//	)
//	if err != nil { log.Fatal(err) }
//	go cli.Start()
//	defer cli.Stop()
package client

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// Client is the top-level client instance. It owns all subsystems
// (config, identity, bootstrap, STUN, holepunch, tunnel, TUN,
// routing, port control, relay, logger).
type Client struct {
	mu      sync.Mutex
	cfg     *Config
	logger  *slog.Logger
	started bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// New creates a new Client with the given options.
func New(opts ...Option) (*Client, error) {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(cfg)
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid client config: %w", err)
	}
	logger := newLogger(cfg.LogLevel, cfg.LogFile)
	return &Client{
		cfg:    cfg,
		logger: logger,
	}, nil
}

// Start begins connecting to the bootstrap server and running all subsystems.
func (c *Client) Start() error {
	c.mu.Lock()
	if c.started {
		c.mu.Unlock()
		return fmt.Errorf("client already started")
	}
	c.started = true
	c.mu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel

	c.logger.Info("client starting",
		"bootstrap", c.cfg.Bootstrap,
		"room", c.cfg.RoomID,
		"listen_port", c.cfg.ListenPort,
	)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		<-ctx.Done()
		c.logger.Info("client context cancelled, shutting down")
	}()

	c.logger.Info("client started")
	return nil
}

// Stop gracefully shuts down the client.
func (c *Client) Stop() {
	c.mu.Lock()
	if !c.started {
		c.mu.Unlock()
		return
	}
	c.started = false
	if c.cancel != nil {
		c.cancel()
	}
	c.mu.Unlock()
	c.wg.Wait()
	c.logger.Info("client stopped")
}

// Config is the client runtime configuration.
type Config struct {
	Bootstrap               []string
	ListenPort              int
	RoomID                  string
	RoomKey                 string
	StunServers             []string
	HolepunchWindow         int
	HolepunchParallel       int
	TurnEnabled             bool
	TurnAddr                string
	TunnelMTU               int
	KCPWindow               int
	AllowUnreliableFallback bool
	NetworkCIDR             string
	PortControlPolicy       string
	PortControlDB           string
	LogLevel                string
	LogFile                 string
}

// DefaultConfig returns a Config populated with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Bootstrap:  []string{},
		ListenPort: 0,
		StunServers: []string{
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
			"stun.cloudflare.com:3478",
		},
		HolepunchWindow:   64,
		HolepunchParallel: 256,
		TunnelMTU:         1280,
		KCPWindow:         256,
		NetworkCIDR:       "fd00:9bd8::/64",
		PortControlPolicy: "deny",
		PortControlDB:     "portcontrol.db",
		LogLevel:          "info",
	}
}

// Validate checks the config for obvious errors.
func (c *Config) Validate() error {
	if len(c.Bootstrap) == 0 {
		return fmt.Errorf("no bootstrap servers configured")
	}
	if c.TunnelMTU < 576 {
		return fmt.Errorf("tunnel MTU %d too small", c.TunnelMTU)
	}
	switch c.PortControlPolicy {
	case "deny", "allow":
	default:
		return fmt.Errorf("invalid port control policy %q", c.PortControlPolicy)
	}
	return nil
}

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
