// Package api implements the server-side REST API for external management
// panels (§9): JWT authentication, mTLS at the TLS layer, rate limiting,
// audit logging, and CRUD endpoints for nodes, rooms, port rules, servers,
// and statistics.
package api

import (
	"context"
	"errors"
	"net"
	"net/http"
	"time"
)

// Config carries the API server's operational settings.
type Config struct {
	// Addr is the listen address. The default is 127.0.0.1:29684 —
	// invariant I5: nothing is exposed until an operator explicitly widens
	// the bind and accepts the resulting attack surface.
	Addr          string
	CertFile      string
	KeyFile       string
	ClientCAFile  string
	AllowedOrigin string
	Secret        []byte
	AdminUser     string
	AdminHash     []byte
	AccessTTL     time.Duration
	RefreshTTL    time.Duration
	// LoginRatePerMin bounds unauthenticated login attempts (§9.1 #6).
	LoginRatePerMin int
	// APIUserRatePerMin bounds authenticated management traffic.
	APIUserRatePerMin int
	// Now overrides the clock for all time-sensitive middleware (tests).
	Now func() time.Time
}

// Server is the REST API HTTP server.
type Server struct {
	cfg    Config
	deps   Deps
	ts     *tokenStore
	audit  AuditLog
	server *http.Server
	ln     net.Listener
}

// NewServer assembles the API server (no listener yet; Start binds).
func NewServer(cfg Config, d Deps, audit AuditLog) *Server {
	if cfg.AccessTTL <= 0 {
		cfg.AccessTTL = DefaultAccessTTL
	}
	if cfg.RefreshTTL <= 0 {
		cfg.RefreshTTL = DefaultRefreshTTL
	}
	if cfg.LoginRatePerMin <= 0 {
		cfg.LoginRatePerMin = loginRatePerMin
	}
	if cfg.APIUserRatePerMin <= 0 {
		cfg.APIUserRatePerMin = 600
	}
	if audit == nil {
		audit = NewMemAuditLog(1024)
	}
	ts := d.Tokens
	if ts == nil {
		ts = newTokenStore()
	}
	return &Server{cfg: cfg, deps: d, ts: ts, audit: audit}
}

// Handler builds the routed handler chain. Exported so tests can exercise
// the full stack over httptest without a TLS listener.
func (s *Server) Handler() http.Handler {
	h := &handler{d: s.deps}
	if h.d.Tokens == nil {
		h.d.Tokens = s.ts
	}
	if h.d.AccessTTL <= 0 {
		h.d.AccessTTL = s.cfg.AccessTTL
	}
	if h.d.RefreshTTL <= 0 {
		h.d.RefreshTTL = s.cfg.RefreshTTL
	}
	if len(h.d.Secret) == 0 {
		h.d.Secret = s.cfg.Secret
	}

	mux := http.NewServeMux()
	const login = "/api/v1/auth/login"
	mux.HandleFunc(login, h.login)
	mux.HandleFunc("/api/v1/auth/refresh", h.refresh)
	mux.HandleFunc("/api/v1/auth/logout", h.logout)
	mux.HandleFunc("GET /api/v1/nodes", h.listNodes)
	mux.HandleFunc("GET /api/v1/nodes/{id}", h.nodeDetail)
	mux.HandleFunc("PUT /api/v1/nodes/{id}/status", h.nodeStatus)
	mux.HandleFunc("DELETE /api/v1/nodes/{id}", h.deleteNode)
	mux.HandleFunc("GET /api/v1/rooms", h.listRooms)
	mux.HandleFunc("GET /api/v1/rooms/{id}/members", h.roomMembers)
	mux.HandleFunc("GET /api/v1/ports", h.listPorts)
	mux.HandleFunc("POST /api/v1/ports", h.addPort)
	mux.HandleFunc("DELETE /api/v1/ports/{id}", h.deletePort)
	mux.HandleFunc("GET /api/v1/servers", h.listServers)
	mux.HandleFunc("GET /api/v1/stats/overview", h.statsOverview)

	var chain http.Handler = mux
	chain = AuditMiddleware(s.audit)(chain)
	rl := &RateLimitMiddleware{
		LoginPath:     login,
		LoginRate:     s.cfg.LoginRatePerMin,
		LoginBurst:    s.cfg.LoginRatePerMin,
		APIUserRate:   s.cfg.APIUserRatePerMin,
		APIUserBurst:  s.cfg.APIUserRatePerMin / 6,
		Now:           s.cfg.Now,
	}
	chain = rl.Wrap(chain)
	chain = AuthMiddleware{
		Secret:      s.cfg.Secret,
		PublicPaths: []string{login, "/api/v1/auth/refresh"},
	}.Wrap(chain)
	chain = CORSMiddleware(s.cfg.AllowedOrigin, chain)
	return chain
}

// Start binds the listener and serves HTTPS. A missing address defaults to
// the loopback bind (I5).
func (s *Server) Start(ctx context.Context) error {
	addr := s.cfg.Addr
	if addr == "" {
		addr = "127.0.0.1:29684"
	}
	tlsCfg, err := BuildTLSConfig(s.cfg.CertFile, s.cfg.KeyFile, s.cfg.ClientCAFile)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	s.ln = ln
	s.server = &http.Server{
		Handler:   s.Handler(),
		TLSConfig: tlsCfg,
		// §9.1 resource bounds: slow clients must not pin goroutines or
		// sockets (Slowloris-class exhaustion).
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 16,
	}
	go func() {
		<-ctx.Done()
		shCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.server.Shutdown(shCtx)
	}()
	err = s.server.ServeTLS(ln, "", "")
	if err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// Stop gracefully shuts down the listener.
func (s *Server) Stop() error {
	if s.server == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.server.Shutdown(ctx)
}

// AuditLog exposes the audit trail collector.
func (s *Server) AuditLog() AuditLog { return s.audit }