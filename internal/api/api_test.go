package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/internal/storage"
	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// fixture builds a server over an in-memory store with a known admin.
func fixture(t *testing.T) (*Server, *memAPIStore, []byte) {
	t.Helper()
	store := newMemAPIStore()
	secret := []byte("test-secret-shared")
	hash, err := HashPassword("correct horse")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	s := NewServer(Config{
		Secret:     secret,
		AdminUser:  "admin",
		AdminHash:  hash,
		AccessTTL:  time.Hour,
		RefreshTTL: 24 * time.Hour,
	}, Deps{
		Store:     store,
		Secret:    secret,
		AdminUser: "admin",
		AdminHash: hash,
	}, nil)
	return s, store, secret
}

// TestJWTIssueVerifyRoundTrip checks token issuance and validation.
func TestJWTIssueVerifyRoundTrip(t *testing.T) {
	secret := []byte("s")
	token, err := IssueToken(secret, Claims{Sub: "u", Role: "admin", Exp: time.Now().Add(time.Hour).Unix(), Typ: "access"})
	if err != nil {
		t.Fatalf("IssueToken: %v", err)
	}
	claims, err := VerifyToken(secret, token, time.Now())
	if err != nil {
		t.Fatalf("VerifyToken: %v", err)
	}
	if claims.Sub != "u" || claims.Typ != "access" {
		t.Errorf("claims mismatch: %+v", claims)
	}
}

// TestJWTRejectsTampering checks signature integrity.
func TestJWTRejectsTampering(t *testing.T) {
	secret := []byte("s")
	token, _ := IssueToken(secret, Claims{Sub: "u", Role: "admin", Exp: time.Now().Add(time.Hour).Unix(), Typ: "access"})
	tampered := token[:len(token)-4] + "AAAA"
	if _, err := VerifyToken(secret, tampered, time.Now()); err == nil {
		t.Error("tampered token must be rejected")
	}
}

// TestJWTExpiry checks the exp claim is enforced.
func TestJWTExpiry(t *testing.T) {
	secret := []byte("s")
	token, _ := IssueToken(secret, Claims{Sub: "u", Role: "admin", Exp: 100, Typ: "access"})
	if _, err := VerifyToken(secret, token, time.Unix(200, 0)); err == nil {
		t.Error("expired token must be rejected")
	}
}

// TestAuthGateRejectsAnonymous checks non-login routes are gated.
func TestAuthGateRejectsAnonymous(t *testing.T) {
	s, _, _ := fixture(t)

	req := httptest.NewRequest("GET", "/api/v1/nodes", nil)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous nodes request: got %d, want 401", rr.Code)
	}
}

// TestLoginIssuesTokens checks the happy path end to end.
func TestLoginIssuesTokens(t *testing.T) {
	s, _, _ := fixture(t)

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "correct horse"})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("login: got %d, want 200: %s", rr.Code, rr.Body.String())
	}
	var resp struct {
		OK   bool `json:"ok"`
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.AccessToken == "" || resp.Data.RefreshToken == "" {
		t.Fatal("tokens missing from login response")
	}
}

// TestLoginWrongPassword checks rejection.
func TestLoginWrongPassword(t *testing.T) {
	s, _, _ := fixture(t)

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: got %d, want 401", rr.Code)
	}
}

// TestAuthenticatedNodesList checks an access token unlocks endpoints.
func TestAuthenticatedNodesList(t *testing.T) {
	s, store, secret := fixture(t)
	_ = store.RegisterNode(t.Context(), &storage.Node{ID: types.NodeID("n1"), Status: storage.NodeStatusOnline})

	token, _ := IssueToken(secret, Claims{Sub: "admin", Role: "admin", Exp: time.Now().Add(time.Hour).Unix(), Typ: "access"})
	req := httptest.NewRequest("GET", "/api/v1/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("authed nodes: got %d, want 200: %s", rr.Code, rr.Body.String())
	}
}

// TestLoginRateLimit checks §9.1 #6: the fifth login per minute is refused.
func TestLoginRateLimit(t *testing.T) {
	// Freeze the clock: bcrypt makes real logins take hundreds of
	// milliseconds each, which would refill the bucket and flake the test.
	now := time.Unix(1000, 0)
	s := NewServer(Config{
		Secret:          []byte("test-secret-shared"),
		AdminUser:       "admin",
		AdminHash:       mustHash(t, "correct horse"),
		AccessTTL:       time.Hour,
		RefreshTTL:      time.Hour,
		LoginRatePerMin: 5,
		Now:             func() time.Time { return now },
	}, Deps{
		Store:     newMemAPIStore(),
		Secret:    []byte("test-secret-shared"),
		AdminUser: "admin",
		AdminHash: mustHash(t, "correct horse"),
	}, nil)
	h := s.Handler()

	body, _ := json.Marshal(map[string]string{"username": "admin", "password": "wrong"})
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(body))
		req.RemoteAddr = "192.0.2.9:1234"
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if i < 5 {
			if rr.Code == http.StatusTooManyRequests {
				t.Fatalf("request %d: unexpected 429 inside the burst", i)
			}
		} else {
			if rr.Code != http.StatusTooManyRequests {
				t.Fatalf("request %d: got %d, want 429", i, rr.Code)
			}
		}
	}
}

func mustHash(t *testing.T, pw string) []byte {
	t.Helper()
	h, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return h
}

// TestAuditTrail records management operations.
func TestAuditTrail(t *testing.T) {
	audit := NewMemAuditLog(10)
	store := newMemAPIStore()
	secret := []byte("audit-secret")
	hash, _ := HashPassword("pw")
	s := NewServer(Config{Secret: secret, AdminUser: "admin", AdminHash: hash, AccessTTL: time.Hour, RefreshTTL: time.Hour, LoginRatePerMin: 100, APIUserRatePerMin: 100},
		Deps{Store: store, Secret: secret, AdminUser: "admin", AdminHash: hash}, audit)
	token, _ := IssueToken(secret, Claims{Sub: "admin", Role: "admin", Exp: time.Now().Add(time.Hour).Unix(), Typ: "access"})

	req := httptest.NewRequest("GET", "/api/v1/nodes", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)

	entries := audit.Entries()
	if len(entries) != 1 {
		t.Fatalf("audit entries = %d, want 1", len(entries))
	}
	e := entries[0]
	if e.Path != "/api/v1/nodes" || e.User != "admin" || e.Status != http.StatusOK {
		t.Errorf("audit entry mismatch: %+v", e)
	}
}

// TestRefreshFlow checks a refresh token exchanges for a fresh access token,
// and that logout revokes it.
func TestRefreshFlow(t *testing.T) {
	s, _, _ := fixture(t)

	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "correct horse"})
	req := httptest.NewRequest("POST", "/api/v1/auth/login", bytes.NewReader(loginBody))
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	var resp struct {
		Data struct {
			AccessToken  string `json:"access_token"`
			RefreshToken string `json:"refresh_token"`
		} `json:"data"`
	}
	json.Unmarshal(rr.Body.Bytes(), &resp)

	refreshBody, _ := json.Marshal(map[string]string{"refresh_token": resp.Data.RefreshToken})
	req = httptest.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewReader(refreshBody))
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("refresh: got %d, want 200: %s", rr.Code, rr.Body.String())
	}

	// Logout with the access token, revoking the refresh token.
	logoutReq := httptest.NewRequest("POST", "/api/v1/auth/logout", bytes.NewReader(refreshBody))
	logoutReq.Header.Set("Authorization", "Bearer "+resp.Data.AccessToken)
	h := httptest.NewRecorder()
	s.Handler().ServeHTTP(h, logoutReq)

	// Refresh again with the revoked token must fail.
	req = httptest.NewRequest("POST", "/api/v1/auth/refresh", bytes.NewReader(refreshBody))
	rr = httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Errorf("refresh after logout: got %d, want 401", rr.Code)
	}
}

// TestStatsOverview checks the stats endpoint aggregates.
func TestStatsOverview(t *testing.T) {
	s, store, secret := fixture(t)
	_ = store.RegisterNode(t.Context(), &storage.Node{ID: types.NodeID("n1"), Status: storage.NodeStatusOnline, NATType: "FullCone"})
	_ = store.RegisterNode(t.Context(), &storage.Node{ID: types.NodeID("n2"), Status: storage.NodeStatusOffline})

	token, _ := IssueToken(secret, Claims{Sub: "admin", Role: "admin", Exp: time.Now().Add(time.Hour).Unix(), Typ: "access"})
	req := httptest.NewRequest("GET", "/api/v1/stats/overview", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	s.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats: got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- minimal in-memory store for API tests ---

type memAPIStore struct {
	mu    sync.Mutex
	nodes map[string]*storage.Node
	rooms map[types.RoomID]*types.Room
	rules map[string]*storage.PortRule
}

func newMemAPIStore() *memAPIStore {
	return &memAPIStore{
		nodes: make(map[string]*storage.Node),
		rooms: make(map[types.RoomID]*types.Room),
		rules: make(map[string]*storage.PortRule),
	}
}

func (s *memAPIStore) RegisterNode(_ context.Context, n *storage.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nodes[string(n.ID)] = n
	return nil
}

func (s *memAPIStore) GetNode(_ context.Context, id string) (*storage.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, ok := s.nodes[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return n, nil
}

func (s *memAPIStore) ListNodes(_ context.Context, _ storage.NodeFilter) ([]*storage.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*storage.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}
	return out, nil
}

func (s *memAPIStore) UpdateNodeStatus(_ context.Context, id string, st storage.NodeStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if n, ok := s.nodes[id]; ok {
		n.Status = st
		return nil
	}
	return errors.New("not found")
}

func (s *memAPIStore) DeleteNode(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.nodes, id)
	return nil
}

func (s *memAPIStore) ListRooms(_ context.Context) ([]*types.Room, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*types.Room, 0, len(s.rooms))
	for _, r := range s.rooms {
		out = append(out, r)
	}
	return out, nil
}

func (s *memAPIStore) ListRoomMembers(_ context.Context, _ string) ([]*storage.Node, error) {
	return nil, nil
}

func (s *memAPIStore) GetPortRules(_ context.Context, _ string) ([]*storage.PortRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*storage.PortRule, 0, len(s.rules))
	for _, r := range s.rules {
		out = append(out, r)
	}
	return out, nil
}

func (s *memAPIStore) SetPortRule(_ context.Context, r *storage.PortRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules[r.ID] = r
	return nil
}

func (s *memAPIStore) DeletePortRule(_ context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rules, id)
	return nil
}
