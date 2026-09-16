package api

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/internal/storage"
	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// Store is the narrow storage surface the handlers consume. storage.Store
// satisfies it; tests supply a small in-memory implementation.
type Store interface {
	ListNodes(ctx context.Context, f storage.NodeFilter) ([]*storage.Node, error)
	GetNode(ctx context.Context, id string) (*storage.Node, error)
	UpdateNodeStatus(ctx context.Context, id string, s storage.NodeStatus) error
	DeleteNode(ctx context.Context, id string) error
	ListRooms(ctx context.Context) ([]*types.Room, error)
	ListRoomMembers(ctx context.Context, roomID string) ([]*storage.Node, error)
	GetPortRules(ctx context.Context, nodeID string) ([]*storage.PortRule, error)
	SetPortRule(ctx context.Context, r *storage.PortRule) error
	DeletePortRule(ctx context.Context, id string) error
}

// Deps bundles the handlers' dependencies so the whole API runs against
// a real store or a test fixture alike.
type Deps struct {
	Store      Store
	Secret     []byte
	AdminUser  string
	AdminHash  []byte // bcrypt hash of the admin password
	Tokens     *tokenStore
	AccessTTL  time.Duration
	RefreshTTL time.Duration
	Now        func() time.Time
	// Servers feeds the /servers endpoints (server mesh view).
	Servers func() []ServerInfo
}

// ServerInfo is the API-facing view of one mesh server.
type ServerInfo struct {
	ID       string `json:"id"`
	Addr     string `json:"addr"`
	IsRoot   bool   `json:"is_root"`
	LastSeen string `json:"last_seen"`
}

type handler struct {
	d Deps
}

func (h *handler) now() time.Time {
	if h.d.Now != nil {
		return h.d.Now()
	}
	return time.Now()
}

// --- /auth ---

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (h *handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "malformed body")
		return
	}
	if req.Username == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "username and password required")
		return
	}
	if req.Username != h.d.AdminUser || !checkPassHash(h.d.AdminHash, req.Password) {
		// Identical response for wrong user and wrong password.
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid credentials")
		return
	}
	now := h.now()
	access, err := IssueToken(h.d.Secret, Claims{
		Sub: req.Username, Role: "admin", Iat: now.Unix(),
		Exp: now.Add(h.d.AccessTTL).Unix(), Typ: "access",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "issue access token")
		return
	}
	refresh, err := IssueToken(h.d.Secret, Claims{
		Sub: req.Username, Role: "admin", Iat: now.Unix(),
		Exp: now.Add(h.d.RefreshTTL).Unix(), Typ: "refresh",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "issue refresh token")
		return
	}
	h.d.Tokens.add(refresh, h.d.RefreshTTL)
	writeOK(w, map[string]interface{}{
		"access_token":  access,
		"refresh_token": refresh,
		"expires_in":    int64(h.d.AccessTTL.Seconds()),
	})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h *handler) refresh(w http.ResponseWriter, r *http.Request) {
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "malformed body")
		return
	}
	if !h.d.Tokens.valid(req.RefreshToken) {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "refresh token unknown or expired")
		return
	}
	claims, err := VerifyToken(h.d.Secret, req.RefreshToken, h.now())
	if err != nil || claims.Typ != "refresh" {
		writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "invalid refresh token")
		return
	}
	now := h.now()
	access, err := IssueToken(h.d.Secret, Claims{
		Sub: claims.Sub, Role: claims.Role, Iat: now.Unix(),
		Exp: now.Add(h.d.AccessTTL).Unix(), Typ: "access",
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", "issue access token")
		return
	}
	writeOK(w, map[string]interface{}{
		"access_token": access,
		"expires_in":   int64(h.d.AccessTTL.Seconds()),
	})
}

func (h *handler) logout(w http.ResponseWriter, r *http.Request) {
	// Revoke the presented bearer token; additionally revoke a refresh token
	// carried in the body, so a single logout can kill the whole session.
	if token := bearer(r); token != "" {
		h.d.Tokens.revoke(token)
	}
	var req refreshRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.RefreshToken != "" {
		h.d.Tokens.revoke(req.RefreshToken)
	}
	writeOK(w, map[string]bool{"ok": true})
}

// --- /nodes ---

func (h *handler) listNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.d.Store.ListNodes(r.Context(), storage.NodeFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeOK(w, nodes)
}

func (h *handler) nodeDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := h.d.Store.GetNode(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "NOT_FOUND", "node not found")
		return
	}
	writeOK(w, n)
}

func (h *handler) nodeStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "malformed body")
		return
	}
	if req.Status != string(storage.NodeStatusOnline) && req.Status != string(storage.NodeStatusOffline) {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "status must be online or offline")
		return
	}
	if err := h.d.Store.UpdateNodeStatus(r.Context(), id, storage.NodeStatus(req.Status)); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeOK(w, map[string]string{"id": id, "status": req.Status})
}

func (h *handler) deleteNode(w http.ResponseWriter, r *http.Request) {
	if err := h.d.Store.DeleteNode(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeOK(w, map[string]bool{"deleted": true})
}

// --- /rooms ---

func (h *handler) listRooms(w http.ResponseWriter, r *http.Request) {
	rooms, err := h.d.Store.ListRooms(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeOK(w, rooms)
}

func (h *handler) roomMembers(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	members, err := h.d.Store.ListRoomMembers(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeOK(w, members)
}

// --- /ports ---

func (h *handler) listPorts(w http.ResponseWriter, r *http.Request) {
	nodeID := r.URL.Query().Get("nodeId")
	if nodeID == "" {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "nodeId query parameter required")
		return
	}
	rules, err := h.d.Store.GetPortRules(r.Context(), nodeID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeOK(w, rules)
}

func (h *handler) addPort(w http.ResponseWriter, r *http.Request) {
	var rule storage.PortRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "BAD_REQUEST", "malformed body")
		return
	}
	if err := h.d.Store.SetPortRule(r.Context(), &rule); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeOK(w, rule)
}

func (h *handler) deletePort(w http.ResponseWriter, r *http.Request) {
	if err := h.d.Store.DeletePortRule(r.Context(), r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	writeOK(w, map[string]bool{"deleted": true})
}

// --- /servers & /stats ---

func (h *handler) listServers(w http.ResponseWriter, r *http.Request) {
	if h.d.Servers == nil {
		writeOK(w, []ServerInfo{})
		return
	}
	writeOK(w, h.d.Servers())
}

func (h *handler) statsOverview(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.d.Store.ListNodes(r.Context(), storage.NodeFilter{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	rooms, err := h.d.Store.ListRooms(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "INTERNAL", err.Error())
		return
	}
	online := 0
	natTypes := map[string]int{}
	for _, n := range nodes {
		if n.Status == storage.NodeStatusOnline {
			online++
		}
		if n.NATType != "" {
			natTypes[n.NATType]++
		}
	}
	writeOK(w, map[string]interface{}{
		"node_total":  len(nodes),
		"node_online": online,
		"room_total":  len(rooms),
		"nat_types":   natTypes,
	})
}