package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Shared infrastructure: context plumbing, per-key token buckets, the
// audit log, and response helpers.

type claimsCtxKey struct{}

func withClaims(ctx context.Context, c *Claims) context.Context {
	return context.WithValue(ctx, claimsCtxKey{}, c)
}

func claimsFrom(ctx context.Context) *Claims {
	c, _ := ctx.Value(claimsCtxKey{}).(*Claims)
	return c
}

// tokenBucketLimiter is a fixed-rate permit bucket per key.
type tokenBucketLimiter struct {
	mu     sync.Mutex
	rate   float64 // permits per minute
	burst  float64
	tokens float64
	last   time.Time
}

func newTokenBucketLimiter(ratePerMinute, burst int) *tokenBucketLimiter {
	if ratePerMinute <= 0 {
		ratePerMinute = 5
	}
	if burst <= 0 {
		burst = ratePerMinute
	}
	b := &tokenBucketLimiter{rate: float64(ratePerMinute) / 60.0, burst: float64(burst)}
	b.tokens = b.burst
	return b
}

func (l *tokenBucketLimiter) Allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.last.IsZero() {
		l.last = now
	}
	elapsed := now.Sub(l.last).Seconds()
	l.tokens += elapsed * l.rate
	if l.tokens > l.burst {
		l.tokens = l.burst
	}
	l.last = now
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}

func keyedLimiter(m *sync.Map, key string, rate, burst int) *tokenBucketLimiter {
	if v, ok := m.Load(key); ok {
		return v.(*tokenBucketLimiter)
	}
	l := newTokenBucketLimiter(rate, burst)
	actual, _ := m.LoadOrStore(key, l)
	return actual.(*tokenBucketLimiter)
}

// AuditLog records one management operation (§9.1 #8).
type AuditLog interface {
	Record(entry AuditEntry)
}

// AuditEntry is one row of the audit trail.
type AuditEntry struct {
	At       time.Time
	User     string
	Method   string
	Path     string
	Status   int
	ClientIP string
}

// MemAuditLog keeps a bounded in-memory trail; the SQL-backed logger is
// injected by the server when storage is available.
type MemAuditLog struct {
	mu      sync.Mutex
	entries []AuditEntry
	max     int
}

func NewMemAuditLog(max int) *MemAuditLog {
	return &MemAuditLog{max: max}
}

func (m *MemAuditLog) Record(e AuditEntry) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries = append(m.entries, e)
	if m.max > 0 && len(m.entries) > m.max {
		m.entries = m.entries[len(m.entries)-m.max:]
	}
}

func (m *MemAuditLog) Entries() []AuditEntry {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]AuditEntry, len(m.entries))
	copy(out, m.entries)
	return out
}

// bearer extracts the token from the Authorization header.
func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return h[len(prefix):]
	}
	return ""
}

// clientIP extracts the source IP, preferring the direct remote address.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	return host
}

// response envelope (§9.4: {ok, data, error}).
type apiError struct {
	Code    string                 `json:"code"`
	Message string                 `json:"message"`
	Details map[string]interface{} `json:"details,omitempty"`
}

type apiResponse struct {
	OK    bool                    `json:"ok"`
	Data  interface{}             `json:"data,omitempty"`
	Error *apiError               `json:"error,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, apiResponse{OK: false, Error: &apiError{Code: code, Message: msg}})
}

func writeOK(w http.ResponseWriter, data interface{}) {
	writeJSON(w, http.StatusOK, apiResponse{OK: true, Data: data})
}