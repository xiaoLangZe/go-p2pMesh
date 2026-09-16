package api

import (
	"net/http"
	"sync"
	"time"
)

// Middleware types for JWT + rate-limiting (§9.1). The client TLS
// certificate, when configured, is enforced at the TLS layer (tls.go) —
// header-based cert checks are spoofable, so none exist here.

// AuthMiddleware verifies the JWT bearer token on every request except the
// public endpoints: login (issues tokens) and refresh (exchanges a refresh
// token for an access token — reachable precisely when the access token is
// unavailable). Logout stays gated: it is authenticated by an access token
// whose subject is the token being revoked.
type AuthMiddleware struct {
	Secret      []byte
	PublicPaths []string
	Now         func() time.Time
}

func (m AuthMiddleware) Wrap(next http.Handler) http.Handler {
	now := m.Now
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isPublicPath(m.PublicPaths, r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		token := bearer(r)
		if token == "" {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing bearer token")
			return
		}
		claims, err := VerifyToken(m.Secret, token, now())
		if err != nil {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", err.Error())
			return
		}
		if claims.Typ != "access" {
			writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "refresh token cannot access the API")
			return
		}
		next.ServeHTTP(w, r.WithContext(withClaims(r.Context(), claims)))
	})
}

func isPublicPath(paths []string, path string) bool {
	for _, p := range paths {
		if p != "" && p == path {
			return true
		}
	}
	return false
}

// RateLimitMiddleware enforces per-IP limits on login (5/min per §9.1 #6)
// and per-user limits elsewhere. Buckets live on the middleware instance so
// every server starts with fresh limiters (no cross-deployment bleed, and
// tests stay independent).
type RateLimitMiddleware struct {
	LoginPath    string
	LoginRate    int // per minute
	LoginBurst   int
	APIUserRate  int // per minute
	APIUserBurst int
	Now          func() time.Time

	ipLimits  sync.Map // ip -> *tokenBucketLimiter
	userLimits sync.Map // subject -> *tokenBucketLimiter
}

func (m *RateLimitMiddleware) Wrap(next http.Handler) http.Handler {
	now := m.Now
	if now == nil {
		now = time.Now
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var lim *tokenBucketLimiter
		if r.URL.Path == m.LoginPath {
			lim = keyedLimiter(&m.ipLimits, "ip:"+clientIP(r), m.LoginRate, m.LoginBurst)
		} else if c := claimsFrom(r.Context()); c != nil {
			lim = keyedLimiter(&m.userLimits, "u:"+c.Sub, m.APIUserRate, m.APIUserBurst)
		} else {
			// Public non-login endpoints (refresh): rate-limit by IP with
			// the API-user budget.
			lim = keyedLimiter(&m.ipLimits, "api-ip:"+clientIP(r), m.APIUserRate, m.APIUserBurst)
		}
		if !lim.Allow(now()) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// CORSMiddleware sets Access-Control-Allow-Origin from configuration.
func CORSMiddleware(allowedOrigin string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// AuditMiddleware logs every management operation after it completes
// (§9.1 #8). statusWriter captures the final response code.
func AuditMiddleware(log AuditLog) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			user := ""
			if c := claimsFrom(r.Context()); c != nil {
				user = c.Sub
			}
			log.Record(AuditEntry{
				At:       time.Now(),
				User:     user,
				Method:   r.Method,
				Path:     r.URL.Path,
				Status:   sw.status,
				ClientIP: clientIP(r),
			})
		})
	}
}

// statusWriter captures the response code for the audit trail.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}