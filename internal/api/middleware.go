package api

import "net/http"

// Middleware types for JWT + mTLS + rate-limiting.
// Full implementation deferred to P3.

// AuthMiddleware verifies the JWT bearer token (and optionally the
// client TLS certificate) on every request.
func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// P3: validate Authorization header + optional client cert.
		next.ServeHTTP(w, r)
	})
}

// RateLimitMiddleware enforces per-IP and per-token rate limits.
func RateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// P3: implement token-bucket rate limiter.
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

// AuditMiddleware logs every management operation for audit trails.
func AuditMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// P3: log method, path, user, timestamp to database.
		next.ServeHTTP(w, r)
	})
}
