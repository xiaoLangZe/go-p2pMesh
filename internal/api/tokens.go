package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"sync"
	"time"
)

// tokenStore keeps issued refresh tokens by their SHA-256 hash — the
// database-side principle of §9.1 #5 ("只存 SHA256(token)") applied to the
// in-memory registry: revoking or querying a token never needs its plaintext.
type tokenStore struct {
	mu     sync.Mutex
	hashes map[string]expiry // sha256 hex -> expiry
	now    func() time.Time
}

type expiry struct {
	Expires time.Time
}

func newTokenStore() *tokenStore {
	return &tokenStore{hashes: make(map[string]expiry), now: time.Now}
}

func tokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// add records a refresh token with its lifetime.
func (s *tokenStore) add(token string, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hashes[tokenHash(token)] = expiry{Expires: s.now().Add(ttl)}
}

// valid reports whether the token is known and unexpired.
func (s *tokenStore) valid(token string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.hashes[tokenHash(token)]
	if !ok {
		return false
	}
	if s.now().After(e.Expires) {
		delete(s.hashes, tokenHash(token))
		return false
	}
	return true
}

// revoke removes a token (logout).
func (s *tokenStore) revoke(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.hashes, tokenHash(token))
}

// passwordVerifier abstracts admin-credential checking so the handler can
// run against a real store or a test fixture.
type passwordVerifier interface {
	Verify(username, password string) (subject usernameRole, ok bool)
}

type usernameRole struct {
	Name string
	Role string
}

// constantTimeEq compares two strings without early exit.
func constantTimeEq(a, b string) bool {
	if len(a) != len(b) {
		return false // leaks length, but hashes are fixed-width in practice
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}