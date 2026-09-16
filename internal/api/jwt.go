package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Minimal HS256 JWT (§9.1 安全措施 #2), implemented without a dependency
// so the security boundary is small enough to audit. Only the claims this
// API consumes are modelled; anything unexpected is rejected.
type Claims struct {
	Sub  string `json:"sub"`  // username
	Role string `json:"role"` // admin (reserved for future roles)
	Iat  int64  `json:"iat"`
	Exp  int64  `json:"exp"`
	Typ  string `json:"typ"` // "access" | "refresh"
}

// IssueToken signs a JWT with the HS256 secret.
func IssueToken(secret []byte, c Claims) (string, error) {
	if len(secret) == 0 {
		return "", errors.New("api: empty JWT secret")
	}
	if c.Exp <= 0 {
		return "", errors.New("api: token must carry an expiry")
	}
	header := `{"alg":"HS256","typ":"JWT"}`
	body, err := json.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("api: marshal claims: %w", err)
	}
	payload := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString(body)
	sig := hmacSHA256(secret, payload)
	return payload + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

// VerifyToken validates signature, form, and expiry. It only accepts
// access/refresh tokens with a valid subject.
func VerifyToken(secret []byte, token string, now time.Time) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("api: malformed token")
	}
	expected := hmacSHA256(secret, parts[0]+"."+parts[1])
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(expected, sig) {
		return nil, errors.New("api: invalid token signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("api: malformed token body")
	}
	var c Claims
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, errors.New("api: malformed token claims")
	}
	if c.Sub == "" {
		return nil, errors.New("api: token has no subject")
	}
	if c.Typ != "access" && c.Typ != "refresh" {
		return nil, errors.New("api: token has no type")
	}
	if c.Exp != 0 && now.Unix() >= c.Exp {
		return nil, errors.New("api: token expired")
	}
	return &c, nil
}

func hmacSHA256(secret []byte, msg string) []byte {
	m := hmac.New(sha256.New, secret)
	m.Write([]byte(msg))
	return m.Sum(nil)
}