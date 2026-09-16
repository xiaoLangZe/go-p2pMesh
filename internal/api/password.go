package api

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword computes the bcrypt hash (§9.1 #4, cost 12) for a plaintext
// admin password at first start.
func HashPassword(plaintext string) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(plaintext), 12)
}

// checkPassHash compares a plaintext password to a bcrypt hash in constant
// time (bcrypt's comparison is already constant-time).
func checkPassHash(hash []byte, plaintext string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(plaintext)) == nil
}
