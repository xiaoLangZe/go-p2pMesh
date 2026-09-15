package identity

import (
	"crypto/ecdh"
	"crypto/sha256"
	"fmt"
	"os"
	"runtime"
)

// CollectFingerprint gathers machine-identifying data and returns it as
// a byte slice suitable for hashing into a NodeID.
//
// The fallback chain (per platform):
//   1. OS machine ID (see machineid_*.go)
//   2. Hostname
//   3. OS type + CPU architecture
func CollectFingerprint() ([]byte, error) {
	var buf []byte

	// 1. OS machine ID
	mid, err := machineID()
	if err == nil && mid != "" {
		buf = append(buf, []byte(mid)...)
	} else {
		// Fallback: hostname + random persistent seed
		host, _ := os.Hostname()
		buf = append(buf, []byte(host)...)
	}

	// 2. Hostname (always include, even if machine ID is present)
	host, err := os.Hostname()
	if err == nil {
		buf = append(buf, []byte(host)...)
	}

	// 3. OS + arch
	buf = append(buf, []byte(runtime.GOOS)...)
	buf = append(buf, []byte(runtime.GOARCH)...)

	// If the fingerprint is empty (shouldn't happen), return an error.
	if len(buf) == 0 {
		return nil, fmt.Errorf("could not collect any fingerprint data")
	}

	return buf, nil
}

// x25519Public derives the X25519 public key from a 32-byte private key
// using the standard library's crypto/ecdh package (available since Go 1.20).
// This avoids external dependencies for P0.
func x25519Public(priv [32]byte) ([32]byte, error) {
	curve := ecdh.X25519()
	secret, err := curve.NewPrivateKey(priv[:])
	if err != nil {
		return [32]byte{}, fmt.Errorf("create x25519 private key: %w", err)
	}
	pub := secret.PublicKey()
	var out [32]byte
	copy(out[:], pub.Bytes())
	return out, nil
}

// hashFingerprint is a convenience helper used elsewhere if needed.
func hashFingerprint(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}
