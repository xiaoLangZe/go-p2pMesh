// Package types defines the public types shared across the go-p2pmesh ecosystem.
//
// These types are part of the stable public API (pkg/) and can be imported by
// third-party applications embedding the server or client packages.
package types

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"regexp"
	"strings"
)

// NodeID is a unique, persistable node identifier.
// The ID is case-insensitive, uses lowercase [a-z0-9-] characters,
// never starts or ends with '-', and never contains consecutive '-'.
// The canonical format is 8-4-4-4-6 segments, e.g. "a3f9k2m8-7p1q-x4r6-9m2p-abc123".
type NodeID string

// nodeIDPattern enforces: lowercase letters/digits, dash separators,
// no leading/trailing/consecutive dashes.
var nodeIDPattern = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// minIDLen and maxIDLen define the acceptable raw-length range of a NodeID
// (excluding dashes).  The canonical form uses 26 base32 characters.
const (
	minIDLen = 16
	maxIDLen = 52
)

// NewNodeIDFromFingerprint derives a canonical NodeID from raw fingerprint bytes.
// The fingerprint is hashed with SHA-256, base32-encoded (lowercase, no padding),
// truncated to 26 characters, and formatted into 8-4-4-4-6 segments.
func NewNodeIDFromFingerprint(fingerprint []byte) NodeID {
	hash := sha256.Sum256(fingerprint)
	encoded := strings.ToLower(base32.StdEncoding.EncodeToString(hash[:]))
	raw := encoded[:26] // 26 chars from the base32 alphabet [a-z2-7]
	return NodeID(formatSegments(raw))
}

// String returns the NodeID as a plain string.
func (n NodeID) String() string { return string(n) }

// Validate returns an error if the NodeID does not conform to the required format.
func (n NodeID) Validate() error {
	s := string(n)
	if s == "" {
		return fmt.Errorf("node id is empty")
	}
	if !nodeIDPattern.MatchString(s) {
		return fmt.Errorf("node id %q contains invalid characters or dash placement", s)
	}
	// Check the raw (non-dash) length is within bounds.
	raw := strings.ReplaceAll(s, "-", "")
	if len(raw) < minIDLen || len(raw) > maxIDLen {
		return fmt.Errorf("node id raw length %d out of range [%d,%d]", len(raw), minIDLen, maxIDLen)
	}
	return nil
}

// Equal reports whether two NodeIDs are equal (case-insensitive).
func (n NodeID) Equal(other NodeID) bool {
	return strings.EqualFold(string(n), string(other))
}

// Raw returns the NodeID with all dashes removed (uppercase).
// Useful as a compact key in maps and databases.
func (n NodeID) Raw() string {
	return strings.ToUpper(strings.ReplaceAll(string(n), "-", ""))
}

// formatSegments inserts dashes into a raw string as 8-4-4-4-6.
// If the string is shorter than 26, the remaining segments are simply shorter.
func formatSegments(raw string) string {
	segments := []int{8, 4, 4, 4, 6}
	var parts []string
	pos := 0
	for _, n := range segments {
		if pos >= len(raw) {
			break
		}
		end := pos + n
		if end > len(raw) {
			end = len(raw)
		}
		parts = append(parts, raw[pos:end])
		pos = end
	}
	return strings.Join(parts, "-")
}

// NodeIdentity bundles a NodeID with its cryptographic key material.
// The Ed25519 key pair is used for signing; the X25519 (curve25519) key pair
// is the Noise static key used during handshake.
type NodeIdentity struct {
	ID            NodeID
	Ed25519Pub    ed25519.PublicKey
	Ed25519Priv   ed25519.PrivateKey
	X25519Pub     [32]byte // Noise static public key
	X25519Priv    [32]byte // Noise static private key
}

// FingerprintHex returns the hex-encoded SHA-256 fingerprint of the
// X25519 static public key.  This is used as a secondary identity / pin.
func (ni *NodeIdentity) FingerprintHex() string {
	h := sha256.Sum256(ni.X25519Pub[:])
	return fmt.Sprintf("%x", h[:])
}
