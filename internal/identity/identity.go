// Package identity implements node identity generation and persistence.
//
// A node identity is derived from a machine fingerprint (machine ID +
// hostname + OS info) and persisted as a set of cryptographic keys:
//   - Ed25519 key pair for signing
//   - X25519 (curve25519) key pair as the Noise static key
//
// The public keys serve as the node's secondary identity on the mesh.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/yourorg/go-p2pmesh/pkg/types"
)

// Identity bundles a NodeID with its cryptographic key material.
// It wraps the public types.NodeIdentity for use within internal packages.
type Identity struct {
	types.NodeIdentity
}

// Generate creates a new Identity by:
//  1. Collecting the machine fingerprint.
//  2. Deriving the NodeID from the fingerprint.
//  3. Generating fresh Ed25519 and X25519 key pairs.
//
// The caller is responsible for calling Save() to persist the keys.
func Generate() (*Identity, error) {
	fp, err := CollectFingerprint()
	if err != nil {
		return nil, fmt.Errorf("collect fingerprint: %w", err)
	}
	nodeID := types.NewNodeIDFromFingerprint(fp)

	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}

	var xPub, xPriv [32]byte
	if _, err := rand.Read(xPriv[:]); err != nil {
		return nil, fmt.Errorf("generate x25519 private key: %w", err)
	}
	// Derive the X25519 public key from the private key.
	// Using curve25519.X25519 would require an external dependency;
	// We use the standard crypto/ecdh package; ecdh key agreement is P9.
	xPub, err = x25519Public(xPriv)
	if err != nil {
		return nil, fmt.Errorf("derive x25519 public key: %w", err)
	}

	return &Identity{
		types.NodeIdentity{
			ID:          nodeID,
			Ed25519Pub:  edPub,
			Ed25519Priv: edPriv,
			X25519Pub:   xPub,
			X25519Priv:  xPriv,
		},
	}, nil
}

// Load reads an identity from the given file path.
// The file format is a simple binary blob:
//   [1 byte version] [32 bytes ed25519 priv] [32 bytes x25519 priv]
// The public keys are derived from the private keys.
func Load(path string) (*Identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read identity file %q: %w", path, err)
	}
	if len(data) < 1+64 {
		return nil, errors.New("identity file too short")
	}
	if data[0] != 1 {
		return nil, fmt.Errorf("unsupported identity file version %d", data[0])
	}
	edPriv := ed25519.PrivateKey(data[1 : 1+64])
	if len(edPriv) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid ed25519 private key length")
	}
	edPub := edPriv.Public().(ed25519.PublicKey)

	var xPriv [32]byte
	copy(xPriv[:], data[1+64:1+64+32])
	xPub, err := x25519Public(xPriv)
	if err != nil {
		return nil, fmt.Errorf("derive x25519 public key: %w", err)
	}

	// Reconstruct the NodeID from the machine fingerprint.
	fp, err := CollectFingerprint()
	if err != nil {
		return nil, fmt.Errorf("collect fingerprint: %w", err)
	}
	nodeID := types.NewNodeIDFromFingerprint(fp)

	return &Identity{
		types.NodeIdentity{
			ID:          nodeID,
			Ed25519Pub:  edPub,
			Ed25519Priv: edPriv,
			X25519Pub:   xPub,
			X25519Priv:  xPriv,
		},
	}, nil
}

// Save persists the identity to the given file path with 0600 permissions.
func (id *Identity) Save(path string) error {
	buf := make([]byte, 0, 1+64+32)
	buf = append(buf, 1) // version
	buf = append(buf, id.Ed25519Priv...)
	buf = append(buf, id.X25519Priv[:]...)
	return os.WriteFile(path, buf, 0600)
}

// LoadOrGenerate tries to load the identity from path; if the file does
// not exist, it generates a new one and saves it.  This is the standard
// startup pattern.
func LoadOrGenerate(path string) (*Identity, error) {
	if path == "" {
		return nil, errors.New("identity file path is empty")
	}
	if _, err := os.Stat(path); err == nil {
		return Load(path)
	}
	id, err := Generate()
	if err != nil {
		return nil, err
	}
	if err := id.Save(path); err != nil {
		return nil, fmt.Errorf("save identity: %w", err)
	}
	return id, nil
}

// FingerprintHex returns the hex-encoded fingerprint string for debugging.
func (id *Identity) FingerprintHex() string {
	fp, _ := CollectFingerprint()
	h := sha256.Sum256(fp)
	return hex.EncodeToString(h[:16])
}

// OSInfo returns a human-readable OS/architecture string.
func OSInfo() string {
	return fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
}
