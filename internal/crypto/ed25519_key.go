package crypto

import (
	"crypto/ed25519"
)

// ed25519PubKey adapts a [32]byte to ed25519.PublicKey for signature checks.
func ed25519PubKey(k [32]byte) ed25519.PublicKey {
	return ed25519.PublicKey(k[:])
}