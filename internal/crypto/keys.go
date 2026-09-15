// Package crypto implements the Noise IK handshake, key management,
// and certificate signing/verification for go-p2pmesh.
package crypto

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"

	"github.com/flynn/noise"
)

// KeyPair bundles an Ed25519 signing key pair.
type KeyPair struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

// Sign signs a message with the Ed25519 private key.
func (kp *KeyPair) Sign(message []byte) ([]byte, error) {
	if len(kp.Private) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid private key size %d", len(kp.Private))
	}
	return ed25519.Sign(kp.Private, message), nil
}

// Verify checks an Ed25519 signature against a public key.
func Verify(pub ed25519.PublicKey, message, sig []byte) bool {
	return ed25519.Verify(pub, message, sig)
}

// GenerateKeyPair generates a new Ed25519 key pair using crypto/rand.
func GenerateKeyPair() (*KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &KeyPair{Public: pub, Private: priv}, nil
}

// Cert is a node certificate signed by the root server's Ed25519 key.
type Cert struct {
	NodeID    string   // canonical NodeID string
	PubKey    [32]byte // X25519 static public key
	Role      Role     // "client", "bootstrap", "root"
	Expiry    uint64   // Unix timestamp; 0 = no expiry
	Signer    [32]byte // root Ed25519 public key that signed this cert
	Signature []byte   // Ed25519 signature over the cert body
}

// Role enumerates the roles a certificate can authorize.
type Role string

const (
	RoleClient    Role = "client"
	RoleBootstrap Role = "bootstrap"
	RoleRoot      Role = "root"
)

// Bytes returns the canonical certificate body (everything except the
// signature) that the signer signs over.
func (c *Cert) Bytes() []byte {
	buf := make([]byte, 0, 32+1+8+32)
	buf = append(buf, []byte(c.NodeID)...)
	buf = append(buf, c.PubKey[:]...)
	buf = append(buf, byte(c.Role[0]))
	var exp [8]byte
	binary.BigEndian.PutUint64(exp[:], c.Expiry)
	buf = append(buf, exp[:]...)
	buf = append(buf, c.Signer[:]...)
	return buf
}

// SignCert creates and signs a Cert with the root key pair.
func SignCert(rootKP *KeyPair, nodeID string, pub [32]byte, role Role, expiry uint64) (*Cert, error) {
	c := &Cert{
		NodeID: nodeID,
		PubKey: pub,
		Role:   role,
		Expiry: expiry,
	}
	if len(rootKP.Public) == 32 {
		copy(c.Signer[:], rootKP.Public)
	}
	sig, err := rootKP.Sign(c.Bytes())
	if err != nil {
		return nil, fmt.Errorf("sign cert: %w", err)
	}
	c.Signature = sig
	return c, nil
}

// VerifyCert checks that a certificate's signature is valid against the
// embedded signer public key.
func (c *Cert) VerifyCert() error {
	if len(c.Signature) == 0 {
		return fmt.Errorf("certificate has no signature")
	}
	if !Verify(ed25519.PublicKey(c.Signer[:]), c.Bytes(), c.Signature) {
		return fmt.Errorf("invalid certificate signature")
	}
	return nil
}

// NoiseHandshake is the interface for the Noise IK handshake state machine.
type NoiseHandshake interface {
	Initiate(prologue []byte) ([]byte, error)
	Respond(message []byte) ([]byte, error)
	Finalize(message []byte) error
	Split() (*noise.CipherState, *noise.CipherState, error)
}

// NoiseIK implements the NoiseHandshake interface using
// Noise_IK_25519_ChaChaPoly_BLAKE2s.
type NoiseIK struct {
	localStatic  [32]byte
	localPub     [32]byte
	remoteStatic [32]byte
	isInitiator  bool
	hs           *noise.HandshakeState
	sendCipher   *noise.CipherState
	recvCipher   *noise.CipherState
	completed    bool
}

// NewNoiseIKInitiator creates the initiator side of the IK handshake.
func NewNoiseIKInitiator(localPriv, remotePub [32]byte) *NoiseIK {
	return &NoiseIK{
		localStatic:  localPriv,
		localPub:     deriveX25519Public(localPriv),
		remoteStatic: remotePub,
		isInitiator:  true,
	}
}

// NewNoiseIKResponder creates the responder side of the IK handshake.
func NewNoiseIKResponder(localPriv [32]byte) *NoiseIK {
	return &NoiseIK{
		localStatic: localPriv,
		localPub:    deriveX25519Public(localPriv),
		isInitiator: false,
	}
}

// Initiate starts the handshake as the initiator.
func (n *NoiseIK) Initiate(prologue []byte) ([]byte, error) {
	if !n.isInitiator {
		return nil, fmt.Errorf("Initiate called on responder")
	}
	cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	cfg := noise.Config{
		CipherSuite:   cs,
		Random:        nil,
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      prologue,
		StaticKeypair: noise.DHKey{Private: n.localStatic[:], Public: n.localPub[:]},
		PeerStatic:    n.remoteStatic[:],
	}
	hs, err := noise.NewHandshakeState(cfg)
	if err != nil {
		return nil, fmt.Errorf("new handshake state: %w", err)
	}
	n.hs = hs
	out, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("write handshake message: %w", err)
	}
	return out, nil
}

// Respond processes an incoming handshake message (responder side).
// Returns the responder's handshake message to send back.
func (n *NoiseIK) Respond(message []byte) ([]byte, error) {
	if n.isInitiator {
		return nil, fmt.Errorf("Respond called on initiator")
	}
	if n.hs == nil {
		cs := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
		cfg := noise.Config{
			CipherSuite:   cs,
			Random:        nil,
			Pattern:       noise.HandshakeIK,
			Initiator:     false,
			StaticKeypair: noise.DHKey{Private: n.localStatic[:], Public: n.localPub[:]},
		}
		hs, err := noise.NewHandshakeState(cfg)
		if err != nil {
			return nil, fmt.Errorf("new handshake state: %w", err)
		}
		n.hs = hs
	}
	// Read the initiator's message.
	_, rs, rr, err := n.hs.ReadMessage(nil, message)
	if err != nil {
		return nil, fmt.Errorf("read handshake message: %w", err)
	}
	// Write the responder's response.
	out, ws, wr, err := n.hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("write responder message: %w", err)
	}
	// After the responder writes, both ciphers may be returned.
	if ws != nil && wr != nil {
		n.sendCipher = ws
		n.recvCipher = wr
		n.completed = true
	} else if rs != nil && rr != nil {
		// Some noise implementations return ciphers on Read.
		n.sendCipher = rs
		n.recvCipher = rr
		n.completed = true
	}
	return out, nil
}

// Finalize processes the final handshake message (initiator side).
func (n *NoiseIK) Finalize(message []byte) error {
	if !n.isInitiator {
		return fmt.Errorf("Finalize called on responder")
	}
	if n.hs == nil {
		return fmt.Errorf("handshake not initiated")
	}
	_, rs, rr, err := n.hs.ReadMessage(nil, message)
	if err != nil {
		return fmt.Errorf("read final message: %w", err)
	}
	if rs != nil && rr != nil {
		n.sendCipher = rs
		n.recvCipher = rr
		n.completed = true
	}
	return nil
}

// Split returns the send/receive CipherStates after the handshake completes.
func (n *NoiseIK) Split() (*noise.CipherState, *noise.CipherState, error) {
	if !n.completed {
		return nil, nil, fmt.Errorf("handshake not completed")
	}
	return n.sendCipher, n.recvCipher, nil
}

// Encrypt encrypts a plaintext message using the send cipher.
func (n *NoiseIK) Encrypt(plaintext []byte) ([]byte, error) {
	if n.sendCipher == nil {
		return nil, fmt.Errorf("send cipher not available")
	}
	return n.sendCipher.Encrypt(nil, nil, plaintext)
}

// Decrypt decrypts a ciphertext using the receive cipher.
func (n *NoiseIK) Decrypt(ciphertext []byte) ([]byte, error) {
	if n.recvCipher == nil {
		return nil, fmt.Errorf("recv cipher not available")
	}
	return n.recvCipher.Decrypt(nil, nil, ciphertext)
}

// IsCompleted reports whether the handshake has finished.
func (n *NoiseIK) IsCompleted() bool { return n.completed }

// LocalPubKey returns the local X25519 static public key.
func (n *NoiseIK) LocalPubKey() [32]byte { return n.localPub }

// RemoteStatic returns the remote party's X25519 static public key (if known).
func (n *NoiseIK) RemoteStatic() [32]byte { return n.remoteStatic }

// deriveX25519Public derives the X25519 public key from a 32-byte private key.
// Uses the noise library's DH25519: DH(priv, basepoint) = public key.
// The X25519 basepoint is the standard 9-byte-repeated constant.
func deriveX25519Public(priv [32]byte) [32]byte {
	basepoint := [32]byte{9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	pub, err := noise.DH25519.DH(priv[:], basepoint[:])
	if err != nil {
		return [32]byte{}
	}
	var out [32]byte
	copy(out[:], pub)
	return out
}
