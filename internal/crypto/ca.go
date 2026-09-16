package crypto

import (
	"encoding/binary"
	"fmt"
	"time"
)

// Certificate-chain time constants (§17.6 / B3):
//
//   - root key: effectively long-lived, offline (no constant needed)
//   - intermediate CA: valid one year from signing
//   - node certificates: valid 90 days
//   - renewal starts 30 days before expiry (day 60 for a 90-day cert)
const (
	CAValidity   = 365 * 24 * time.Hour
	CertValidity = 90 * 24 * time.Hour
	// RenewWindow is how long before expiry renewal attempts begin.
	RenewWindow = 30 * 24 * time.Hour
)

// CACert is the root-signed certificate binding a public key to the role
// of intermediate certificate authority.
//
// The two-tier chain (§17.6) exists so the long-lived authority never sits
// online: the root signs only CA certs, and the intermediate CA (whose
// compromise is bounded by its 90-day-issued certs' validity) signs node
// certs. Recovering from a compromised CA is issuing a new CACert with the
// offline root — that is *not* root rotation, so the rotation bootstrap
// paradox no longer applies.
type CACert struct {
	CAKey     [32]byte // the intermediate CA's Ed25519 public key
	NotBefore uint64   // Unix seconds
	NotAfter  uint64   // Unix seconds
	Signer    [32]byte // root Ed25519 public key
	Signature []byte
}

// Bytes is the canonical body signed by the root (everything but the
// signature).
func (c *CACert) Bytes() []byte {
	buf := make([]byte, 0, 1+32+8+8+32)
	buf = append(buf, 0xCA) // domain separation from node certs
	buf = append(buf, c.CAKey[:]...)
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], c.NotBefore)
	buf = append(buf, nb[:]...)
	var na [8]byte
	binary.BigEndian.PutUint64(na[:], c.NotAfter)
	buf = append(buf, na[:]...)
	buf = append(buf, c.Signer[:]...)
	return buf
}

// SignCACert issues an intermediate-CA certificate for caPub with the root
// key. notBefore/notAfter of zero mean "now" and "now + CAValidity".
func SignCACert(rootKP *KeyPair, caPub [32]byte, notBefore, notAfter uint64) (*CACert, error) {
	now := uint64(time.Now().Unix())
	if notBefore == 0 {
		notBefore = now
	}
	if notAfter == 0 {
		notAfter = notBefore + uint64(CAValidity/time.Second)
	}
	c := &CACert{CAKey: caPub, NotBefore: notBefore, NotAfter: notAfter}
	if len(rootKP.Public) == 32 {
		copy(c.Signer[:], rootKP.Public)
	}
	sig, err := rootKP.Sign(c.Bytes())
	if err != nil {
		return nil, fmt.Errorf("sign CA cert: %w", err)
	}
	c.Signature = sig
	return c, nil
}

// Verify checks the root signature on the CA certificate.
func (c *CACert) Verify() error {
	if len(c.Signature) == 0 {
		return fmt.Errorf("CA certificate has no signature")
	}
	if !Verify(ed25519PubKey(c.Signer), c.Bytes(), c.Signature) {
		return fmt.Errorf("invalid CA certificate signature")
	}
	return nil
}

// vVerify is the chain verification in one pass:
//
//	rootPub ──signs── CA cert ──signs── node cert
//
// Checks, in order: the CA cert is signed by the expected root; the CA's
// validity window covers now; the node cert is signed by that exact CA
// key; the node cert has not expired. timeNow is a Unix-seconds clock for
// testability.
func ChainVerify(rootPub [32]byte, ca *CACert, cert *Cert, timeNow uint64) error {
	if ca == nil || cert == nil {
		return fmt.Errorf("nil certificate in chain")
	}
	if ca.Signer != rootPub {
		return fmt.Errorf("CA certificate not signed by the trusted root")
	}
	if err := ca.Verify(); err != nil {
		return err
	}
	if timeNow < ca.NotBefore {
		return fmt.Errorf("CA certificate not yet valid")
	}
	if timeNow >= ca.NotAfter {
		return fmt.Errorf("CA certificate expired")
	}
	if cert.Signer != ca.CAKey {
		return fmt.Errorf("node certificate not signed by the active intermediate CA")
	}
	if err := cert.VerifyCert(); err != nil {
		return err
	}
	if cert.Expiry != 0 && timeNow >= cert.Expiry {
		return fmt.Errorf("node certificate expired")
	}
	return nil
}

// ShouldRenewCA reports whether the CA certificate is inside the renewal
// window and should trigger re-issuance (B3: starts trying 30 days before
// expiry). The *decision* to renew belongs to the root owner; this is only
// the timing signal.
func ShouldRenewCA(ca *CACert, timeNow uint64) bool {
	if ca == nil {
		return true
	}
	window := uint64(RenewWindow / time.Second)
	return timeNow+window >= ca.NotAfter
}