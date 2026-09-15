package crypto

import "fmt"

// ErrNotImplemented is returned by any function whose implementation
// is deferred to a later phase.
var ErrNotImplemented = fmt.Errorf("not implemented in current phase")

// CertAuth is the certificate authority that holds the root Ed25519
// key pair and can sign/verify node certificates.
type CertAuth struct {
	rootKP    *KeyPair
	tofu      bool
	knownPubs map[[32]byte]bool
}

// NewCertAuth creates a new CertAuth.  If rootKP is nil, a new root
// key pair is generated.
func NewCertAuth(rootKP *KeyPair, tofu bool) (*CertAuth, error) {
	ca := &CertAuth{
		tofu:      tofu,
		knownPubs: make(map[[32]byte]bool),
	}
	if rootKP != nil {
		ca.rootKP = rootKP
	} else {
		kp, err := GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generate root key: %w", err)
		}
		ca.rootKP = kp
	}
	return ca, nil
}

// SignNodeCert signs a node certificate with the root key.
func (ca *CertAuth) SignNodeCert(nodeID string, pub [32]byte, role Role, expiry uint64) (*Cert, error) {
	if ca.rootKP == nil {
		return nil, fmt.Errorf("no root key pair")
	}
	return SignCert(ca.rootKP, nodeID, pub, role, expiry)
}

// VerifyNodeCert verifies a node certificate's signature.
func (ca *CertAuth) VerifyNodeCert(cert *Cert) error {
	if cert == nil {
		return fmt.Errorf("nil certificate")
	}
	if len(cert.Signature) == 0 && ca.tofu {
		if ca.knownPubs[cert.PubKey] {
			return nil
		}
		ca.knownPubs[cert.PubKey] = true
		return nil
	}
	return cert.VerifyCert()
}
