package crypto

import (
	"fmt"
	"time"
)

// CertAuth is the online certificate authority: it holds the *intermediate*
// CA key pair (§17.6) and its root-signed CA certificate, and issues and
// verifies node certificates.
//
// The root key itself never lives in a CertAuth instance: the offline root
// only ever calls SignCACert when provisioning or recovering an
// intermediate CA. This is the code shape of invariant I9 — the authority
// that matters most is not reachable from any online process.
type CertAuth struct {
	rootPub  [32]byte
	caKP     *KeyPair
	caCert   *CACert
	tofu     bool
	knownPubs map[[32]byte]bool
	// now is the clock (Unix seconds), injectable for tests.
	now func() time.Time
}

// NewCertAuth creates an online CA. If caKP or caCert is nil (the usual
// bootstrap case), it generates a fresh intermediate key pair and, when
// rootKP is also provided, has the root sign its CA certificate — with a
// nil root it signs the CA cert with the freshly generated root, which is
// only valid for a self-contained single-host deployment.
func NewCertAuth(rootKP *KeyPair, tofu bool) (*CertAuth, error) {
	ca := &CertAuth{
		tofu:      tofu,
		knownPubs: make(map[[32]byte]bool),
		now:       time.Now,
	}
	var kp *KeyPair
	var err error
	if rootKP != nil {
		copy(ca.rootPub[:], rootKP.Public)
		kp = rootKP
	} else {
		kp, err = GenerateKeyPair()
		if err != nil {
			return nil, fmt.Errorf("generate root key: %w", err)
		}
		copy(ca.rootPub[:], kp.Public)
	}
	caKP, err := GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("generate intermediate CA key: %w", err)
	}
	ca.caKP = caKP
	caCert, err := SignCACert(kp, pub32(caKP.Public), 0, 0)
	if err != nil {
		return nil, fmt.Errorf("sign CA certificate: %w", err)
	}
	ca.caCert = caCert
	return ca, nil
}

// RootPub returns the trusted root's public key embedded in this CA
// (the trust anchor to distribute to clients).
func (ca *CertAuth) RootPub() [32]byte { return ca.rootPub }

// CACertificate returns the CA's root-signed certificate (needed to
// present the chain to verifiers).
func (ca *CertAuth) CACertificate() *CACert { return ca.caCert }

// SignNodeCert signs a node certificate with the *intermediate* CA key.
func (ca *CertAuth) SignNodeCert(nodeID string, pub [32]byte, role Role, expiry uint64) (*Cert, error) {
	if ca.caKP == nil {
		return nil, fmt.Errorf("no intermediate CA key pair")
	}
	return SignCert(ca.caKP, nodeID, pub, role, expiry)
}

// VerifyNodeCert verifies a node certificate.
//
// With the certificate chain enabled (tofu=false) it runs the full chain:
// root → CA cert → node cert, including validity windows. Under TOFU the
// design (§15.2) treats the root binding as unverified: unsigned first
// contacts are remembered by public key, and — critically — that mode must
// leave core privileges off; callers check ca.TOFU() separately.
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
	return ChainVerify(ca.rootPub, ca.caCert, cert, uint64(ca.now().Unix()))
}

// TOFU reports whether trust-on-first-use is active. Callers gate core
// privileges on its inverse (§17.7: TOFU on → core privileges off).
func (ca *CertAuth) TOFU() bool { return ca.tofu }

// CAExpiry returns the CA certificate's expiry timestamp.
func (ca *CertAuth) CAExpiry() uint64 { return ca.caCert.NotAfter }

// pub32 extracts the public key bytes of a KeyPair.
func pub32(pub []byte) [32]byte {
	var out [32]byte
	copy(out[:], pub)
	return out
}