package crypto

import (
	"testing"
	"time"
)

// TestChainHappyPath verifies the full chain: root → CA → node cert.
func TestChainHappyPath(t *testing.T) {
	root, _ := GenerateKeyPair()
	caKP, _ := GenerateKeyPair()
	now := uint64(time.Now().Unix())
	ca, err := SignCACert(root, pub32(caKP.Public), now, now+uint64(CAValidity/time.Second))
	if err != nil {
		t.Fatalf("SignCACert: %v", err)
	}

	nodeCert, err := SignCert(caKP, "node-1", [32]byte{1}, RoleClient, now+uint64(CertValidity/time.Second))
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}

	if err := ChainVerify(pub32(root.Public), ca, nodeCert, now+1); err != nil {
		t.Errorf("valid chain rejected: %v", err)
	}
}

// TestChainWrongRoot checks that a CA signed by a different root is refused.
func TestChainWrongRoot(t *testing.T) {
	rootA, _ := GenerateKeyPair()
	rootB, _ := GenerateKeyPair()
	caKP, _ := GenerateKeyPair()
	now := uint64(time.Now().Unix())
	ca, _ := SignCACert(rootA, pub32(caKP.Public), now, now+10000)
	cert, _ := SignCert(caKP, "n", [32]byte{1}, RoleClient, now+1000)

	if err := ChainVerify(pub32(rootB.Public), ca, cert, now); err == nil {
		t.Error("chain with mismatched trust anchor must be rejected")
	}
}

// TestChainWrongCAKey checks a node cert not signed by the CA key is refused.
func TestChainWrongCAKey(t *testing.T) {
	root, _ := GenerateKeyPair()
	caKP, _ := GenerateKeyPair()
	rogueKP, _ := GenerateKeyPair()
	now := uint64(time.Now().Unix())
	ca, _ := SignCACert(root, pub32(caKP.Public), now, now+10000)
	cert, _ := SignCert(rogueKP, "n", [32]byte{1}, RoleClient, now+1000)

	if err := ChainVerify(pub32(root.Public), ca, cert, now); err == nil {
		t.Error("node cert signed by a different key must be rejected")
	}
}

// TestChainCACertExpired checks the CA validity window is enforced.
func TestChainCACertExpired(t *testing.T) {
	root, _ := GenerateKeyPair()
	caKP, _ := GenerateKeyPair()
	now := uint64(time.Now().Unix())
	ca, _ := SignCACert(root, pub32(caKP.Public), now-20000, now-10000)
	cert, _ := SignCert(caKP, "n", [32]byte{1}, RoleClient, now+1000)

	if err := ChainVerify(pub32(root.Public), ca, cert, now); err == nil {
		t.Error("expired CA certificate must be rejected")
	}
}

// TestChainNodeCertExpired checks node-cert expiry enforcement.
func TestChainNodeCertExpired(t *testing.T) {
	root, _ := GenerateKeyPair()
	caKP, _ := GenerateKeyPair()
	now := uint64(time.Now().Unix())
	ca, _ := SignCACert(root, pub32(caKP.Public), now, now+100000)
	cert, _ := SignCert(caKP, "n", [32]byte{1}, RoleClient, now-100)

	if err := ChainVerify(pub32(root.Public), ca, cert, now); err == nil {
		t.Error("expired node certificate must be rejected")
	}
}

// TestCertAuthIssuesAndVerifies checks the online CA end to end.
func TestCertAuthIssuesAndVerifies(t *testing.T) {
	root, _ := GenerateKeyPair()
	ca, err := NewCertAuth(root, false)
	if err != nil {
		t.Fatalf("NewCertAuth: %v", err)
	}
	if ca.TOFU() {
		t.Fatal("TOFU must be off when constructed with tofu=false")
	}
	cert, err := ca.SignNodeCert("node-1", [32]byte{9}, RoleBootstrap, uint64(time.Now().Unix())+1)
	if err != nil {
		t.Fatalf("SignNodeCert: %v", err)
	}
	if err := ca.VerifyNodeCert(cert); err != nil {
		t.Errorf("self-issued cert failed verification: %v", err)
	}
}

// TestCertAuthRejectsForeignCert checks an unrelated CA's cert is refused.
func TestCertAuthRejectsForeignCert(t *testing.T) {
	ca, _ := NewCertAuth(nil, false)
	otherRoot, _ := GenerateKeyPair()
	otherCa, _ := NewCertAuth(otherRoot, false)
	cert, _ := otherCa.SignNodeCert("node-x", [32]byte{1}, RoleClient, uint64(time.Now().Unix())+5000)

	if err := ca.VerifyNodeCert(cert); err == nil {
		t.Error("foreign chain must be rejected")
	}
}

// TestTOFUAcceptsUnsignedThenPins checks trust-on-first-use semantics.
func TestTOFUAcceptsUnsignedThenPins(t *testing.T) {
	ca, _ := NewCertAuth(nil, true)
	if !ca.TOFU() {
		t.Fatal("TOFU must be on")
	}
	unsigned := &Cert{PubKey: [32]byte{7}, Role: RoleClient}
	// First contact: accepted and remembered.
	if err := ca.VerifyNodeCert(unsigned); err != nil {
		t.Fatalf("first TOFU contact rejected: %v", err)
	}
	// Same key again: accepted (pinned, not re-pinned).
	if err := ca.VerifyNodeCert(unsigned); err != nil {
		t.Errorf("pinned key rejected on second contact: %v", err)
	}
}

// TestShouldRenewCA checks the B3 renewal window (start trying 30 days out).
func TestShouldRenewCA(t *testing.T) {
	root, _ := GenerateKeyPair()
	caKP, _ := GenerateKeyPair()
	now := uint64(time.Now().Unix())
	year := uint64(CAValidity / time.Second)
	ca, _ := SignCACert(root, pub32(caKP.Public), now, now+year)

	if ShouldRenewCA(ca, now) {
		t.Error("fresh CA must not signal renewal")
	}
	// 5 days before expiry: definitely inside the window.
	near := ca.NotAfter - uint64(5*24*time.Hour/time.Second)
	if !ShouldRenewCA(ca, near) {
		t.Error("CA near expiry must signal renewal")
	}
}
