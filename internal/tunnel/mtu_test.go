package tunnel

import "testing"

// TestInvariantD3_MTUArithmetic checks the arithmetic that D3 flagged as
// inconsistent. The pre-P1 design used 1280 for both inner and outer MTU, which
// cannot hold once encapsulation is counted; these tests pin the corrected
// relationship so it cannot silently regress.
func TestInvariantD3_MTUArithmetic(t *testing.T) {
	const pathMTU = 1500

	// Overhead is the sum of every header added on the way out.
	overheadV6 := EncapsulationOverhead(true)
	if want := IPv6HeaderLen + UDPHeaderLen + NoiseOverhead + KCPOverhead; overheadV6 != want {
		t.Errorf("IPv6 encapsulation overhead = %d, want %d", overheadV6, want)
	}
	overheadV4 := EncapsulationOverhead(false)
	if want := IPv4HeaderLen + UDPHeaderLen + NoiseOverhead + KCPOverhead; overheadV4 != want {
		t.Errorf("IPv4 encapsulation overhead = %d, want %d", overheadV4, want)
	}
	if overheadV6 <= overheadV4 {
		t.Error("IPv6 header is larger than IPv4, so its overhead must be larger")
	}

	// inner = path - overhead, and it must actually fit.
	inner := InnerMTU(pathMTU, true)
	if inner != pathMTU-overheadV6 {
		t.Errorf("InnerMTU(%d, ipv6) = %d, want %d", pathMTU, inner, pathMTU-overheadV6)
	}
	if err := ValidateMTU(inner, pathMTU, true); err != nil {
		t.Errorf("computed inner MTU %d rejected: %v", inner, err)
	}

	// One byte over budget must be rejected: that is the misconfiguration that
	// used to silently fragment every full-size packet.
	if err := ValidateMTU(inner+1, pathMTU, true); err == nil {
		t.Error("ValidateMTU accepted an inner MTU larger than the path budget")
	}
}

// TestMTUAdvisoryBelowIPv6Minimum documents the arithmetic corner the design
// must live with: a 1280-byte IPv6 path leaves less than 1280 for the inner
// packet, so the virtual link cannot meet RFC 8200 §5. It must be advisible
// rather than fatal, because such a path is otherwise legitimate.
func TestMTUAdvisoryBelowIPv6Minimum(t *testing.T) {
	inner := InnerMTU(1280, true)
	if inner >= 1280 {
		t.Fatalf("expected inner MTU below 1280 for a 1280 IPv6 path, got %d", inner)
	}
	if MTUAdvisory(inner) == "" {
		t.Error("expected an advisory for a sub-1280 inner MTU")
	}
	// A normal 1500 path must not trigger the advisory.
	if adv := MTUAdvisory(InnerMTU(1500, true)); adv != "" {
		t.Errorf("unexpected advisory for a 1500 path: %s", adv)
	}
	// Fitting inside the path is still a hard requirement regardless of family.
	if err := ValidateMTU(InnerMTU(1280, true), 1280, true); err != nil {
		t.Errorf("a correctly sized sub-1280 inner MTU must not be rejected: %v", err)
	}
}

// TestDefaultConfigMTUFits checks the shipped default (1280) actually fits a
// standard path, so the out-of-the-box configuration does not fragment.
func TestDefaultConfigMTUFits(t *testing.T) {
	const configuredInner = 1280
	for _, pathMTU := range []int{1500, 9000} {
		if err := ValidateMTU(configuredInner, pathMTU, true); err != nil {
			t.Errorf("default inner MTU %d does not fit a %d path: %v", configuredInner, pathMTU, err)
		}
	}
}
