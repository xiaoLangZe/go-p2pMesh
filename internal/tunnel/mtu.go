package tunnel

import "fmt"

// MTU arithmetic.
//
// The design flags (D3) that setting both the inner TUN MTU and the outer path
// MTU to 1280 cannot work: the inner payload still has to carry the
// encapsulation, so the usable inner MTU is the path MTU minus every header the
// stack adds on the way out. Sizing it wrong causes either fragmentation or a
// PMTU black hole, which shows up as "large packets vanish, small ones work".
//
// Encapsulation stack (outermost first) for a data packet on a UDP tunnel:
//
//	[IPv6 or IPv4 header][UDP header][Noise nonce+tag][KCP segment][IP packet]
//
// The TUN device carries the innermost IP packet, so its MTU must be:
//
//	inner = pathMTU − outerIPHeader − UDPHeader − NoiseOverhead − KCPOverhead
const (
	// IPv4HeaderLen is the minimum IPv4 header (no options).
	IPv4HeaderLen = 20
	// IPv6HeaderLen is the fixed IPv6 header (RFC 8200).
	IPv6HeaderLen = 40
	// UDPHeaderLen is the fixed UDP header.
	UDPHeaderLen = 8
	// KCPOverhead is the per-segment KCP header (kcp-go).
	KCPOverhead = 24
	// NoiseOverhead is the per-packet AEAD framing: 8-byte nonce + 16-byte tag.
	NoiseOverhead = 8 + 16
)

// OuterHeaderLen returns the outer IP header length for the given family.
func OuterHeaderLen(isIPv6 bool) int {
	if isIPv6 {
		return IPv6HeaderLen
	}
	return IPv4HeaderLen
}

// EncapsulationOverhead returns the total per-packet overhead added on top of
// an inner IP packet when it travels through the tunnel.
func EncapsulationOverhead(isIPv6 bool) int {
	return OuterHeaderLen(isIPv6) + UDPHeaderLen + NoiseOverhead + KCPOverhead
}

// InnerMTU computes the TUN device MTU that fits inside a path of pathMTU.
//
// pathMTU is the largest packet the underlying path can carry without
// fragmentation. For an IPv6 path this is at least 1280 (RFC 8200 §5); for an
// IPv4 path it is typically 1500.
func InnerMTU(pathMTU int, outerIsIPv6 bool) int {
	return pathMTU - EncapsulationOverhead(outerIsIPv6)
}

// ValidateMTU checks that the configured inner MTU actually fits inside the
// path. A value that does not fit is a hard error: accepting it would fragment
// every full-size packet, which surfaces later as mysterious large-packet loss
// rather than as a configuration mistake.
//
// Note the arithmetic has a real consequence: a UDP+KCP+Noise tunnel over IPv6
// costs 96 bytes of overhead, so an IPv6 path of exactly 1280 (the protocol
// minimum) leaves only 1184 for the inner packet — below IPv6's stated 1280
// link minimum. That case is reported by MTUAdvisory rather than rejected,
// because such a path is legitimate (IPv6-only path) and the operator needs to
// make a deliberate choice, not be blocked.
func ValidateMTU(innerMTU, pathMTU int, outerIsIPv6 bool) error {
	if innerMTU < 1 {
		return fmt.Errorf("inner MTU %d is not positive", innerMTU)
	}
	maxInner := InnerMTU(pathMTU, outerIsIPv6)
	if innerMTU > maxInner {
		return fmt.Errorf(
			"inner MTU %d exceeds path budget: path MTU %d − overhead %d = %d max inner",
			innerMTU, pathMTU, EncapsulationOverhead(outerIsIPv6), maxInner)
	}
	return nil
}

// MTUAdvisory returns a non-empty warning when the inner MTU is technically
// usable but violates the IPv6 link minimum, or is low enough that common upper
// layers may misbehave. An empty string means no concern.
func MTUAdvisory(innerMTU int) string {
	if innerMTU < 1280 {
		return fmt.Sprintf(
			"inner MTU %d is below the IPv6 link minimum of 1280; "+
				"the virtual link will not meet RFC 8200 §5. "+
				"Raise the path MTU (e.g. a 1500 path yields %d) or accept that "+
				"IPv6 traffic on this link is non-conformant",
			innerMTU, InnerMTU(1500, true))
	}
	return ""
}
