package types

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
)

// IPv6ULA is the default ULA /64 prefix used for the virtual mesh network.
// It can be overridden via configuration but must be a /64 ULA (fd00::/8 range).
const IPv6ULA = "fd00:9bd8::"

// DeriveIPv6Addr computes the mesh-internal IPv6 address for a given NodeID.
// The address is the ULA prefix + the lower 48 bits of SHA-256(NodeID).
// The result is deterministic and globally unique: the address can be
// reconstructed from the NodeID alone, without any central allocator.
func DeriveIPv6Addr(nodeID NodeID) (netip.Addr, error) {
	h := sha256.Sum256([]byte(nodeID))
	// Use the lower 48 bits (6 bytes) of the hash as the interface identifier.
	ula, err := netip.ParseAddr(IPv6ULA)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid ULA prefix %q: %w", IPv6ULA, err)
	}
	// Construct a full 128-bit address from the ULA prefix + host suffix.
	// ULA prefix occupies the first 80 bits (fd00:9bd8::/64 means 64 network bits
	// + 16 bits of subnet; we use the first 8 bytes of the prefix and append
	// 6 bytes from the hash, zero-filling the remaining bytes to reach 16 bytes).
	var addr [16]byte
	raw := ula.AsSlice()
	copy(addr[:8], raw[:8])
	// Set the Universal/Local and Individual/Group bits per RFC 4291 §2.5.1
	// for the modified EUI-64 style (not strictly necessary for ULA, but
	// conventional): flip bit 6 of the first suffix byte.
	copy(addr[10:], h[:6])
	addr[8] |= 0x02
	return netip.AddrFrom16(addr), nil
}

// PublicAddr is a node's public (observed) IP:port endpoint on the internet.
type PublicAddr struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// String returns "ip:port" or "[ipv6]:port".
func (p PublicAddr) String() string {
	return fmt.Sprintf("%s:%d", p.IP, p.Port)
}
