package types

import (
	"fmt"
	"net/netip"
)

// IPv6ULA is the default ULA /64 prefix used for the virtual mesh network.
// It can be overridden via configuration but must be a /64 ULA (fd00::/8 range).
const IPv6ULA = "fd00:9bd8::"

// DeriveIPv6Addr computes the mesh-internal IPv6 address for a node in a room.
//
// The address is the ULA prefix + the lower 48 bits of the room-salted digest
// of the node ID. Salting by room key enforces invariant I7: the same node has
// a different address in each room, so an address learned in room A does not
// resolve in room B.
//
// Unlike the pre-P1-baseline version this function takes the room key, not just the node
// ID — an unsalted address would be identical across rooms and would let any
// peer reach a node regardless of room membership.
func DeriveIPv6Addr(nodeID NodeID, roomKey RoomKey) (netip.Addr, error) {
	ula, err := netip.ParseAddr(IPv6ULA)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid ULA prefix %q: %w", IPv6ULA, err)
	}
	d := roomKey.saltedDigest(nodeID)

	var addr [16]byte
	raw := ula.AsSlice()
	copy(addr[:8], raw[:8])
	// Interface identifier: 6 bytes from the salted digest. The remaining two
	// bytes of the suffix stay zero so addresses stay inside a /64 and are easy
	// to read in logs.
	copy(addr[10:], d[:6])
	// Flip the universal/local bit (RFC 4291 §2.5.1) as a conventional marker
	// that this identifier is not derived from a hardware MAC.
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
