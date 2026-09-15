package types

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
)

// IPv4MeshBase is the base of the virtual IPv4 mesh address space.
//
// We use 240.0.0.0/4 (Class E reserved, RFC 1112) because:
//   1. It NEVER conflicts with RFC 1918 private LANs (10/8, 172.16/12, 192.168/16)
//   2. It NEVER conflicts with CGNAT (100.64.0.0/10, RFC 6598)
//   3. It NEVER conflicts with link-local APIPA (169.254/16)
//   4. No real network equipment uses 240.0.0.0/4 as a LAN address
//   5. ZeroTier uses the same approach, proving it works in practice
//
// The /4 prefix gives 2^28 addresses = 2^20 = 1,048,576 possible /24 subnets,
// which is more than enough for room-based allocation.
const IPv4MeshBase = "240.0.0.0"

// IPv4MeshPrefixLen is the prefix length of the entire mesh address space.
const IPv4MeshPrefixLen = 4

// IPv4RoomPrefixLen is the prefix length assigned to each room.
// Each room gets a /24 (256 addresses, 254 usable hosts).
const IPv4RoomPrefixLen = 24

// RoomSubnet represents the IPv4 /24 subnet allocated to a room.
type RoomSubnet struct {
	Base   netip.Addr // e.g. 240.10.20.0
	Plen   int        // always 24
}

// String returns the CIDR notation, e.g. "240.10.20.0/24".
func (rs RoomSubnet) String() string {
	return fmt.Sprintf("%s/%d", rs.Base.String(), rs.Plen)
}

// DeriveRoomSubnet computes the /24 IPv4 subnet for a given RoomID.
// The subnet is deterministically derived from the SHA-256 of the RoomID,
// mapped into the 240.0.0.0/4 space.  This means:
//   - The same room ID always gets the same subnet (no central allocator needed)
//   - Different rooms get different subnets (with overwhelming probability)
//   - The subnet never conflicts with any RFC 1918 / CGNAT / link-local LAN
func DeriveRoomSubnet(roomID RoomID) (RoomSubnet, error) {
	h := sha256.Sum256([]byte(roomID))
	// Use the lower 20 bits of the hash as the subnet index within 240.0.0.0/4.
	// 20 bits → 0 to 1,048,575 possible /24 subnets.
	subnetIndex := uint32(h[0])<<12 | uint32(h[1])<<4 | uint32(h[2]&0x0F)

	// The base address is 240.0.0.0 + (subnetIndex << 8) (since each /24 is 256 addresses).
	// 240.0.0.0 as bytes: [240, 0, 0, 0]
	// Adding subnetIndex << 8 means:
	//   first octet  = 240 + (subnetIndex >> 16)   → range 240-255
	//   second octet = (subnetIndex >> 8) & 0xFF
	//   third octet  = subnetIndex & 0xFF
	//   fourth octet = 0 (network address)
	firstOctet := 240 + byte(subnetIndex>>16)
	secondOctet := byte((subnetIndex >> 8) & 0xFF)
	thirdOctet := byte(subnetIndex & 0xFF)

	addr := netip.AddrFrom4([4]byte{firstOctet, secondOctet, thirdOctet, 0})
	return RoomSubnet{Base: addr, Plen: IPv4RoomPrefixLen}, nil
}

// DeriveNodeIPv4 computes the IPv4 address for a node within a room's /24 subnet.
// The host part is deterministically derived from the NodeID's SHA-256,
// mapped to 1-254 (avoiding .0 network and .255 broadcast addresses).
// The result is deterministic: the same (NodeID, RoomID) always yields the same address.
func DeriveNodeIPv4(nodeID NodeID, roomID RoomID) (netip.Addr, error) {
	subnet, err := DeriveRoomSubnet(roomID)
	if err != nil {
		return netip.Addr{}, err
	}
	// Hash the NodeID to get a deterministic host byte.
	h := sha256.Sum256([]byte(nodeID))
	// Map to 1-254 (avoid .0 and .255).
	hostByte := byte(int(h[0]%254) + 1)

	base := subnet.Base.As4()
	addr := netip.AddrFrom4([4]byte{base[0], base[1], base[2], hostByte})
	return addr, nil
}

// IsMeshIPv4 reports whether an IPv4 address falls within the 240.0.0.0/4 mesh space.
func IsMeshIPv4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	return b[0] >= 240 // 240.0.0.0/4 → first octet 240-255
}

// IsMeshIPv6 reports whether an IPv6 address falls within the fd00:9bd8::/64 mesh space.
func IsMeshIPv6(addr netip.Addr) bool {
	if !addr.Is6() {
		return false
	}
	ula, err := netip.ParseAddr(IPv6ULA)
	if err != nil {
		return false
	}
	ulaBytes := ula.As16()
	addrBytes := addr.As16()
	// Check the first 8 bytes (64-bit prefix) match.
	for i := 0; i < 8; i++ {
		if ulaBytes[i] != addrBytes[i] {
			return false
		}
	}
	return true
}
