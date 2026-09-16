package types

import (
	"fmt"
	"net/netip"
)

// IPv4MeshBase is the base of the virtual IPv4 mesh address space.
//
// We use 240.0.0.0/4 (Class E reserved, RFC 1112) because:
//  1. It NEVER conflicts with RFC 1918 private LANs (10/8, 172.16/12, 192.168/16)
//  2. It NEVER conflicts with CGNAT (100.64.0.0/10, RFC 6598)
//  3. It NEVER conflicts with link-local APIPA (169.254/16)
//  4. No real network equipment uses 240.0.0.0/4 as a LAN address
//  5. ZeroTier uses the same approach, proving it works in practice
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
	Base netip.Addr // e.g. 240.10.20.0
	Plen int        // always 24
}

// String returns the CIDR notation, e.g. "240.10.20.0/24".
func (rs RoomSubnet) String() string {
	return fmt.Sprintf("%s/%d", rs.Base.String(), rs.Plen)
}

// DeriveRoomSubnet computes the /24 IPv4 subnet for a room from its salt key.
//
// The index comes from the room key (not the readable room ID), so an observer
// cannot tell which subnet a room occupies without the key — this is the same
// isolation property I7 relies on for IPv6.
func DeriveRoomSubnet(roomKey RoomKey) RoomSubnet {
	subnetIndex := roomKey.saltedSubnetIndex()

	// Each /24 occupies 256 addresses, so the index shifts left by 8 bits into
	// the 240.0.0.0/4 space:
	//   first octet  = 240 + (subnetIndex >> 16)   → 240–255
	//   second octet = (subnetIndex >> 8) & 0xFF
	//   third octet  = subnetIndex & 0xFF
	//   fourth octet = 0 (network address)
	firstOctet := 240 + byte(subnetIndex>>16)
	secondOctet := byte((subnetIndex >> 8) & 0xFF)
	thirdOctet := byte(subnetIndex & 0xFF)

	return RoomSubnet{
		Base: netip.AddrFrom4([4]byte{firstOctet, secondOctet, thirdOctet, 0}),
		Plen: IPv4RoomPrefixLen,
	}
}

// DeriveNodeIPv4 computes the IPv4 address for a node within a room's /24 subnet.
//
// The host part is derived from the room-salted digest of the node ID, mapped to
// 1–254 (avoiding the .0 network and .255 broadcast addresses). Derivation is
// deterministic: the same (NodeID, roomKey) always yields the same address, so
// no central allocator is needed and every peer computes the same answer.
func DeriveNodeIPv4(nodeID NodeID, roomKey RoomKey) netip.Addr {
	subnet := DeriveRoomSubnet(roomKey)
	d := roomKey.saltedDigest(nodeID)
	hostByte := byte(int(d[6]%254) + 1)

	base := subnet.Base.As4()
	return netip.AddrFrom4([4]byte{base[0], base[1], base[2], hostByte})
}

// IsMeshIPv4 reports whether an IPv4 address falls within the 240.0.0.0/4 mesh space.
func IsMeshIPv4(addr netip.Addr) bool {
	if !addr.Is4() {
		return false
	}
	b := addr.As4()
	return b[0] >= 240 // 240.0.0.0/4 → first octet 240–255
}

// IsMeshIPv6 reports whether an IPv6 address falls within the mesh ULA prefix.
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
	// Compare the /64 prefix: one ULA prefix covers the whole mesh.
	for i := 0; i < 8; i++ {
		if ulaBytes[i] != addrBytes[i] {
			return false
		}
	}
	return true
}
