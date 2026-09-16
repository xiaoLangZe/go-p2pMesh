package types

import (
	"net/netip"
	"testing"
)

// TestInvariantI7_CrossRoomUnusable enforces invariant I7: an address derived for
// one room must not be valid in another. If this test fails, room isolation has
// silently degraded into "everyone can reach everyone".
func TestInvariantI7_CrossRoomUnusable(t *testing.T) {
	const nodeID NodeID = "a3f9k2m8-7p1q-x4r6-9m2p-abc123"

	keyA := DeriveRoomKey([]byte("mesh-secret"), "room-a", nil)
	keyB := DeriveRoomKey([]byte("mesh-secret"), "room-b", nil)

	v6A, err := DeriveIPv6Addr(nodeID, keyA)
	if err != nil {
		t.Fatalf("derive ipv6 in room A: %v", err)
	}
	v6B, err := DeriveIPv6Addr(nodeID, keyB)
	if err != nil {
		t.Fatalf("derive ipv6 in room B: %v", err)
	}
	if v6A == v6B {
		t.Errorf("I7 violated: same node has identical IPv6 %s in both rooms", v6A)
	}

	v4A := DeriveNodeIPv4(nodeID, keyA)
	v4B := DeriveNodeIPv4(nodeID, keyB)
	if v4A == v4B {
		t.Errorf("I7 violated: same node has identical IPv4 %s in both rooms", v4A)
	}
}

// TestRoomAddressDeterministic checks both peers compute the same address for
// the same (node, room key) without any coordination.
func TestRoomAddressDeterministic(t *testing.T) {
	const nodeID NodeID = "7p1q-x4r6-9m2p-abc123-def456"
	key := DeriveRoomKey([]byte("s"), "room", nil)

	first, err := DeriveIPv6Addr(nodeID, key)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveIPv6Addr(nodeID, key)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("derivation not deterministic: %s vs %s", first, second)
	}
	if DeriveNodeIPv4(nodeID, key) != DeriveNodeIPv4(nodeID, key) {
		t.Error("IPv4 derivation not deterministic")
	}
}

// TestRoomKeyNeedsSecret verifies the salt actually depends on the key material:
// a different mesh secret must produce a different address (D2 — salting that
// does not depend on a secret is equivalent to no salting).
func TestRoomKeyNeedsSecret(t *testing.T) {
	const nodeID NodeID = "a3f9k2m8-7p1q-x4r6-9m2p-abc123"

	k1 := DeriveRoomKey([]byte("secret-one"), "room", nil)
	k2 := DeriveRoomKey([]byte("secret-two"), "room", nil)

	a1, err := DeriveIPv6Addr(nodeID, k1)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := DeriveIPv6Addr(nodeID, k2)
	if err != nil {
		t.Fatal(err)
	}
	if a1 == a2 {
		t.Error("D2 violated: addresses identical under different mesh secrets")
	}
}

// TestExplicitRoomKeyOverridesMeshSecret checks an operator-supplied room key is
// what actually salts the address, so a closed room can pick its own secret.
func TestExplicitRoomKeyOverridesMeshSecret(t *testing.T) {
	const nodeID NodeID = "a3f9k2m8-7p1q-x4r6-9m2p-abc123"

	explicit := DeriveRoomKey([]byte("ignored"), "room", []byte("explicit-key"))
	different := DeriveRoomKey([]byte("ignored"), "room", []byte("other-key"))
	if explicit == different {
		t.Fatal("distinct explicit keys produced the same room key")
	}
	a, err := DeriveIPv6Addr(nodeID, explicit)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DeriveIPv6Addr(nodeID, different)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Error("explicit room key did not affect address derivation")
	}
}

// TestAddressSpaceDoesNotConflictWithLANs verifies the mesh IPv4 space never
// overlaps the address ranges a user's local network is likely to use.
func TestAddressSpaceDoesNotConflictWithLANs(t *testing.T) {
	lanRanges := []string{
		"10.0.0.0/8",     // RFC 1918
		"172.16.0.0/12",  // RFC 1918
		"192.168.0.0/16", // RFC 1918 (most home networks)
		"100.64.0.0/10",  // RFC 6598 CGNAT
		"169.254.0.0/16", // link-local / APIPA
		"127.0.0.0/8",    // loopback
	}
	lanPrefixes := make([]netip.Prefix, 0, len(lanRanges))
	for _, r := range lanRanges {
		p, err := netip.ParsePrefix(r)
		if err != nil {
			t.Fatalf("bad test range %s: %v", r, err)
		}
		lanPrefixes = append(lanPrefixes, p)
	}

	// Sample many rooms: the subnet must land outside every LAN range.
	for i := 0; i < 2000; i++ {
		roomID := RoomID("room-" + string(rune('a'+i%26)) + "-" + string(rune('0'+i%10)))
		key := DeriveRoomKey([]byte("mesh"), roomID, nil)
		subnet := DeriveRoomSubnet(key)
		if !IsMeshIPv4(subnet.Base) {
			t.Fatalf("subnet %s outside mesh space", subnet.Base)
		}
		for _, lan := range lanPrefixes {
			if lan.Contains(subnet.Base) {
				t.Fatalf("subnet %s for %s collides with LAN range %s", subnet.Base, roomID, lan)
			}
		}
	}
}

// TestNodeHostOctetInUsableRange ensures derived addresses avoid the network
// (.0) and broadcast (.255) addresses of the room's /24.
func TestNodeHostOctetInUsableRange(t *testing.T) {
	key := DeriveRoomKey([]byte("mesh"), "room", nil)
	for i := 0; i < 500; i++ {
		nodeID := NodeID("node-" + string(rune('a'+i%26)) + string(rune('0'+i%10)))
		addr := DeriveNodeIPv4(nodeID, key)
		host := addr.As4()[3]
		if host == 0 || host == 255 {
			t.Fatalf("node %s got unusable host octet %d (addr %s)", nodeID, host, addr)
		}
	}
}
