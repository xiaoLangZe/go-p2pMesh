package types

import (
	"crypto/sha256"
	"encoding/binary"
	"strings"
)

// This file implements invariant I7: "跨房间不可用" — an address learned in
// room A must be useless in room B.
//
// Mechanism: every mesh address is derived from a per-room salt. The salt is
// derived from the room's key material, not from the readable room ID alone
// (D2). Without the room key an observer cannot compute a node's address in
// that room, and an address computed for one room does not resolve in another.

// DefaultRoomID is the fixed room used before the room subsystem exists.
//
// Rationale (D14): the design's phase order derives salted addresses before
// real rooms are available. Rather than defer salting (which would force
// addressing rework later), P1 salts against this fixed default room. The salt
// function already takes (roomID, roomKey), so P5 only substitutes real rooms
// without changing any signature.
const DefaultRoomID RoomID = "default"

// saltDomain separates this hash use from every other hash in the system.
const saltDomain = "gop2pmesh/addr-salt/v1"

// RoomKey is a 32-byte room secret used to salt address derivation.
type RoomKey [32]byte

// DeriveRoomKey produces the room's salt key.
//
// If explicitKey is non-empty (operator supplied room_key in config), it is
// hashed directly — this lets closed rooms pick their own secret. Otherwise the
// key is derived from the mesh secret and the room ID, so that two nodes that
// share a mesh secret agree on the key without out-of-band exchange.
//
// A meshSecret of nil is allowed and yields a well-defined (but non-secret)
// key; callers that need isolation must supply a secret.
func DeriveRoomKey(meshSecret []byte, roomID RoomID, explicitKey []byte) RoomKey {
	h := sha256.New()
	h.Write([]byte("gop2pmesh/room-key/v1"))
	if len(explicitKey) > 0 {
		h.Write([]byte{1})
		h.Write(explicitKey)
	} else {
		h.Write([]byte{0})
		h.Write(meshSecret)
	}
	h.Write([]byte(strings.ToLower(string(roomID))))
	var out RoomKey
	copy(out[:], h.Sum(nil))
	return out
}

// saltedDigest computes the room-salted digest of a node ID.
//
// Ordering matters for reproducibility across platforms: the salt is written
// first, then the labels, then the lowercased node ID. Node IDs are compared
// case-insensitively (see NodeID), so lowercasing keeps derivation stable no
// matter how an operator typed the ID.
func (k RoomKey) saltedDigest(nodeID NodeID) [32]byte {
	h := sha256.New()
	h.Write([]byte(saltDomain))
	h.Write(k[:])
	h.Write([]byte(strings.ToLower(string(nodeID))))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// saltedSubnetIndex derives the room's subnet index within the mesh IPv4 space
// from the room key. Using the key (not the readable room ID) means an observer
// cannot enumerate which subnet a room occupies without the key.
func (k RoomKey) saltedSubnetIndex() uint32 {
	h := sha256.New()
	h.Write([]byte(saltDomain))
	h.Write([]byte("subnet"))
	h.Write(k[:])
	sum := h.Sum(nil)
	// Lower 20 bits → one of 2^20 possible /24 subnets inside 240.0.0.0/4.
	return binary.BigEndian.Uint32(sum[:4]) & 0x000FFFFF
}
