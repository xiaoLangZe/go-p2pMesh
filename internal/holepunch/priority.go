package holepunch

import (
	"sort"

	"github.com/yourorg/go-p2pmesh/pkg/types"
)

// Rule R1: peers in the same room are connected first.
//
// The ordering is deterministic on purpose. If two nodes rank the same
// candidate set differently they open connections in different orders, and the
// mesh oscillates as each side's attempts race the other's.
//
//	primary:   same room before different room
//	secondary: earlier join time first
//	tertiary:  NodeID ascending (final tie-break, independent of map order)

// SelectPeers orders connection candidates according to rule R1.
//
// maxOutOfRoom caps how many different-room candidates the result may contain.
// Pass 0 to apply the default policy from the design: same-room candidates are
// never displaced by different-room ones. A positive value allows at most that
// many out-of-room candidates through, which callers use when cross-room
// coordination is genuinely needed.
func SelectPeers(candidates []PeerInfo, currentRoom types.RoomID, maxOutOfRoom int) []PeerInfo {
	ordered := make([]PeerInfo, len(candidates))
	copy(ordered, candidates)

	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := ordered[i], ordered[j]
		aSame := isSameRoom(a, currentRoom)
		bSame := isSameRoom(b, currentRoom)
		if aSame != bSame {
			return aSame
		}
		if !a.JoinedAt.Equal(b.JoinedAt) {
			return a.JoinedAt.Before(b.JoinedAt)
		}
		return a.NodeID < b.NodeID
	})

	if maxOutOfRoom <= 0 {
		return ordered
	}

	out := make([]PeerInfo, 0, len(ordered))
	outOfRoom := 0
	for _, p := range ordered {
		if !isSameRoom(p, currentRoom) {
			if outOfRoom >= maxOutOfRoom {
				continue
			}
			outOfRoom++
		}
		out = append(out, p)
	}
	return out
}

// isSameRoom reports whether a peer belongs to the current room.
//
// An empty current room means "no room context", in which case nothing is
// considered same-room — the caller has no basis to prefer anyone and the
// ordering falls back to join time and NodeID.
func isSameRoom(p PeerInfo, room types.RoomID) bool {
	return room != "" && p.RoomID == room
}

// PartitionByRoom splits candidates into same-room and different-room slices,
// each already ordered by R1.
//
// Callers that report success metrics use this rather than SelectPeers alone,
// because the design requires out-of-room attempts to be counted separately: if
// they were averaged with same-room attempts, a failure of invariant I7
// (cross-room addresses becoming usable) would hide inside a healthy overall
// success rate.
func PartitionByRoom(candidates []PeerInfo, currentRoom types.RoomID) (same, other []PeerInfo) {
	for _, p := range SelectPeers(candidates, currentRoom, 0) {
		if isSameRoom(p, currentRoom) {
			same = append(same, p)
		} else {
			other = append(other, p)
		}
	}
	return same, other
}

// ShouldAttemptOutOfRoom reports whether an out-of-room candidate may be tried,
// given how many same-room tunnels are already established and how many are
// targeted.
//
// This is the "do not start out-of-room work while in-room demand is unmet"
// constraint from the design, expressed as a single predicate so every caller
// applies it identically.
func ShouldAttemptOutOfRoom(sameRoomEstablished, sameRoomTarget int) bool {
	if sameRoomTarget <= 0 {
		return true // no same-room target configured: nothing to wait for
	}
	return sameRoomEstablished >= sameRoomTarget
}
