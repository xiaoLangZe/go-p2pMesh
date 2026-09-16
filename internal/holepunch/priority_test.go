package holepunch

import (
	"testing"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

func peer(id string, room types.RoomID, joined time.Time) PeerInfo {
	return PeerInfo{NodeID: id, RoomID: room, JoinedAt: joined}
}

// TestRuleR1_SameRoomFirst enforces rule R1: same-room candidates must be
// ordered ahead of different-room candidates regardless of join time.
func TestRuleR1_SameRoomFirst(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const room = types.RoomID("room-a")

	// Different-room peers joined earlier; they must still sort after in-room
	// peers, because favouring them would spend punch budget on addresses that
	// invariant I7 makes unreachable.
	candidates := []PeerInfo{
		peer("other-oldest", "room-b", base),
		peer("same-newest", room, base.Add(10*time.Hour)),
		peer("other-middle", "room-c", base.Add(time.Hour)),
		peer("same-oldest", room, base.Add(time.Minute)),
	}

	got := SelectPeers(candidates, room, 0)

	wantOrder := []string{"same-oldest", "same-newest", "other-oldest", "other-middle"}
	for i, want := range wantOrder {
		if got[i].NodeID != want {
			t.Errorf("position %d = %q, want %q (order: %v)",
				i, got[i].NodeID, want, ids(got))
		}
	}
}

// TestRuleR1_DeterministicTieBreak checks ordering does not depend on the input
// order, so two nodes given the same candidates always agree.
func TestRuleR1_DeterministicTieBreak(t *testing.T) {
	same := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const room = types.RoomID("r")

	forward := []PeerInfo{
		peer("bbb", room, same),
		peer("aaa", room, same),
		peer("ccc", room, same),
	}
	// Same set, reversed input order.
	reversed := []PeerInfo{
		peer("ccc", room, same),
		peer("aaa", room, same),
		peer("bbb", room, same),
	}

	a := SelectPeers(forward, room, 0)
	b := SelectPeers(reversed, room, 0)
	for i := range a {
		if a[i].NodeID != b[i].NodeID {
			t.Fatalf("ordering depends on input order at %d: %q vs %q", i, a[i].NodeID, b[i].NodeID)
		}
	}
	// Equal join times fall back to NodeID ascending.
	if want := []string{"aaa", "bbb", "ccc"}; !equalIDs(a, want) {
		t.Errorf("tie-break order = %v, want %v", ids(a), want)
	}
}

// TestRuleR1_OutOfRoomCap verifies the cap actually limits out-of-room
// candidates while never dropping in-room ones.
func TestRuleR1_OutOfRoomCap(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const room = types.RoomID("r")

	candidates := []PeerInfo{
		peer("same-1", room, base),
		peer("same-2", room, base.Add(time.Minute)),
		peer("other-1", "x", base),
		peer("other-2", "y", base),
		peer("other-3", "z", base),
	}

	got := SelectPeers(candidates, room, 1)
	sameCount, otherCount := 0, 0
	for _, p := range got {
		if p.RoomID == room {
			sameCount++
		} else {
			otherCount++
		}
	}
	if sameCount != 2 {
		t.Errorf("in-room candidates must never be dropped: got %d, want 2", sameCount)
	}
	if otherCount != 1 {
		t.Errorf("out-of-room cap not applied: got %d, want 1", otherCount)
	}
}

// TestRuleR1_EmptyRoomPrefersNoOne checks that with no room context the ordering
// degrades to join time rather than arbitrarily claiming everyone is same-room.
func TestRuleR1_EmptyRoomPrefersNoOne(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	candidates := []PeerInfo{
		peer("late", "r", base.Add(time.Hour)),
		peer("early", "r", base),
	}
	got := SelectPeers(candidates, "", 0)
	if want := []string{"early", "late"}; !equalIDs(got, want) {
		t.Errorf("empty-room order = %v, want %v", ids(got), want)
	}
}

// TestPartitionByRoom verifies the split used for separate success metrics.
func TestPartitionByRoom(t *testing.T) {
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	const room = types.RoomID("r")

	same, other := PartitionByRoom([]PeerInfo{
		peer("in-1", room, base),
		peer("out-1", "s", base),
		peer("in-2", room, base.Add(time.Minute)),
	}, room)

	if len(same) != 2 || len(other) != 1 {
		t.Fatalf("partition sizes = (%d, %d), want (2, 1)", len(same), len(other))
	}
	if same[0].NodeID != "in-1" || same[1].NodeID != "in-2" {
		t.Errorf("in-room slice not ordered by join time: %v", ids(same))
	}
}

// TestShouldAttemptOutOfRoom verifies the gate that keeps out-of-room work from
// starting while in-room demand is unmet.
func TestShouldAttemptOutOfRoom(t *testing.T) {
	cases := []struct {
		established, target int
		want                bool
	}{
		{0, 5, false}, // nothing in-room yet
		{4, 5, false}, // still short of target
		{5, 5, true},  // target met
		{6, 5, true},  // exceeded
		{0, 0, true},  // no target configured: nothing to wait for
	}
	for _, c := range cases {
		if got := ShouldAttemptOutOfRoom(c.established, c.target); got != c.want {
			t.Errorf("ShouldAttemptOutOfRoom(%d, %d) = %v, want %v",
				c.established, c.target, got, c.want)
		}
	}
}

// TestPunchStatsKeepsGroupsSeparate guards the requirement that out-of-room
// attempts are not averaged into same-room success, which would let an I7
// failure hide.
func TestPunchStatsKeepsGroupsSeparate(t *testing.T) {
	s := PunchStats{
		SameRoomAttempted:  10,
		SameRoomSucceeded:  9,
		OtherRoomAttempted: 90,
		OtherRoomSucceeded: 0,
	}
	if got := s.SuccessRate(); got != 0.9 {
		t.Errorf("same-room success rate = %v, want 0.9", got)
	}
	// 90/100 attempts left the room: visible rather than diluted.
	if got := s.OtherRoomAttemptRate(); got != 0.9 {
		t.Errorf("out-of-room attempt rate = %v, want 0.9", got)
	}
}

func ids(peers []PeerInfo) []string {
	out := make([]string, len(peers))
	for i, p := range peers {
		out[i] = p.NodeID
	}
	return out
}

func equalIDs(peers []PeerInfo, want []string) bool {
	got := ids(peers)
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
