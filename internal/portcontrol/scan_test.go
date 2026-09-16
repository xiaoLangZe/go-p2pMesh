package portcontrol

import (
	"testing"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// TestDecideSameRoomDefault checks that a rule with empty AllowedRooms
// admits same-room sources and refuses out-of-room ones.
func TestDecideSameRoomDefault(t *testing.T) {
	c := NewController(PolicyDeny)
	c.AddRule(&PortRule{
		ID: "r", Protocol: "tcp", LocalPort: 22, VirtualPort: 60022, Enabled: true,
	})

	same := Source{SameRoom: true, Room: "room-a", Addr: "fd00:1::1"}
	other := Source{SameRoom: false, Room: "room-b", Addr: "fd00:1::2"}

	if got := c.Decide(60022, same); got != DecisionAllow {
		t.Errorf("same-room source: got %v, want Allow", got)
	}
	if got := c.Decide(60022, other); got != DecisionDropNotAllowed {
		t.Errorf("out-of-room source: got %v, want DropNotAllowed", got)
	}
}

// TestDecideExplicitRooms checks an explicit AllowedRooms list.
func TestDecideExplicitRooms(t *testing.T) {
	c := NewController(PolicyDeny)
	c.AddRule(&PortRule{
		ID: "r", Protocol: "tcp", LocalPort: 22, VirtualPort: 60022, Enabled: true,
		AllowedRooms: []types.RoomID{"room-a", "room-c"},
	})

	if got := c.Decide(60022, Source{Room: "room-a"}); got != DecisionAllow {
		t.Errorf("room-a: got %v, want Allow", got)
	}
	if got := c.Decide(60022, Source{Room: "room-c"}); got != DecisionAllow {
		t.Errorf("room-c: got %v, want Allow", got)
	}
	// A same-room flag is irrelevant when the list is explicit and the room
	// is not in it.
	if got := c.Decide(60022, Source{Room: "room-b", SameRoom: true}); got != DecisionDropNotAllowed {
		t.Errorf("room-b: got %v, want DropNotAllowed", got)
	}
}

// TestDecideUnconfigured checks the probe case for the scanner's benefit.
func TestDecideUnconfigured(t *testing.T) {
	c := NewController(PolicyDeny)
	if got := c.Decide(59999, Source{SameRoom: true}); got != DecisionDropUnconfigured {
		t.Errorf("unconfigured: got %v, want DropUnconfigured", got)
	}
}

// TestAllowedRoomsEncodeDecode checks the storage JSON round-trip.
func TestAllowedRoomsEncodeDecode(t *testing.T) {
	rooms := []types.RoomID{"room-a", "room-b2"}
	enc := encodeAllowedRooms(rooms)
	if enc == "" {
		t.Fatal("encode produced empty string")
	}
	dec := decodeAllowedRooms(enc)
	if len(dec) != 2 || dec[0] != "room-a" || dec[1] != "room-b2" {
		t.Errorf("round-trip mismatch: %v", dec)
	}
	// Empty list encodes as the storage default and decodes as nil.
	if encodeAllowedRooms(nil) != "" {
		t.Error("nil list must encode as empty string")
	}
	if decodeAllowedRooms("") != nil {
		t.Error("empty storage value must decode as nil (same-room default)")
	}
	// Malformed storage must fall back to the stricter default, not crash.
	if decodeAllowedRooms("not-json") != nil {
		t.Error("malformed storage must decode as nil")
	}
}

// TestScannerSameRoomExempt checks §8.1.1 豁免.
func TestScannerSameRoomExempt(t *testing.T) {
	s := NewScanner()
	for i := 0; i < 500; i++ {
		if d := s.Probe("fd00:1::9", i, true); d != ProbeExempt {
			t.Fatalf("same-room probe %d: got %v, want exempt", i, d)
		}
	}
	if s.BlacklistSecondsLeft("fd00:1::9") > 0 {
		t.Error("same-room source must never be blacklisted")
	}
}

// TestScannerRateLimit checks layer 2: anomalous rates leave the
// blacklist untouched but get rate-limited instead of recorded.
//
// All probes hit the *same* port so the distinct-port anomaly threshold is
// never in play — this test isolates the token bucket.
func TestScannerRateLimit(t *testing.T) {
	s := NewScanner()
	clock := time.Unix(1000000, 0)
	s.now = func() time.Time { return clock }

	recorded := 0
	limited := 0
	// Burst 20 then one token per 100ms (10/s): 200 instant probes on the
	// same port overflow the bucket without tripping anything else.
	for i := 0; i < 200; i++ {
		switch s.Probe("fd00:2::1", 9000, false) {
		case ProbeRecorded:
			recorded++
		case ProbeRateLimited:
			limited++
		default:
			t.Fatalf("unexpected disposition for rate test")
		}
	}
	if recorded == 0 || limited == 0 {
		t.Errorf("recorded=%d limited=%d, want both non-zero", recorded, limited)
	}
	if recorded > s.burst {
		t.Errorf("recorded=%d exceeds burst %d", recorded, s.burst)
	}
	// Same-port flooding must never blacklist.
	if s.BlacklistSecondsLeft("fd00:2::1") > 0 {
		t.Error("same-port flooding must not blacklist the source")
	}
}

// TestScannerAnomalyBlacklist checks layer 3: 100+ distinct unconfigured
// ports inside the window blacklists the source and fires the report.
func TestScannerAnomalyBlacklist(t *testing.T) {
	s := NewScanner()
	clock := time.Unix(1000000, 0)
	s.now = func() time.Time { return clock }
	var reported bool
	var reportedPorts int
	s.OnAnomaly = func(src string, ports int) {
		reported = true
		reportedPorts = ports
	}

	// 200ms per probe keeps the token bucket topped up (10/s) while the
	// whole 120-probe sequence stays inside the 60s window.
	for i := 0; i < 120; i++ {
		clock = clock.Add(200 * time.Millisecond)
		d := s.Probe("fd00:3::1", 2000+i, false)
		if i < s.threshold-1 {
			if d != ProbeRecorded {
				t.Fatalf("probe %d: got %v, want recorded", i, d)
			}
			continue
		}
		// The 100th distinct port crosses the threshold → blacklist now.
		if d != ProbeBlacklisted {
			t.Fatalf("probe %d: got %v, want blacklisted", i, d)
		}
		break
	}
	if !reported {
		t.Error("OnAnomaly not fired")
	}
	if reportedPorts < s.threshold {
		t.Errorf("reported distinct ports = %d, want >= %d", reportedPorts, s.threshold)
	}
	if s.BlacklistSecondsLeft("fd00:3::1") <= 0 {
		t.Error("source should be blacklisted")
	}
	// Further probes during the blacklist stay blacklisted.
	if d := s.Probe("fd00:3::1", 3000, false); d != ProbeBlacklisted {
		t.Errorf("during blacklist: got %v, want blacklisted", d)
	}
}

// TestScannerBlacklistExpiry checks the 5-minute clock.
func TestScannerBlacklistExpiry(t *testing.T) {
	s := NewScanner()
	clock := time.Unix(1000000, 0)
	s.now = func() time.Time { return clock }

	// Cross the threshold to blacklist.
	for i := 0; i < s.threshold; i++ {
		s.Probe("fd00:4::1", 4000+i, false)
	}
	if d := s.Probe("fd00:4::1", 4100, false); d != ProbeBlacklisted {
		t.Fatalf("expected blacklist, got %v", d)
	}

	// Advance past 5 minutes.
	clock = clock.Add(s.blacklistFor + time.Second)
	if d := s.Probe("fd00:4::1", 4200, false); d == ProbeBlacklisted {
		t.Error("blacklist should expire after 5 minutes")
	}
}

// TestScannerPrunesWindow checks that a slow trickle does not accumulate
// to the threshold (§8.4: 拉黑门槛要宽).
func TestScannerPrunesWindow(t *testing.T) {
	s := NewScanner()
	clock := time.Unix(1000000, 0)
	s.now = func() time.Time { return clock }

	// One probe per 2 seconds: 100 probes take 200s, well beyond the 60s
	// window, so the distinct count inside the window stays under threshold.
	for i := 0; i < 150; i++ {
		d := s.Probe("fd00:5::1", 5000+i, false)
		if d == ProbeBlacklisted {
			t.Fatalf("slow trickle must not blacklist (probe %d)", i)
		}
		clock = clock.Add(2 * time.Second)
	}
}