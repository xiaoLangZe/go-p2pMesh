package portcontrol

import (
	"context"
	"io"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/internal/storage"
)

// TestForwarderDefaultDeny checks that an unconfigured virtual port
// fails loudly through DialVirtual.
func TestForwarderDefaultDeny(t *testing.T) {
	c := NewController(PolicyDeny)
	f := NewForwarder(c)

	if _, err := f.DialVirtual(60022, "tcp", Source{SameRoom: true, Addr: "fd00:1::1"}); err == nil {
		t.Fatal("expected error for unconfigured virtual port (default deny)")
	}
}

// TestForwarderProtocolMismatch checks tcp/udp mismatch rejection.
func TestForwarderProtocolMismatch(t *testing.T) {
	c := NewController(PolicyDeny)
	f := NewForwarder(c)
	c.AddRule(&PortRule{
		ID:          "r1",
		Protocol:    "tcp",
		LocalPort:   22,
		VirtualPort: 60022,
		Enabled:     true,
	})
	if _, err := f.DialVirtual(60022, "udp", Source{SameRoom: true, Addr: "fd00:1::1"}); err == nil {
		t.Error("expected protocol mismatch error for udp on a tcp rule")
	}
}

// TestForwarderDisabledRule checks a disabled rule behaves as absent.
func TestForwarderDisabledRule(t *testing.T) {
	c := NewController(PolicyDeny)
	f := NewForwarder(c)
	c.AddRule(&PortRule{
		ID:          "r1",
		Protocol:    "tcp",
		LocalPort:   22,
		VirtualPort: 60022,
		Enabled:     false,
	})
	if _, err := f.DialVirtual(60022, "tcp", Source{SameRoom: true, Addr: "fd00:1::1"}); err == nil {
		t.Error("expected error for disabled rule")
	}
}

// TestForwarderRoutesToLocal wires a fake local service and checks that
// DialVirtual reaches it through the mapping.
func TestForwarderRoutesToLocal(t *testing.T) {
	// Local TCP echo service on 127.0.0.1.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	localPort := ln.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c) // echo
			}(conn)
		}
	}()

	c := NewController(PolicyDeny)
	f := NewForwarder(c)
	c.AddRule(&PortRule{
		ID:          "echo",
		Protocol:    "tcp",
		LocalPort:   localPort,
		VirtualPort: 60022,
		Enabled:     true,
	})

	conn, err := f.DialVirtual(60022, "tcp", Source{SameRoom: true, Addr: "fd00:1::1"})
	if err != nil {
		t.Fatalf("DialVirtual: %v", err)
	}
	defer conn.Close()

	payload := []byte("hello through the mapping")
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(buf) != string(payload) {
		t.Errorf("echo mismatch: got %q, want %q", buf, payload)
	}
}

// TestSelfCheckAllowGate checks the confirmation gate: a default-allow
// policy without explicit confirmation must refuse startup.
func TestSelfCheckAllowGate(t *testing.T) {
	c := NewController(PolicyAllow)
	if err := c.SelfCheck(StartupOptions{AllowConfirmed: false}, nil); err == nil {
		t.Fatal("expected refusal for default_policy=allow without confirmation")
	}
	if err := c.SelfCheck(StartupOptions{AllowConfirmed: true}, nil); err != nil {
		t.Errorf("confirmed allow should pass, got %v", err)
	}
}

// TestSelfCheckRulesFileMissing checks the rules-file readability gate.
func TestSelfCheckRulesFileMissing(t *testing.T) {
	c := NewController(PolicyDeny)
	err := c.SelfCheck(StartupOptions{RulesFile: "/nonexistent/rules.db", AllowConfirmed: true}, nil)
	if err == nil {
		t.Fatal("expected error for missing rules file")
	}
}

// TestSelfCheckSubnetCollision checks the mesh/LAN overlap gate.
func TestSelfCheckSubnetCollision(t *testing.T) {
	c := NewController(PolicyDeny)
	local := func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil
	}
	err := c.SelfCheck(StartupOptions{MeshCIDR: "192.168.1.0/24", AllowConfirmed: true}, local)
	if err == nil {
		t.Fatal("expected collision error for overlapping mesh/LAN subnet")
	}

	localOK := func() ([]netip.Prefix, error) {
		return []netip.Prefix{netip.MustParsePrefix("192.168.10.0/24")}, nil
	}
	if err := c.SelfCheck(StartupOptions{MeshCIDR: "240.0.1.0/24", AllowConfirmed: true}, localOK); err != nil {
		t.Errorf("disjoint subnet should pass, got %v", err)
	}
}

// TestRulePersistenceRoundTrip checks save/load through the store.
func TestRulePersistenceRoundTrip(t *testing.T) {
	ctx := context.Background()
	store := newMemRuleStore()
	p := NewRulePersistence(store, "client-1")

	rules := []*PortRule{
		{ID: "a", Protocol: "tcp", LocalPort: 22, VirtualPort: 60022, Enabled: true},
		{ID: "b", Protocol: "udp", LocalPort: 53, VirtualPort: 60053, Enabled: true},
	}
	for _, r := range rules {
		if err := p.SaveRule(ctx, r); err != nil {
			t.Fatalf("SaveRule: %v", err)
		}
	}

	loaded, err := p.LoadRules(ctx)
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("loaded %d rules, want 2", len(loaded))
	}
	byVirtual := make(map[int]*PortRule)
	for _, r := range loaded {
		byVirtual[r.VirtualPort] = r
	}
	if r, ok := byVirtual[60022]; !ok || r.LocalPort != 22 {
		t.Errorf("rule 60022 not correctly loaded: %+v", r)
	}
	if r, ok := byVirtual[60053]; !ok || r.Protocol != "udp" {
		t.Errorf("rule 60053 not correctly loaded: %+v", r)
	}
}

// TestAddRulePersistedRefusesInvald checks validation happens before the
// store is touched (no half-applied rules).
func TestAddRulePersistedRefusesInvalid(t *testing.T) {
	ctx := context.Background()
	c := NewController(PolicyDeny)
	store := newMemRuleStore()
	p := NewRulePersistence(store, "client-1")

	if err := c.AddRulePersisted(ctx, p, &PortRule{ID: "bad", Protocol: "tcp", LocalPort: 0, VirtualPort: 60022}); err == nil {
		t.Error("invalid rule must be refused")
	}
	if n := len(store.rules); n != 0 {
		t.Errorf("store has %d rules, want 0 (nothing persisted on failure)", n)
	}
}

// TestAddRulePersistedRoundTrip checks the persisted+register path.
func TestAddRulePersistedRoundTrip(t *testing.T) {
	ctx := context.Background()
	c := NewController(PolicyDeny)
	store := newMemRuleStore()
	p := NewRulePersistence(store, "client-1")

	if err := c.AddRulePersisted(ctx, p, &PortRule{ID: "r", Protocol: "tcp", LocalPort: 22, VirtualPort: 60022, Enabled: true}); err != nil {
		t.Fatalf("AddRulePersisted: %v", err)
	}
	if !c.IsAllowed(60022) {
		t.Error("persisted rule not live in registry")
	}
	if len(store.rules) != 1 {
		t.Errorf("store has %d rules, want 1", len(store.rules))
	}

	// Reload into a fresh controller.
	c2 := NewController(PolicyDeny)
	if err := c2.LoadPersisted(ctx, p); err != nil {
		t.Fatalf("LoadPersisted: %v", err)
	}
	if !c2.IsAllowed(60022) {
		t.Error("loaded rule not live in fresh controller")
	}
}

// TestValidateRule checks the registry guards.
func TestValidateRule(t *testing.T) {
	if validateRule(nil) == nil {
		t.Error("nil rule must fail")
	}
	if validateRule(&PortRule{}) == nil {
		t.Error("zero ports must fail")
	}
	if validateRule(&PortRule{VirtualPort: 1, LocalPort: 1, Protocol: "sctp"}) == nil {
		t.Error("sctp must fail (only tcp/udp allowed)")
	}
	if validateRule(&PortRule{VirtualPort: 1, LocalPort: 1, Protocol: "tcp"}) != nil {
		t.Error("valid rule must pass")
	}
}

// TestControllerApplyServerRules checks the sync path registers rules.
func TestControllerApplyServerRules(t *testing.T) {
	ctx := context.Background()
	c := NewController(PolicyDeny)
	rules := []storage.PortRule{
		{ID: "s1", Protocol: "tcp", LocalPort: 80, VirtualPort: 60080, Enabled: true},
	}
	n, err := c.ApplyServerRules(ctx, rules)
	if err != nil {
		t.Fatalf("ApplyServerRules: %v", err)
	}
	if n != 1 {
		t.Errorf("applied %d rules, want 1", n)
	}
	if !c.IsAllowed(60080) {
		t.Error("synced rule should be allowed")
	}
	if c.IsAllowed(60081) {
		t.Error("unsynced port must remain denied")
	}
}

// testStore is an in-memory PortRuleStore for tests.
type testStore struct {
	mu    sync.Mutex
	rules map[string]*storage.PortRule
}

func newMemRuleStore() *testStore {
	return &testStore{rules: make(map[string]*storage.PortRule)}
}

func (s *testStore) SetPortRule(ctx context.Context, r *storage.PortRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *r
	s.rules[r.ID] = &cp
	return nil
}
func (s *testStore) GetPortRules(ctx context.Context, nodeID string) ([]*storage.PortRule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*storage.PortRule, 0, len(s.rules))
	for _, r := range s.rules {
		cp := *r
		out = append(out, &cp)
	}
	return out, nil
}
func (s *testStore) DeletePortRule(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.rules, id)
	return nil
}
