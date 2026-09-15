package storage

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/yourorg/go-p2pmesh/pkg/types"
)

// newTestStore opens a temporary SQLite store and closes it when the test ends.
func newTestStore(t *testing.T) *SQLStore {
	t.Helper()
	dsn := filepath.Join(t.TempDir(), "test.db")
	s, err := NewSQLStore("sqlite", dsn, 1, 1)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// TestInvariantI8_ConflictRejected enforces invariant I8: a NodeID already bound
// to one public key must not be silently rebound to another. Without this, a
// machine that guesses a NodeID could evict the legitimate owner.
func TestInvariantI8_ConflictRejected(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const id = "a3f9k2m8-7p1q-x4r6-9m2p-abc123"
	first := &Node{
		ID:       types.NodeID(id),
		PubKey:   []byte("key-one-aaaaaaaaaaaaaaaaaaaaaaaa"),
		IPv6Addr: "fd00:9bd8::1",
		Status:   NodeStatusOnline,
	}
	if err := s.RegisterNode(ctx, first); err != nil {
		t.Fatalf("first registration must succeed: %v", err)
	}

	// Same ID, different key: must be refused, not overwritten.
	impostor := &Node{
		ID:       types.NodeID(id),
		PubKey:   []byte("key-two-bbbbbbbbbbbbbbbbbbbbbbbb"),
		IPv6Addr: "fd00:9bd8::2",
		Status:   NodeStatusOnline,
	}
	err := s.RegisterNode(ctx, impostor)
	if !errors.Is(err, ErrNodeIDConflict) {
		t.Fatalf("expected ErrNodeIDConflict, got %v", err)
	}

	// The original binding must be untouched.
	got, err := s.GetNode(ctx, id)
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if string(got.PubKey) != string(first.PubKey) {
		t.Error("I8 violated: stored public key was overwritten by the impostor")
	}
	if got.IPv6Addr != first.IPv6Addr {
		t.Error("I8 violated: stored address was overwritten by the impostor")
	}
}

// TestRegisterNodeIdempotentForSameKey checks a legitimate node re-registering
// (restart, address change) is allowed to update its mutable fields.
func TestRegisterNodeIdempotentForSameKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	n := &Node{
		ID:       types.NodeID("a3f9k2m8-7p1q-x4r6-9m2p-abc123"),
		PubKey:   []byte("stable-key-aaaaaaaaaaaaaaaaaaaaaa"),
		IPv6Addr: "fd00:9bd8::1",
		Status:   NodeStatusOnline,
	}
	if err := s.RegisterNode(ctx, n); err != nil {
		t.Fatalf("first registration: %v", err)
	}

	// Same key, new observed address and NAT type.
	n.PublicAddr = "203.0.113.5:54321"
	n.NATType = "FullCone"
	if err := s.RegisterNode(ctx, n); err != nil {
		t.Fatalf("re-registration with the same key must succeed: %v", err)
	}

	got, err := s.GetNode(ctx, n.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if got.PublicAddr != "203.0.113.5:54321" {
		t.Errorf("mutable field not updated: got %q", got.PublicAddr)
	}
	if got.NATType != "FullCone" {
		t.Errorf("NAT type not updated: got %q", got.NATType)
	}
}

// TestUnbindNodeIDAllowsRebind covers the D5 recovery path: after an operator
// unbinds a squatted ID, the legitimate machine can register with a new key.
func TestUnbindNodeIDAllowsRebind(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	const id = "a3f9k2m8-7p1q-x4r6-9m2p-abc123"
	squatter := &Node{
		ID:     types.NodeID(id),
		PubKey: []byte("squatter-key-aaaaaaaaaaaaaaaaaaaa"),
		Status: NodeStatusOnline,
	}
	if err := s.RegisterNode(ctx, squatter); err != nil {
		t.Fatalf("squatter registration: %v", err)
	}

	// Legitimate owner cannot register while the squat stands.
	legit := &Node{
		ID:     types.NodeID(id),
		PubKey: []byte("legit-key-bbbbbbbbbbbbbbbbbbbbbbbb"),
		Status: NodeStatusOnline,
	}
	if err := s.RegisterNode(ctx, legit); !errors.Is(err, ErrNodeIDConflict) {
		t.Fatalf("expected conflict before unbind, got %v", err)
	}

	// Operator unbinds, then the legitimate key can take the ID.
	if err := s.UnbindNodeID(ctx, id); err != nil {
		t.Fatalf("unbind: %v", err)
	}
	if err := s.RegisterNode(ctx, legit); err != nil {
		t.Fatalf("registration after unbind must succeed: %v", err)
	}
	got, err := s.GetNode(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.PubKey) != string(legit.PubKey) {
		t.Error("rebind did not take effect")
	}
}

// TestUnbindNodeIDMissingReportsNotFound ensures unbinding an unknown ID is an
// error rather than a silent success, so an operator typo is visible.
func TestUnbindNodeIDMissingReportsNotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.UnbindNodeID(context.Background(), "no-such-node"); err == nil {
		t.Error("expected an error when unbinding a non-existent node")
	}
}

// TestMigrationCreatesIPv4Columns guards the idempotent ALTER TABLE path: the
// second migration must have applied and re-running it must not fail.
func TestMigrationCreatesIPv4Columns(t *testing.T) {
	dsn := filepath.Join(t.TempDir(), "twice.db")

	s1, err := NewSQLStore("sqlite", dsn, 1, 1)
	if err != nil {
		t.Fatalf("first open: %v", err)
	}
	_ = s1.Close()

	// Reopening re-runs both migrations; duplicate-column errors must be ignored.
	s2, err := NewSQLStore("sqlite", dsn, 1, 1)
	if err != nil {
		t.Fatalf("second open must tolerate already-applied migrations: %v", err)
	}
	defer s2.Close()

	n := &Node{
		ID:       types.NodeID("a3f9k2m8-7p1q-x4r6-9m2p-abc123"),
		PubKey:   []byte("k"),
		IPv4Addr: "240.1.2.3",
		Status:   NodeStatusOnline,
	}
	if err := s2.RegisterNode(context.Background(), n); err != nil {
		t.Fatalf("IPv4 column not usable after re-migration: %v", err)
	}
	got, err := s2.GetNode(context.Background(), n.ID.String())
	if err != nil {
		t.Fatal(err)
	}
	if got.IPv4Addr != "240.1.2.3" {
		t.Errorf("IPv4 address not persisted: got %q", got.IPv4Addr)
	}
}
