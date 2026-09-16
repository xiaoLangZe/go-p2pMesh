package room

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/xiaoLangZe/go-p2pmesh/internal/storage"
	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// memStore is an in-memory storage.Store for tests. It implements the
// Store interface with maps.
type memStore struct {
	rooms   map[types.RoomID]*types.Room
	members map[types.RoomID]map[types.NodeID]bool
	nodes   map[types.NodeID]*storage.Node
}

func newMemStore() *memStore {
	return &memStore{
		rooms:   make(map[types.RoomID]*types.Room),
		members: make(map[types.RoomID]map[types.NodeID]bool),
		nodes:   make(map[types.NodeID]*storage.Node),
	}
}

func (s *memStore) RegisterNode(ctx context.Context, n *storage.Node) error {
	s.nodes[n.ID] = n
	return nil
}
func (s *memStore) GetNode(ctx context.Context, id string) (*storage.Node, error) {
	n, ok := s.nodes[types.NodeID(id)]
	if !ok {
		return nil, errors.New("not found")
	}
	return n, nil
}
func (s *memStore) ListNodes(ctx context.Context, f storage.NodeFilter) ([]*storage.Node, error) {
	out := make([]*storage.Node, 0, len(s.nodes))
	for _, n := range s.nodes {
		out = append(out, n)
	}
	return out, nil
}
func (s *memStore) UpdateNodeStatus(ctx context.Context, id string, status storage.NodeStatus) error {
	if n, ok := s.nodes[types.NodeID(id)]; ok {
		n.Status = status
		return nil
	}
	return errors.New("not found")
}
func (s *memStore) DeleteNode(ctx context.Context, id string) error {
	delete(s.nodes, types.NodeID(id))
	return nil
}
func (s *memStore) UnbindNodeID(ctx context.Context, id string) error { return nil }

func (s *memStore) CreateRoom(ctx context.Context, r *types.Room) error {
	s.rooms[r.ID] = r
	return nil
}
func (s *memStore) GetRoom(ctx context.Context, id string) (*types.Room, error) {
	r, ok := s.rooms[types.RoomID(id)]
	if !ok {
		return nil, errors.New("room not found")
	}
	return r, nil
}
func (s *memStore) ListRooms(ctx context.Context) ([]*types.Room, error) {
	out := make([]*types.Room, 0, len(s.rooms))
	for _, r := range s.rooms {
		out = append(out, r)
	}
	return out, nil
}
func (s *memStore) AddRoomMember(ctx context.Context, roomID, nodeID string) error {
	rid := types.RoomID(roomID)
	if _, ok := s.rooms[rid]; !ok {
		return errors.New("room not found")
	}
	if s.members[rid] == nil {
		s.members[rid] = make(map[types.NodeID]bool)
	}
	s.members[rid][types.NodeID(nodeID)] = true
	return nil
}
func (s *memStore) RemoveRoomMember(ctx context.Context, roomID, nodeID string) error {
	rid := types.RoomID(roomID)
	if s.members[rid] != nil {
		delete(s.members[rid], types.NodeID(nodeID))
	}
	return nil
}
func (s *memStore) ListRoomMembers(ctx context.Context, roomID string) ([]*storage.Node, error) {
	set := s.members[types.RoomID(roomID)]
	out := make([]*storage.Node, 0, len(set))
	for id := range set {
		if n, ok := s.nodes[id]; ok {
			out = append(out, n)
		}
	}
	return out, nil
}
func (s *memStore) SetPortRule(ctx context.Context, rule *storage.PortRule) error { return nil }
func (s *memStore) GetPortRules(ctx context.Context, nodeID string) ([]*storage.PortRule, error) {
	return nil, nil
}
func (s *memStore) DeletePortRule(ctx context.Context, ruleID string) error { return nil }
func (s *memStore) CreateAPIUser(ctx context.Context, u *storage.APIUser) error {
	return nil
}
func (s *memStore) GetAPIUser(ctx context.Context, username string) (*storage.APIUser, error) {
	return nil, errors.New("not found")
}
func (s *memStore) RevokeAPIToken(ctx context.Context, tokenID string) error { return nil }
func (s *memStore) Close() error                                            { return nil }

// TestCreateRoom checks room creation.
func TestCreateRoom(t *testing.T) {
	m := NewManager(newMemStore())
	ctx := context.Background()
	r, err := m.CreateRoom(ctx, "Test-Room", "owner-1", types.RoomOptions{})
	if err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}
	if r.ID == "" {
		t.Error("room ID is empty")
	}
	if r.OwnerID != "owner-1" {
		t.Errorf("owner = %s, want owner-1", r.OwnerID)
	}
	if r.MaxMembers != 100 {
		t.Errorf("default max members = %d, want 100", r.MaxMembers)
	}
}

// TestCreateRoomRejectsEmpty checks empty names/owners fail loudly.
func TestCreateRoomRejectsEmpty(t *testing.T) {
	m := NewManager(newMemStore())
	ctx := context.Background()
	if _, err := m.CreateRoom(ctx, "", "o", types.RoomOptions{}); err == nil {
		t.Error("empty name should fail")
	}
	if _, err := m.CreateRoom(ctx, "room", "", types.RoomOptions{}); err == nil {
		t.Error("empty owner should fail")
	}
}

// TestJoinAndLeave checks membership lifecycle.
func TestJoinAndLeave(t *testing.T) {
	ctx := context.Background()
	ms := newMemStore()
	// register nodes
	ms.RegisterNode(ctx, &storage.Node{ID: types.NodeID("n1"), Status: storage.NodeStatusOnline})
	ms.RegisterNode(ctx, &storage.Node{ID: types.NodeID("n2"), Status: storage.NodeStatusOnline})

	m := NewManager(ms)
	room, err := m.CreateRoom(ctx, "room-a", "n1", types.RoomOptions{})
	if err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}

	if err := m.JoinRoom(ctx, string(room.ID), "n1", ""); err != nil {
		t.Fatalf("JoinRoom n1: %v", err)
	}
	if err := m.JoinRoom(ctx, string(room.ID), "n2", ""); err != nil {
		t.Fatalf("JoinRoom n2: %v", err)
	}

	members, err := m.GetMembers(ctx, room.ID, 0, 0)
	if err != nil {
		t.Fatalf("GetMembers: %v", err)
	}
	if members.Total != 2 {
		t.Errorf("total = %d, want 2", members.Total)
	}

	if err := m.LeaveRoom(ctx, string(room.ID), "n1"); err != nil {
		t.Fatalf("LeaveRoom: %v", err)
	}
	members, _ = m.GetMembers(ctx, room.ID, 0, 0)
	if members.Total != 1 {
		t.Errorf("after leave, total = %d, want 1", members.Total)
	}
}

// TestJoinRoomRequiresPassword checks encrypted rooms.
func TestJoinRoomRequiresPassword(t *testing.T) {
	ctx := context.Background()
	m := NewManager(newMemStore())
	room, err := m.CreateRoom(ctx, "sec-room", "owner", types.RoomOptions{Encrypted: true})
	if err != nil {
		t.Fatalf("CreateRoom: %v", err)
	}
	if err := m.JoinRoom(ctx, string(room.ID), "n1", ""); err == nil {
		t.Error("joining an encrypted room without a password should fail")
	}
	if err := m.JoinRoom(ctx, string(room.ID), "n1", "secret"); err != nil {
		t.Errorf("joining with a password should succeed, got %v", err)
	}
}

// TestGetMembersPagination checks I1: pagination works.
func TestGetMembersPagination(t *testing.T) {
	ctx := context.Background()
	ms := newMemStore()
	for i := 0; i < 120; i++ {
		ms.RegisterNode(ctx, &storage.Node{
			ID:     types.NodeID(fmt.Sprintf("node-%03d", i)),
			Status: storage.NodeStatusOnline,
		})
	}
	m := NewManager(ms)
	room, _ := m.CreateRoom(ctx, "big", "node-000", types.RoomOptions{})
	for i := 0; i < 120; i++ {
		m.JoinRoom(ctx, string(room.ID), fmt.Sprintf("node-%03d", i), "")
	}

	// First page.
	p1, err := m.GetMembers(ctx, room.ID, 0, 50)
	if err != nil {
		t.Fatalf("GetMembers p1: %v", err)
	}
	if p1.Total != 120 {
		t.Errorf("total = %d, want 120", p1.Total)
	}
	if len(p1.Members) != 50 {
		t.Errorf("page 1 size = %d, want 50", len(p1.Members))
	}
	if !p1.HasMore {
		t.Error("page 1 should have more")
	}

	// Second page.
	p2, err := m.GetMembers(ctx, room.ID, 50, 50)
	if err != nil {
		t.Fatalf("GetMembers p2: %v", err)
	}
	if len(p2.Members) != 50 {
		t.Errorf("page 2 size = %d, want 50", len(p2.Members))
	}
	if !p2.HasMore {
		t.Error("page 2 should have more")
	}

	// Last page.
	p3, err := m.GetMembers(ctx, room.ID, 100, 50)
	if err != nil {
		t.Fatalf("GetMembers p3: %v", err)
	}
	if len(p3.Members) != 20 {
		t.Errorf("page 3 size = %d, want 20", len(p3.Members))
	}
	if p3.HasMore {
		t.Error("page 3 should not have more")
	}
}

// TestCrossRoomIsolation checks that member lists are room-scoped: a member
// list for room A never contains room B's members (I7 at the listing layer).
func TestCrossRoomIsolation(t *testing.T) {
	ctx := context.Background()
	ms := newMemStore()
	ms.RegisterNode(ctx, &storage.Node{ID: types.NodeID("a1"), Status: storage.NodeStatusOnline})
	ms.RegisterNode(ctx, &storage.Node{ID: types.NodeID("b1"), Status: storage.NodeStatusOnline})

	m := NewManager(ms)
	roomA, _ := m.CreateRoom(ctx, "room-a", "a1", types.RoomOptions{})
	roomB, _ := m.CreateRoom(ctx, "room-b", "b1", types.RoomOptions{})

	m.JoinRoom(ctx, string(roomA.ID), "a1", "")
	m.JoinRoom(ctx, string(roomB.ID), "b1", "")

	membersA, _ := m.GetMembers(ctx, roomA.ID, 0, 0)
	membersB, _ := m.GetMembers(ctx, roomB.ID, 0, 0)

	for _, mem := range membersA.Members {
		if mem.NodeID == "b1" {
			t.Error("room A member list contains room B member")
		}
	}
	for _, mem := range membersB.Members {
		if mem.NodeID == "a1" {
			t.Error("room B member list contains room A member")
		}
	}
}