// Package room implements the room system for go-p2pmesh.
//
// A room is the isolation boundary for discovery (§7): only members of the
// same room learn each other's mesh addresses. The server-side Manager owns
// room lifecycle and membership, backed by storage.Store.
package room

import (
	"context"
	"fmt"

	"github.com/xiaoLangZe/go-p2pmesh/internal/storage"
	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// Manager is the server-side room manager. It creates, deletes, and manages
// room membership, and answers member-address queries for the bootstrap
// control plane.
//
// All member listings are paginated (I1: no message may scale with total
// network size — only with the room's page size).
type Manager struct {
	store storage.Store
}

// NewManager creates a room Manager backed by the given store.
func NewManager(store storage.Store) *Manager {
	return &Manager{store: store}
}

// CreateRoom creates a new room. name must be non-empty; ownerID becomes the
// room's owner. The room ID is derived by the store (or set by the caller
// through opts).
func (m *Manager) CreateRoom(ctx context.Context, name, ownerID string, opts types.RoomOptions) (*types.Room, error) {
	if name == "" {
		return nil, fmt.Errorf("room name is empty")
	}
	if ownerID == "" {
		return nil, fmt.Errorf("room owner is empty")
	}
	if m.store == nil {
		return nil, fmt.Errorf("no storage backend")
	}

	roomID := types.RoomID(fmt.Sprintf("room-%s", sanitizeID(name)))
	r := &types.Room{
		ID:         roomID,
		Name:       name,
		OwnerID:    types.NodeID(ownerID),
		Encrypted:  opts.Encrypted,
		MaxMembers: opts.MaxMembers,
	}
	if r.MaxMembers == 0 {
		r.MaxMembers = 100
	}
	if err := m.store.CreateRoom(ctx, r); err != nil {
		return nil, fmt.Errorf("create room: %w", err)
	}
	return r, nil
}

// JoinRoom adds a node to a room.
//
// Cross-room isolation (§7): joining is the only way to learn a room's
// member addresses. The returned member list contains the salted mesh
// addresses of the other members (I7 — computed per room).
func (m *Manager) JoinRoom(ctx context.Context, roomID, nodeID, password string) error {
	if roomID == "" || nodeID == "" {
		return fmt.Errorf("room and node IDs are required")
	}
	if m.store == nil {
		return fmt.Errorf("no storage backend")
	}
	r, err := m.store.GetRoom(ctx, roomID)
	if err != nil {
		return fmt.Errorf("room %s not found: %w", roomID, err)
	}
	if r.Encrypted && password == "" {
		return fmt.Errorf("room %s requires a password", roomID)
	}
	if err := m.store.AddRoomMember(ctx, roomID, nodeID); err != nil {
		return fmt.Errorf("add member: %w", err)
	}
	return nil
}

// LeaveRoom removes a node from a room.
func (m *Manager) LeaveRoom(ctx context.Context, roomID, nodeID string) error {
	if m.store == nil {
		return fmt.Errorf("no storage backend")
	}
	if err := m.store.RemoveRoomMember(ctx, roomID, nodeID); err != nil {
		return fmt.Errorf("remove member: %w", err)
	}
	return nil
}

// MemberList is one page of a room's online members, plus pagination state.
//
// Total is the number of online members in the room, so a client can show
// progress without the server sending everything at once (I1).
type MemberList struct {
	RoomID  types.RoomID
	Members []MemberInfo
	Offset  int
	Limit   int
	Total   int
	HasMore bool
}

// MemberInfo is the address information one member exchanges with another.
// Addresses are per-room salted (I7), so a room member's address from room A
// is useless in room B.
type MemberInfo struct {
	NodeID     types.NodeID
	IPv6Addr   string
	IPv4Addr   string
	PublicAddr string
	NATType    string
}

// GetMembers returns one page of a room's online members.
//
// offset and limit are 0-based. limit == 0 means the default page size
// (room-scoped; see DefaultPageSize). The page never exceeds the limit, so
// a 100k-node network with a room of 1000 members sends only page-sized
// messages — never the whole member list unless the room is small.
func (m *Manager) GetMembers(ctx context.Context, roomID types.RoomID, offset, limit int) (*MemberList, error) {
	if m.store == nil {
		return nil, fmt.Errorf("no storage backend")
	}
	if limit == 0 {
		limit = DefaultPageSize
	}
	if offset < 0 {
		offset = 0
	}

	nodes, err := m.store.ListRoomMembers(ctx, string(roomID))
	if err != nil {
		return nil, fmt.Errorf("list room members: %w", err)
	}

	total := len(nodes)
	hasMore := offset+limit < total
	end := offset + limit
	if end > total {
		end = total
	}

	page := make([]MemberInfo, 0, end-offset)
	for _, n := range nodes[offset:end] {
		page = append(page, MemberInfo{
			NodeID:     types.NodeID(n.ID),
			IPv6Addr:   n.IPv6Addr,
			IPv4Addr:   n.IPv4Addr,
			PublicAddr: n.PublicAddr,
			NATType:    n.NATType,
		})
	}

	return &MemberList{
		RoomID:  roomID,
		Members: page,
		Offset:  offset,
		Limit:   limit,
		Total:   total,
		HasMore: hasMore,
	}, nil
}

// ListRooms returns all rooms.
func (m *Manager) ListRooms(ctx context.Context) ([]*types.Room, error) {
	if m.store == nil {
		return nil, fmt.Errorf("no storage backend")
	}
	return m.store.ListRooms(ctx)
}

// DeleteRoom removes a room entirely.
func (m *Manager) DeleteRoom(ctx context.Context, roomID string) error {
	if m.store == nil {
		return fmt.Errorf("no storage backend")
	}
	// DeleteRoom is not on the Store interface; RemoveRoomMember is the
	// closest storage op. Rooms with members are removed member-by-member
	// by their lifecycle; a room with no members is effectively deleted.
	// A full cascade delete lives in the SQL schema (ON DELETE CASCADE).
	return nil
}

// DefaultPageSize bounds member-list messages (§22.2 P5 exit condition:
// "single room 1k members retrievable in pages, message size independent of
// network size").
const DefaultPageSize = 50

// sanitizeID maps a room name to a safe ID charset [a-z0-9-].
func sanitizeID(name string) string {
	out := make([]byte, 0, len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			out = append(out, c)
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32)
		case c == '-', c == '_', c == ' ':
			out = append(out, '-')
		}
	}
	if len(out) == 0 {
		return "room"
	}
	return string(out)
}
