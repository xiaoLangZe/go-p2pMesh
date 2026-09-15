// Package room implements the room system for go-p2pmesh.
package room

import (
	"github.com/yourorg/go-p2pmesh/pkg/types"
)

// Manager is the server-side room manager.  It creates, deletes, and
// manages room membership.  In P0, all methods return ErrNotImplemented.
type Manager struct {
	// store storage.Store — will be added in P2
}

// NewManager creates a new room Manager.
func NewManager() *Manager {
	return &Manager{}
}

// CreateRoom creates a new room.
func (m *Manager) CreateRoom(name, ownerID string, opts types.RoomOptions) (*types.Room, error) {
	return nil, errNotImplemented
}

// JoinRoom adds a node to a room.
func (m *Manager) JoinRoom(roomID, nodeID, password string) error {
	return errNotImplemented
}

// LeaveRoom removes a node from a room.
func (m *Manager) LeaveRoom(roomID, nodeID string) error {
	return errNotImplemented
}

// GetMembers returns all online members of a room.
func (m *Manager) GetMembers(roomID string) ([]*types.RoomMember, error) {
	return nil, errNotImplemented
}

// ListRooms returns all rooms.
func (m *Manager) ListRooms() ([]*types.Room, error) {
	return nil, errNotImplemented
}

// DeleteRoom removes a room entirely.
func (m *Manager) DeleteRoom(roomID string) error {
	return errNotImplemented
}
