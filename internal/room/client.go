package room

import (
	"fmt"
	"sync"

	"github.com/yourorg/go-p2pmesh/pkg/types"
)

var errNotImplemented = fmt.Errorf("room not implemented in current phase")

// RoomMember holds the cached info about a member of the current room.
type RoomMember struct {
	NodeID     types.NodeID
	IPv6Addr   string
	PublicAddr string
	NATType    string
}

// Client is the client-side room logic.  It tracks the current room
// membership and receives push notifications from the server.
type Client struct {
	mu         sync.RWMutex
	currentRoom string
	members    map[types.NodeID]*RoomMember
}

// NewClient creates a room Client.
func NewClient() *Client {
	return &Client{members: make(map[types.NodeID]*RoomMember)}
}

// JoinRoom sends a join request to the server.
func (c *Client) JoinRoom(roomID, password string) error {
	return errNotImplemented
}

// LeaveRoom sends a leave request.
func (c *Client) LeaveRoom() error {
	return errNotImplemented
}

// OnMemberJoin is called when the server pushes a new member.
func (c *Client) OnMemberJoin(m *RoomMember) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.members[m.NodeID] = m
}

// OnMemberLeave is called when the server pushes a member departure.
func (c *Client) OnMemberLeave(nodeID types.NodeID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.members, nodeID)
}

// OnMemberUpdate is called when a member's address changes.
func (c *Client) OnMemberUpdate(m *RoomMember) {
	c.OnMemberJoin(m) // same operation under the lock
}

// Members returns a snapshot of the current room members.
func (c *Client) Members() []*RoomMember {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*RoomMember, 0, len(c.members))
	for _, m := range c.members {
		result = append(result, m)
	}
	return result
}

// CurrentRoom returns the room ID the client is currently in.
func (c *Client) CurrentRoom() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.currentRoom
}
