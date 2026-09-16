package types

import "time"

// RoomID is a unique room identifier (same character rules as NodeID).
type RoomID string

// Room represents an isolation unit: only members of the same room can
// discover each other's IPv6 addresses and establish P2P tunnels.
type Room struct {
	ID         RoomID    `json:"id" db:"id"`
	Name       string    `json:"name" db:"name"`
	OwnerID    NodeID    `json:"owner_id" db:"owner_id"`
	Encrypted  bool      `json:"encrypted" db:"encrypted"`
	MaxMembers int       `json:"max_members" db:"max_members"`
	CreatedAt  time.Time `json:"created_at" db:"created_at"`
}

// RoomMember is a node currently belonging to a room.
type RoomMember struct {
	RoomID   RoomID    `json:"room_id" db:"room_id"`
	NodeID   NodeID    `json:"node_id" db:"node_id"`
	JoinedAt time.Time `json:"joined_at" db:"joined_at"`
}

// RoomOptions controls room creation parameters.
type RoomOptions struct {
	Name       string
	Encrypted  bool
	MaxMembers int
}
