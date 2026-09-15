// Package storage defines the data persistence layer for go-p2pmesh.
//
// The Store interface is implemented by multiple backends:
//   - SQLStore (MySQL, PostgreSQL, SQLite) via database/sql + sqlx
//   - MongoStore (MongoDB) via the official MongoDB driver (P2)
//   - SQLiteStore (client-side, pure Go via modernc.org/sqlite)
//
// All SQL-based implementations MUST use parameter-bound queries.
// String concatenation or fmt.Sprintf for SQL construction is prohibited.
package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/yourorg/go-p2pmesh/pkg/types"
)

// NodeStatus represents the online/offline state of a node.
type NodeStatus string

const (
	NodeStatusOnline  NodeStatus = "online"
	NodeStatusOffline NodeStatus = "offline"
)

// Node is the full database record for a mesh node.
type Node struct {
	ID         types.NodeID `json:"id" db:"id"`
	PubKey     []byte       `json:"pubkey" db:"pubkey"`
	RoomID     string       `json:"room_id" db:"room_id"`
	IPv6Addr   string       `json:"ipv6_addr" db:"ipv6_addr"`
	IPv4Addr   string       `json:"ipv4_addr" db:"ipv4_addr"`
	PublicAddr string       `json:"public_addr" db:"public_addr"`
	NATType    string       `json:"nat_type" db:"nat_type"`
	Status     NodeStatus   `json:"status" db:"status"`
	CreatedAt  time.Time    `json:"created_at" db:"created_at"`
	LastSeen   time.Time    `json:"last_seen" db:"last_seen"`
}

// PortRule represents a single port access rule for a node.
type PortRule struct {
	ID          string `json:"id" db:"id"`
	NodeID      string `json:"node_id" db:"node_id"`
	Protocol    string `json:"protocol" db:"protocol"`
	LocalPort   int    `json:"local_port" db:"local_port"`
	VirtualPort int    `json:"virtual_port" db:"virtual_port"`
	Description string `json:"description" db:"description"`
	Enabled     bool   `json:"enabled" db:"enabled"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// APIUser is a REST API user account.
type APIUser struct {
	ID           string `json:"id" db:"id"`
	Username     string `json:"username" db:"username"`
	PasswordHash string `json:"-" db:"password_hash"`
	Role         string `json:"role" db:"role"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	LastLogin    *time.Time `json:"last_login" db:"last_login"`
}

// NodeFilter is used to filter node listings.
type NodeFilter struct {
	RoomID  string
	Status  NodeStatus
	Limit   int
	Offset  int
}

// DatabaseConfig holds the configuration needed to create a Store.
type DatabaseConfig struct {
	Type         string
	DSN          string
	MaxOpenConns int
	MaxIdleConns int
}

// Store is the storage abstraction implemented by all backends.
type Store interface {
	// Nodes
	RegisterNode(ctx context.Context, n *Node) error
	GetNode(ctx context.Context, id string) (*Node, error)
	ListNodes(ctx context.Context, filter NodeFilter) ([]*Node, error)
	UpdateNodeStatus(ctx context.Context, id string, status NodeStatus) error
	DeleteNode(ctx context.Context, id string) error

	// Rooms
	CreateRoom(ctx context.Context, r *types.Room) error
	GetRoom(ctx context.Context, id string) (*types.Room, error)
	ListRooms(ctx context.Context) ([]*types.Room, error)
	AddRoomMember(ctx context.Context, roomID, nodeID string) error
	RemoveRoomMember(ctx context.Context, roomID, nodeID string) error
	ListRoomMembers(ctx context.Context, roomID string) ([]*Node, error)

	// Port rules
	SetPortRule(ctx context.Context, rule *PortRule) error
	GetPortRules(ctx context.Context, nodeID string) ([]*PortRule, error)
	DeletePortRule(ctx context.Context, ruleID string) error

	// API users
	CreateAPIUser(ctx context.Context, u *APIUser) error
	GetAPIUser(ctx context.Context, username string) (*APIUser, error)
	RevokeAPIToken(ctx context.Context, tokenID string) error

	Close() error
}

// ErrNotImplemented is returned by Store methods in P0.
var ErrNotImplemented = fmt.Errorf("storage not implemented in current phase")

// noopStore is a Store that returns ErrNotImplemented for every method.
type noopStore struct{}

func (noopStore) RegisterNode(ctx context.Context, n *Node) error                 { return ErrNotImplemented }
func (noopStore) GetNode(ctx context.Context, id string) (*Node, error)            { return nil, ErrNotImplemented }
func (noopStore) ListNodes(ctx context.Context, f NodeFilter) ([]*Node, error)      { return nil, ErrNotImplemented }
func (noopStore) UpdateNodeStatus(ctx context.Context, id string, s NodeStatus) error { return ErrNotImplemented }
func (noopStore) DeleteNode(ctx context.Context, id string) error                   { return ErrNotImplemented }
func (noopStore) CreateRoom(ctx context.Context, r *types.Room) error              { return ErrNotImplemented }
func (noopStore) GetRoom(ctx context.Context, id string) (*types.Room, error)       { return nil, ErrNotImplemented }
func (noopStore) ListRooms(ctx context.Context) ([]*types.Room, error)             { return nil, ErrNotImplemented }
func (noopStore) AddRoomMember(ctx context.Context, roomID, nodeID string) error   { return ErrNotImplemented }
func (noopStore) RemoveRoomMember(ctx context.Context, roomID, nodeID string) error { return ErrNotImplemented }
func (noopStore) ListRoomMembers(ctx context.Context, roomID string) ([]*Node, error) { return nil, ErrNotImplemented }
func (noopStore) SetPortRule(ctx context.Context, rule *PortRule) error            { return ErrNotImplemented }
func (noopStore) GetPortRules(ctx context.Context, nodeID string) ([]*PortRule, error) { return nil, ErrNotImplemented }
func (noopStore) DeletePortRule(ctx context.Context, ruleID string) error         { return ErrNotImplemented }
func (noopStore) CreateAPIUser(ctx context.Context, u *APIUser) error              { return ErrNotImplemented }
func (noopStore) GetAPIUser(ctx context.Context, username string) (*APIUser, error) { return nil, ErrNotImplemented }
func (noopStore) RevokeAPIToken(ctx context.Context, tokenID string) error        { return ErrNotImplemented }
func (noopStore) Close() error                                                     { return nil }
