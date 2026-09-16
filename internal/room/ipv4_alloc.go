package room

import (
	"fmt"
	"sync"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// IPv4Allocator derives per-room IPv4 addresses.
//
// Every peer computes the same address for a given (NodeID, RoomID) pair, so
// there is no allocation protocol and no central registry — the server only
// verifies that a claimed address matches the derivation (see VerifyNodeIPv4).
type IPv4Allocator struct {
	mu      sync.RWMutex
	keys    map[types.RoomID]types.RoomKey
	subnets map[types.RoomID]types.RoomSubnet
}

// NewIPv4Allocator creates a new IPv4 allocator.
func NewIPv4Allocator() *IPv4Allocator {
	return &IPv4Allocator{
		keys:    make(map[types.RoomID]types.RoomKey),
		subnets: make(map[types.RoomID]types.RoomSubnet),
	}
}

// RoomKey returns the salt key for a room, deriving it on first use.
func (a *IPv4Allocator) RoomKey(meshSecret []byte, roomID types.RoomID, explicitKey []byte) types.RoomKey {
	a.mu.RLock()
	if k, ok := a.keys[roomID]; ok {
		a.mu.RUnlock()
		return k
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()
	if k, ok := a.keys[roomID]; ok {
		return k
	}
	k := types.DeriveRoomKey(meshSecret, roomID, explicitKey)
	a.keys[roomID] = k
	return k
}

// RoomSubnet returns the /24 IPv4 subnet for the given room.
func (a *IPv4Allocator) RoomSubnet(roomID types.RoomID, roomKey types.RoomKey) types.RoomSubnet {
	a.mu.RLock()
	if s, ok := a.subnets[roomID]; ok {
		a.mu.RUnlock()
		return s
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()
	if s, ok := a.subnets[roomID]; ok {
		return s
	}
	s := types.DeriveRoomSubnet(roomKey)
	a.subnets[roomID] = s
	return s
}

// NodeIPv4Addr returns the IPv4 address for a node within a room.
func (a *IPv4Allocator) NodeIPv4Addr(nodeID types.NodeID, roomKey types.RoomKey) string {
	return types.DeriveNodeIPv4(nodeID, roomKey).String()
}

// NodeIPv6Addr returns the IPv6 address for a node within a room.
func (a *IPv4Allocator) NodeIPv6Addr(nodeID types.NodeID, roomKey types.RoomKey) (string, error) {
	addr, err := types.DeriveIPv6Addr(nodeID, roomKey)
	if err != nil {
		return "", fmt.Errorf("derive node ipv6: %w", err)
	}
	return addr.String(), nil
}

// VerifyNodeIPv4 checks that a claimed IPv4 address matches the derivation.
// The server calls this before accepting a registration so a node cannot claim
// an address that belongs to a different (NodeID, room) pair.
func (a *IPv4Allocator) VerifyNodeIPv4(nodeID types.NodeID, roomKey types.RoomKey, claimed string) bool {
	return types.DeriveNodeIPv4(nodeID, roomKey).String() == claimed
}

// VerifyNodeIPv6 checks that a claimed IPv6 address matches the derivation.
func (a *IPv4Allocator) VerifyNodeIPv6(nodeID types.NodeID, roomKey types.RoomKey, claimed string) bool {
	expected, err := types.DeriveIPv6Addr(nodeID, roomKey)
	if err != nil {
		return false
	}
	return expected.String() == claimed
}
