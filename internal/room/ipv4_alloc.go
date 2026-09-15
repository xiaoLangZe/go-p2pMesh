package room

import (
	"fmt"
	"sync"

	"github.com/yourorg/go-p2pmesh/pkg/types"
)

// IPv4Allocator manages IPv4 address allocation within rooms.
// Each room gets a deterministic /24 subnet derived from the RoomID,
// and each node gets a deterministic host within that subnet derived
// from the NodeID.  No central allocation is needed — both the server
// and the client can compute the same address independently.
type IPv4Allocator struct {
	mu      sync.RWMutex
	// cache of computed subnets to avoid re-hashing on every request
	subnets map[types.RoomID]types.RoomSubnet
}

// NewIPv4Allocator creates a new IPv4 allocator.
func NewIPv4Allocator() *IPv4Allocator {
	return &IPv4Allocator{
		subnets: make(map[types.RoomID]types.RoomSubnet),
	}
}

// RoomSubnet returns the /24 IPv4 subnet for the given room.
// The subnet is derived deterministically from the RoomID and cached.
func (a *IPv4Allocator) RoomSubnet(roomID types.RoomID) (types.RoomSubnet, error) {
	a.mu.RLock()
	if s, ok := a.subnets[roomID]; ok {
		a.mu.RUnlock()
		return s, nil
	}
	a.mu.RUnlock()

	a.mu.Lock()
	defer a.mu.Unlock()
	// Double-check after acquiring write lock.
	if s, ok := a.subnets[roomID]; ok {
		return s, nil
	}
	s, err := types.DeriveRoomSubnet(roomID)
	if err != nil {
		return types.RoomSubnet{}, fmt.Errorf("derive room subnet: %w", err)
	}
	a.subnets[roomID] = s
	return s, nil
}

// NodeIPv4Addr returns the IPv4 address for a node within a room.
// The address is derived deterministically from (NodeID, RoomID).
func (a *IPv4Allocator) NodeIPv4Addr(nodeID types.NodeID, roomID types.RoomID) (string, error) {
	addr, err := types.DeriveNodeIPv4(nodeID, roomID)
	if err != nil {
		return "", fmt.Errorf("derive node ipv4: %w", err)
	}
	return addr.String(), nil
}

// VerifyNodeIPv4 checks that a given IPv4 address matches what would be
// derived from the (NodeID, RoomID) pair.  This is used by the server
// to prevent address spoofing.
func (a *IPv4Allocator) VerifyNodeIPv4(nodeID types.NodeID, roomID types.RoomID, claimedAddr string) (bool, error) {
	expected, err := types.DeriveNodeIPv4(nodeID, roomID)
	if err != nil {
		return false, err
	}
	return expected.String() == claimedAddr, nil
}
