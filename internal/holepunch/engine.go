// Package holepunch implements the NAT traversal hole-punching engine.
package holepunch

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// ErrNotImplemented is returned by scaffolds completed in the P1 baseline.
var ErrNotImplemented = fmt.Errorf("holepunch not implemented in current phase")

// Strategy represents one hole-punching strategy in the priority matrix.
type Strategy string

const (
	StrategyIPv6Direct   Strategy = "ipv6_direct"
	StrategyUDPStandard  Strategy = "udp_standard"
	StrategyUDPPredict   Strategy = "udp_predict"
	StrategyTCPSimultaneous Strategy = "tcp_simultaneous"
	StrategyTURNRelay    Strategy = "turn_relay"
)

// PunchResult records the outcome of a hole-punch attempt.
type PunchResult struct {
	Strategy  Strategy
	Success   bool
	LocalAddr net.Addr
	RemoteAddr net.Addr
	Error     error
}

// Engine coordinates the hole-punching strategy matrix.
type Engine struct {
	mu sync.Mutex
	// Configuration will be added in P2.
}

// NewEngine creates a hole-punching engine.
func NewEngine() *Engine {
	return &Engine{}
}

// Punch attempts to establish a direct connection with the target peer
// using the strategy priority matrix.
func (e *Engine) Punch(targetInfo *PeerInfo) (*PunchResult, error) {
	return nil, ErrNotImplemented
}

// PeerInfo holds the information about the remote peer needed for punching.
type PeerInfo struct {
	NodeID string
	// RoomID is the room the peer belongs to. Rule R1 (see priority.go) uses it
	// to order candidates: same-room peers are attempted first.
	RoomID types.RoomID
	// JoinedAt orders peers within the same room. The zero value is fine for
	// peers whose join time is unknown; NodeID then decides the order.
	JoinedAt     time.Time
	IPv6         string
	PublicAddr   string
	NATType      string
	PredictRange [2]int // [start, end] predicted port range
}

// PunchStats counts outcomes separately per R1 group.
//
// The split is deliberate: the design requires that out-of-room attempts are
// counted apart from same-room ones, because averaging them would let an
// invariant-I7 failure (cross-room addresses becoming usable) hide inside a
// healthy-looking overall success rate.
type PunchStats struct {
	SameRoomAttempted  int
	SameRoomSucceeded  int
	OtherRoomAttempted int
	OtherRoomSucceeded int
}

// SuccessRate returns the same-room success ratio, or 0 when nothing was tried.
func (s PunchStats) SuccessRate() float64 {
	if s.SameRoomAttempted == 0 {
		return 0
	}
	return float64(s.SameRoomSucceeded) / float64(s.SameRoomAttempted)
}

// OtherRoomAttemptRate reports what fraction of attempts left the room. A
// non-zero value with no same-room failures to explain it suggests I7 is not
// being enforced.
func (s PunchStats) OtherRoomAttemptRate() float64 {
	total := s.SameRoomAttempted + s.OtherRoomAttempted
	if total == 0 {
		return 0
	}
	return float64(s.OtherRoomAttempted) / float64(total)
}
