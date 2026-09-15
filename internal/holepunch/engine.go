// Package holepunch implements the NAT traversal hole-punching engine.
package holepunch

import (
	"fmt"
	"net"
	"sync"
)

// ErrNotImplemented is returned by all methods in P0.
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
	// Configuration will be added in P5.
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
	NodeID     string
	IPv6       string
	PublicAddr string
	NATType    string
	PredictRange [2]int // [start, end] predicted port range
}
