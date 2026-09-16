package holepunch

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// StrategyMatrix implements the three-level path-establishment ladder from
// DESIGN.md §12.1. Each level tries progressively more expensive methods.
type StrategyMatrix struct {
	mu              sync.Mutex
	timeout         time.Duration
	parallelBudget  int
	loadGuardActive bool
}

// NewStrategyMatrix creates a matrix with the given per-step timeout and
// parallel attempt budget (from capacity self-assessment, §16.4).
func NewStrategyMatrix(timeout time.Duration, parallelBudget int) *StrategyMatrix {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if parallelBudget <= 0 {
		parallelBudget = 64
	}
	return &StrategyMatrix{
		timeout:        timeout,
		parallelBudget: parallelBudget,
	}
}

// EstablishPath tries each strategy in priority order until one succeeds or
// all fail. It follows §12.1's stage-one ladder:
//
//  1. IPv6 direct connect (if both peers have public v6)
//  2. Standard UDP hole punching (cone NATs)
//  3. Symmetric port prediction (single-sided)
//  4. Symmetric port prediction (double-sided)
//  5. TCP simultaneous open (last-resort within P2P direct)
//
// Each step has a timeout; on failure the next step is tried immediately.
func (m *StrategyMatrix) EstablishPath(target *PeerInfo) (*PunchResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	strategies := []Strategy{
		StrategyIPv6Direct,
		StrategyUDPStandard,
		StrategyUDPPredict,
		StrategyTCPSimultaneous,
	}

	for _, s := range strategies {
		// Skip IPv6 direct if target has no IPv6.
		if s == StrategyIPv6Direct && target.IPv6 == "" {
			continue
		}
		// Skip UDP standard if either side is symmetric (needs prediction).
		if s == StrategyUDPStandard && (target.NATType == "Symmetric") {
			continue
		}
		// Skip prediction if target has no predict range.
		if s == StrategyUDPPredict && target.PredictRange[1] == 0 {
			continue
		}

		result := m.tryStrategy(s, target)
		if result.Success {
			return result, nil
		}
	}

	return nil, fmt.Errorf("all strategies failed for peer %s", target.NodeID)
}

// tryStrategy executes one strategy and returns its result.
func (m *StrategyMatrix) tryStrategy(s Strategy, target *PeerInfo) *PunchResult {
	switch s {
	case StrategyIPv6Direct:
		return m.tryIPv6Direct(target)
	case StrategyUDPStandard:
		return m.tryUDPStandard(target)
	case StrategyUDPPredict:
		return m.tryUDPPredict(target)
	case StrategyTCPSimultaneous:
		return m.tryTCPSimultaneous(target)
	default:
		return &PunchResult{Strategy: s, Success: false, Error: fmt.Errorf("unknown strategy %s", s)}
	}
}

// tryIPv6Direct attempts a direct UDP connection to the peer's public IPv6.
func (m *StrategyMatrix) tryIPv6Direct(target *PeerInfo) *PunchResult {
	addr := fmt.Sprintf("[%s]:%d", target.IPv6, 29683)
	conn, err := net.DialTimeout("udp", addr, m.timeout)
	if err != nil {
		return &PunchResult{Strategy: StrategyIPv6Direct, Success: false, Error: err}
	}
	defer conn.Close()

	// Send a probe and wait for response.
	if _, err := conn.Write([]byte("p2pmesh-probe")); err != nil {
		return &PunchResult{Strategy: StrategyIPv6Direct, Success: false, Error: err}
	}
	conn.SetReadDeadline(time.Now().Add(m.timeout))
	buf := make([]byte, 64)
	if _, err := conn.Read(buf); err != nil {
		return &PunchResult{Strategy: StrategyIPv6Direct, Success: false, Error: err}
	}
	return &PunchResult{
		Strategy:   StrategyIPv6Direct,
		Success:    true,
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: conn.RemoteAddr(),
	}
}

// tryUDPStandard attempts standard UDP hole punching: both peers send to
// each other's public address simultaneously.
func (m *StrategyMatrix) tryUDPStandard(target *PeerInfo) *PunchResult {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return &PunchResult{Strategy: StrategyUDPStandard, Success: false, Error: err}
	}
	defer conn.Close()

	peerAddr, err := net.ResolveUDPAddr("udp", target.PublicAddr)
	if err != nil {
		return &PunchResult{Strategy: StrategyUDPStandard, Success: false, Error: err}
	}

	// Send probe packets to the peer's public address.
	conn.SetWriteDeadline(time.Now().Add(m.timeout))
	if _, err := conn.WriteTo([]byte("p2pmesh-probe"), peerAddr); err != nil {
		return &PunchResult{Strategy: StrategyUDPStandard, Success: false, Error: err}
	}

	// Wait for the peer's probe to arrive (the NAT mapping must be open).
	conn.SetReadDeadline(time.Now().Add(m.timeout))
	buf := make([]byte, 64)
	if _, _, err := conn.ReadFrom(buf); err != nil {
		return &PunchResult{Strategy: StrategyUDPStandard, Success: false, Error: err}
	}
	return &PunchResult{
		Strategy:   StrategyUDPStandard,
		Success:    true,
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: peerAddr,
	}
}

// tryUDPPredict attempts port prediction for symmetric NATs. It opens
// multiple sockets in parallel (within the budget) and fires at the
// predicted port range.
//
// Per DESIGN.md §12.5: punching must use a SINGLE socket with multiple
// goroutines — NOT multiple processes. Each process gets a different NAT
// mapping, which defeats prediction.
func (m *StrategyMatrix) tryUDPPredict(target *PeerInfo) *PunchResult {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return &PunchResult{Strategy: StrategyUDPPredict, Success: false, Error: err}
	}
	defer conn.Close()

	lo, hi := target.PredictRange[0], target.PredictRange[1]
	if lo <= 0 || hi <= 0 || hi < lo {
		return &PunchResult{Strategy: StrategyUDPPredict, Success: false,
			Error: fmt.Errorf("invalid predict range [%d, %d]", lo, hi)}
	}

	// Resolve the peer's IP from its public address.
	peerAddr, err := net.ResolveUDPAddr("udp", target.PublicAddr)
	if err != nil {
		return &PunchResult{Strategy: StrategyUDPPredict, Success: false, Error: err}
	}

	type attempt struct {
		port int
		err  error
	}

	width := hi - lo + 1
	if width > m.parallelBudget {
		width = m.parallelBudget
	}

	attempts := make(chan attempt, width)
	deadline := time.Now().Add(m.timeout)

	// Fan out: each goroutine sends to a different predicted port using the
	// SAME socket. This is the single-socket constraint (§12.5).
	for i := 0; i < width; i++ {
		port := lo + i
		go func() {
			target := &net.UDPAddr{IP: peerAddr.IP, Port: port}
			conn.SetWriteDeadline(deadline)
			_, err := conn.WriteTo([]byte("p2pmesh-probe"), target)
			attempts <- attempt{port: port, err: err}
		}()
	}

	// Collect all write results.
	for i := 0; i < width; i++ {
		<-attempts
	}

	// Wait for a response on any of the predicted ports.
	conn.SetReadDeadline(deadline)
	buf := make([]byte, 64)
	_, remote, err := conn.ReadFrom(buf)
	if err != nil {
		return &PunchResult{Strategy: StrategyUDPPredict, Success: false, Error: err}
	}
	return &PunchResult{
		Strategy:   StrategyUDPPredict,
		Success:    true,
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: remote,
	}
}

// tryTCPSimultaneous attempts TCP simultaneous open as a last-resort
// fallback. Both peers set SO_REUSEADDR and send SYN to each other's
// predicted public address at the same time.
//
// Per DESIGN.md §12.4: Windows SO_REUSEPORT support is limited, so this
// has low success rate (15–35%). It is only tried after all UDP strategies
// fail.
func (m *StrategyMatrix) tryTCPSimultaneous(target *PeerInfo) *PunchResult {
	// TCP simultaneous open requires both sides to dial at the same time.
	// In practice this means we dial the peer's public address and hope the
	// peer is doing the same to ours.
	conn, err := net.DialTimeout("tcp", target.PublicAddr, m.timeout)
	if err != nil {
		return &PunchResult{Strategy: StrategyTCPSimultaneous, Success: false, Error: err}
	}
	defer conn.Close()
	return &PunchResult{
		Strategy:   StrategyTCPSimultaneous,
		Success:    true,
		LocalAddr:  conn.LocalAddr(),
		RemoteAddr: conn.RemoteAddr(),
	}
}
