package stun

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// StunServer tracks one third-party STUN server's health and latency.
type StunServer struct {
	Addr      string
	Latency   time.Duration
	IPv4      net.IP
	IPv6      net.IP
	Healthy   bool
	LastCheck time.Time
}

// Pool is a health-checked pool of third-party STUN servers.
type Pool struct {
	mu      sync.RWMutex
	servers []*StunServer
}

// NewPool creates a new STUN server pool from the given addresses.
func NewPool(addrs []string) *Pool {
	p := &Pool{}
	for _, a := range addrs {
		p.servers = append(p.servers, &StunServer{Addr: a})
	}
	return p
}

// All returns all STUN servers (for health checking).
func (p *Pool) All() []*StunServer {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]*StunServer, len(p.servers))
	copy(out, p.servers)
	return out
}

// Best returns the healthiest STUN server with the lowest latency.
func (p *Pool) Best() (*StunServer, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var best *StunServer
	for _, s := range p.servers {
		if !s.Healthy {
			continue
		}
		if best == nil || s.Latency < best.Latency {
			best = s
		}
	}
	if best == nil {
		return nil, fmt.Errorf("no healthy STUN servers")
	}
	return best, nil
}

// CheckHealth probes all STUN servers.  Currently a no-op; the real STUN
// Binding health check is P2.
func (p *Pool) CheckHealth(timeout time.Duration) {
	// P2: implement actual STUN Binding health checks.
}

// ErrNotImplemented is returned by scaffolds completed in the P1 baseline.
var ErrNotImplemented = fmt.Errorf("stun not implemented in current phase")
