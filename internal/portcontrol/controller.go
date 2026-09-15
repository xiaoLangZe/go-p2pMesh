// Package portcontrol implements the port access control and virtual
// port mapping system.
//
// Core rules:
//   - Default deny: all unconfigured ports are rejected.
//   - Open ports: explicitly configured ports are allowed.
//   - Virtual port mapping: external access to [ipv6]:virtualPort
//     forwards to 127.0.0.1:localPort; direct access to localPort is rejected.
package portcontrol

import (
	"fmt"
	"sync"
	"time"
)

// PortRule defines a single port access rule.
type PortRule struct {
	ID          string
	NodeID      string
	Protocol    string // "tcp" or "udp"
	LocalPort   int    // real local port the service listens on
	VirtualPort int    // external-facing port on the IPv6 address
	Description string
	Enabled     bool
	CreatedAt   time.Time
}

// Policy is the default port policy.
type Policy string

const (
	PolicyDeny  Policy = "deny"
	PolicyAllow Policy = "allow"
)

// Controller manages port access rules and virtual port mapping.
type Controller struct {
	mu       sync.RWMutex
	rules    map[int]*PortRule // keyed by virtual port
	local    map[int]*PortRule // keyed by local port
	policy   Policy
}

// NewController creates a Controller with the given default policy.
func NewController(policy Policy) *Controller {
	return &Controller{
		rules:  make(map[int]*PortRule),
		local:  make(map[int]*PortRule),
		policy: policy,
	}
}

// AddRule registers a port rule.
func (c *Controller) AddRule(rule *PortRule) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules[rule.VirtualPort] = rule
	c.local[rule.LocalPort] = rule
}

// RemoveRule deletes a rule by its virtual port.
func (c *Controller) RemoveRule(virtualPort int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if rule, ok := c.rules[virtualPort]; ok {
		delete(c.rules, virtualPort)
		delete(c.local, rule.LocalPort)
	}
}

// LookupVirtual finds the rule for the given virtual port.
func (c *Controller) LookupVirtual(virtualPort int) (*PortRule, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.rules[virtualPort]
	return r, ok
}

// LookupLocal finds the rule for the given local port.
func (c *Controller) LookupLocal(localPort int) (*PortRule, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	r, ok := c.local[localPort]
	return r, ok
}

// IsAllowed checks whether a connection to the given virtual port is allowed.
func (c *Controller) IsAllowed(virtualPort int) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.policy == PolicyAllow {
		return true
	}
	r, ok := c.rules[virtualPort]
	return ok && r.Enabled
}

// ListRules returns all registered rules.
func (c *Controller) ListRules() []*PortRule {
	c.mu.RLock()
	defer c.mu.RUnlock()
	result := make([]*PortRule, 0, len(c.rules))
	for _, r := range c.rules {
		result = append(result, r)
	}
	return result
}

// ErrNotImplemented is returned by scaffolds completed in the P1 baseline.
var ErrNotImplemented = fmt.Errorf("port forwarding not implemented in current phase")

// Forward is the virtual-port→local-port forwarder.
// It will be implemented in P7 using gVisor netstack.
func (c *Controller) Forward(virtualPort int, data []byte) ([]byte, error) {
	return nil, ErrNotImplemented
}
