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
	"sync"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// PortRule defines a single port access rule.
type PortRule struct {
	ID          string
	NodeID      string
	Protocol    string // "tcp" or "udp"
	LocalPort   int    // real local port the service listens on
	VirtualPort int    // external-facing port on the IPv6 address
	// AllowedRooms lists the rooms whose members may reach this port.
	// Empty means the rule default: same-room sources only (§8.2).
	AllowedRooms []types.RoomID
	Description  string
	Enabled      bool
	CreatedAt    time.Time
}

// Policy is the default port policy.
type Policy string

const (
	PolicyDeny  Policy = "deny"
	PolicyAllow Policy = "allow"
)

// Controller manages port access rules and virtual port mapping.
type Controller struct {
	mu     sync.RWMutex
	rules  map[int]*PortRule // keyed by virtual port
	local  map[int]*PortRule // keyed by local port
	policy Policy
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

// InboundDecision is the verdict of a virtual-port access attempt from a
// specific source, including source-room semantics (§8.1.1).
type InboundDecision int

const (
	// DecisionAllow: forward to the local service.
	DecisionAllow InboundDecision = iota
	// DecisionDropUnconfigured: no rule exists for the port — silent drop;
	// the probe may count toward scan detection (I10).
	DecisionDropUnconfigured
	// DecisionDropNotAllowed: rule exists but this source room is not
	// permitted — silent drop, indistinguishable from an absent port.
	DecisionDropNotAllowed
	// DecisionDropDisabled: rule exists but is disabled — silent drop.
	DecisionDropDisabled
)

// Source identifies where an inbound attempt came from (§8.1.1).
type Source struct {
	// Room is the source's room, empty when unknown.
	Room types.RoomID
	// SameRoom reports whether the source is in the same room as this node.
	// It is the caller's job to establish this (room-scoped addressing).
	SameRoom bool
	// Addr is the source mesh address, for scan accounting (I10).
	Addr string
}

// Decide evaluates an inbound attempt against the rule table and source.
//
// The matrix (§8.1.1):
//   - configured + enabled + source room allowed → Allow
//   - configured + enabled + source room not allowed → DropNotAllowed
//   - configured + disabled → DropDisabled
//   - unconfigured → DropUnconfigured (scan accounting applies elsewhere)
func (c *Controller) Decide(virtualPort int, src Source) InboundDecision {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.policy == PolicyAllow {
		return DecisionAllow
	}
	r, ok := c.rules[virtualPort]
	if !ok {
		return DecisionDropUnconfigured
	}
	if !r.Enabled {
		return DecisionDropDisabled
	}
	if RuleAllowsSource(r, src) {
		return DecisionAllow
	}
	return DecisionDropNotAllowed
}

// RuleAllowsSource is the source-room gate for one rule (§8.2):
// empty AllowedRooms means same-room only; otherwise explicit membership.
func RuleAllowsSource(r *PortRule, src Source) bool {
	if len(r.AllowedRooms) == 0 {
		return src.SameRoom
	}
	for _, room := range r.AllowedRooms {
		if room == src.Room {
			return true
		}
	}
	return false
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
