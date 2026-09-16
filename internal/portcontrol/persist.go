package portcontrol

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/internal/storage"
)

// PortRuleStore is the minimal store surface the persistence layer needs.
// storage.Store satisfies it; tests can supply a lightweight in-memory
// implementation without the full node/room/API-user surface.
type PortRuleStore interface {
	SetPortRule(ctx context.Context, rule *storage.PortRule) error
	GetPortRules(ctx context.Context, nodeID string) ([]*storage.PortRule, error)
	DeletePortRule(ctx context.Context, ruleID string) error
}

// RulePersistence wires the in-memory rule registry to durable storage.
//
// The client keeps rules in a local SQLite database (config key
// `[portcontrol] db_file`, default `portcontrol.db`); the server keeps them
// in its own store and distributes them via PORT_RULE_SYNC (§7/§14 of the
// protocol). Both directions share the Controller registry as the single
// source of truth at runtime.
type RulePersistence struct {
	mu     sync.Mutex
	store  PortRuleStore
	nodeID string
}

// NewRulePersistence creates a persistence wrapper. A nil store is allowed
// (rules then live only in memory, e.g. server-push-only clients).
func NewRulePersistence(store PortRuleStore, nodeID string) *RulePersistence {
	return &RulePersistence{store: store, nodeID: nodeID}
}

// SaveRule persists a rule. To stay race-free, the Controller serialises
// updates through the persistence mutex before touching the registry.
func (p *RulePersistence) SaveRule(ctx context.Context, rule *PortRule) error {
	if p.store == nil {
		return nil
	}
	sr := &storage.PortRule{
		ID:           rule.ID,
		NodeID:       rule.NodeID,
		Protocol:     rule.Protocol,
		LocalPort:    rule.LocalPort,
		VirtualPort:  rule.VirtualPort,
		Description:  rule.Description,
		AllowedRooms: encodeAllowedRooms(rule.AllowedRooms),
		Enabled:      rule.Enabled,
		CreatedAt:    rule.CreatedAt,
	}
	if sr.NodeID == "" {
		sr.NodeID = p.nodeID
	}
	return p.store.SetPortRule(ctx, sr)
}

// DeleteRule removes a persisted rule.
func (p *RulePersistence) DeleteRule(ctx context.Context, ruleID string) error {
	if p.store == nil {
		return nil
	}
	return p.store.DeletePortRule(ctx, ruleID)
}

// LoadRules reads all persisted rules for this node and returns them.
func (p *RulePersistence) LoadRules(ctx context.Context) ([]*PortRule, error) {
	if p.store == nil {
		return nil, nil
	}
	stored, err := p.store.GetPortRules(ctx, p.nodeID)
	if err != nil {
		return nil, fmt.Errorf("load port rules: %w", err)
	}
	out := make([]*PortRule, 0, len(stored))
	for _, sr := range stored {
		out = append(out, &PortRule{
			ID:           sr.ID,
			NodeID:       sr.NodeID,
			Protocol:     sr.Protocol,
			LocalPort:    sr.LocalPort,
			VirtualPort:  sr.VirtualPort,
			Description:  sr.Description,
			AllowedRooms: decodeAllowedRooms(sr.AllowedRooms),
			Enabled:      sr.Enabled,
			CreatedAt:    sr.CreatedAt,
		})
	}
	return out, nil
}

// ApplyServerRules applies rules pushed by the server (PORT_RULE_SYNC).
//
// Semantics: server rules replace *seeded* rules with the same ID and are
// added wholesale; the caller (bootstrap control plane) decides whether a
// full-sync or delta. Returns the number of rules applied.
func (c *Controller) ApplyServerRules(ctx context.Context, rules []storage.PortRule) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	applied := 0
	for _, sr := range rules {
		pc := &PortRule{
			ID:           sr.ID,
			NodeID:       sr.NodeID,
			Protocol:     sr.Protocol,
			LocalPort:    sr.LocalPort,
			VirtualPort:  sr.VirtualPort,
			Description:  sr.Description,
			AllowedRooms: decodeAllowedRooms(sr.AllowedRooms),
			Enabled:      sr.Enabled,
			CreatedAt:    sr.CreatedAt,
		}
		c.rules[pc.VirtualPort] = pc
		c.local[pc.LocalPort] = pc
		applied++
	}
	return applied, nil
}

// AddRulePersisted registers a rule and persists it. Returns an error when
// the rule is invalid or the store rejects it; the registry is not mutated
// on failure, so callers can retry without a half-applied rule.
func (c *Controller) AddRulePersisted(ctx context.Context, p *RulePersistence, rule *PortRule) error {
	if err := validateRule(rule); err != nil {
		return err
	}
	if rule.NodeID == "" {
		rule.NodeID = p.nodeID
	}
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = time.Now().UTC()
	}
	if err := p.SaveRule(ctx, rule); err != nil {
		return fmt.Errorf("persist rule: %w", err)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules[rule.VirtualPort] = rule
	c.local[rule.LocalPort] = rule
	return nil
}

// RemoveRulePersisted removes and deletes a rule by virtual port.
func (c *Controller) RemoveRulePersisted(ctx context.Context, p *RulePersistence, virtualPort int) error {
	c.mu.Lock()
	rule, ok := c.rules[virtualPort]
	if ok {
		delete(c.rules, virtualPort)
		delete(c.local, rule.LocalPort)
	}
	c.mu.Unlock()
	if !ok {
		return fmt.Errorf("no rule for virtual port %d", virtualPort)
	}
	if err := p.DeleteRule(ctx, rule.ID); err != nil {
		return fmt.Errorf("delete rule: %w", err)
	}
	return nil
}

// LoadPersisted replaces the in-memory registry with the persisted rules.
// Used at client startup before the TUN data path is up.
func (c *Controller) LoadPersisted(ctx context.Context, p *RulePersistence) error {
	rules, err := p.LoadRules(ctx)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rules = make(map[int]*PortRule, len(rules))
	c.local = make(map[int]*PortRule, len(rules))
	for _, r := range rules {
		c.rules[r.VirtualPort] = r
		c.local[r.LocalPort] = r
	}
	return nil
}

// validateRule checks the rule fields the registry depends on. It is the
// new-rule entry point check so the double index can never hold an entry
// with a zero port.
func validateRule(rule *PortRule) error {
	if rule == nil {
		return fmt.Errorf("nil rule")
	}
	if rule.VirtualPort < 1 || rule.VirtualPort > 65535 {
		return fmt.Errorf("virtual port %d out of range", rule.VirtualPort)
	}
	if rule.LocalPort < 1 || rule.LocalPort > 65535 {
		return fmt.Errorf("local port %d out of range", rule.LocalPort)
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		return fmt.Errorf("protocol must be tcp or udp, got %q", rule.Protocol)
	}
	return nil
}
