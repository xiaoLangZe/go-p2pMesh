package portcontrol

import (
	"fmt"
	"net"
	"net/netip"
	"os"
)

// StartupOptions carries the inputs the port-control subsystem validates
// before the client is allowed to serve any virtual port.
//
// The design treats startup as a *confirmation* point, not a formality:
// a permissive policy or a subnet that collides with the host's own LAN
// must stop the process rather than degrade silently (invariant I6), and
// a broad "allow" policy must be an explicit, acknowledged decision
// (invariant I5: nothing is exposed by default).
type StartupOptions struct {
	// RulesFile is the path the port rules are loaded from. Empty means
	// rules live elsewhere (memory, server push); when set it must exist
	// and be readable, otherwise startup fails.
	RulesFile string

	// MeshCIDR is the IPv4 mesh subnet (e.g. a room's 240.0.0.0/4 /24).
	// It is checked for collision against the host's own interfaces: a
	// mesh subnet that overlaps a local LAN would silently black-hole
	// that LAN's traffic once routes are installed.
	MeshCIDR string

	// AllowConfirmed must be true when the controller's policy is
	// PolicyAllow. It records that the operator knowingly accepted an
	// open default policy; without it, startup is refused. This mirrors
	// the "-allow-yes" style confirmation the design mandates for the
	// permissive mode.
	AllowConfirmed bool
}

// LocalNets lists the IP prefixes currently configured on the host,
// excluding loopback and link-local. StartupCheck uses it to detect a
// mesh/LAN collision. It is a parameter (rather than an unexported call)
// so the collision check is testable without touching the real routing
// table.
type LocalNets func() ([]netip.Prefix, error)

// DefaultLocalNets enumerates the host's global interface addresses.
func DefaultLocalNets() ([]netip.Prefix, error) {
	var out []netip.Prefix
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("enumerate interfaces: %w", err)
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			// One unreadable interface must not abort the whole check;
			// it only reduces coverage, which is logged by the caller.
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			p, ok := ipnetToPrefix(ipn)
			if !ok {
				continue
			}
			if p.Addr().IsLoopback() || isLinkLocal(p.Addr()) {
				continue
			}
			out = append(out, p)
		}
	}
	return out, nil
}

// isLinkLocal reports link-local unicast (169.254.0.0/16 or fe80::/10),
// which never participates in routing and so cannot collide in the sense
// the mesh check cares about.
func isLinkLocal(a netip.Addr) bool {
	return a.IsLinkLocalUnicast()
}

// SelfCheck validates the startup configuration and returns the first
// blocking problem. It enforces the design's "confirmation, not silence"
// rule: an unsafe combination must be reported, never accepted quietly.
//
// Checks, in order:
//  1. If a rules file is configured, it exists and is readable.
//  2. A default-allow policy is refused unless explicitly confirmed.
//  3. The mesh IPv4 subnet must not overlap any host LAN subnet.
func (c *Controller) SelfCheck(opts StartupOptions, local LocalNets) error {
	if opts.RulesFile != "" {
		f, err := os.Open(opts.RulesFile)
		if err != nil {
			return fmt.Errorf("port rules file unreadable: %w", err)
		}
		_ = f.Close()
	}

	c.mu.RLock()
	policy := c.policy
	c.mu.RUnlock()
	if policy == PolicyAllow && !opts.AllowConfirmed {
		return fmt.Errorf(
			"default_policy=allow requires an explicit confirmation: the port " +
				"controller would expose every unconfigured port on the mesh. " +
				"Pass the allow-confirmation flag only if this is intended")
	}

	if opts.MeshCIDR != "" {
		mesh, err := netip.ParsePrefix(opts.MeshCIDR)
		if err != nil {
			return fmt.Errorf("invalid mesh CIDR %q: %w", opts.MeshCIDR, err)
		}
		listNets := local
		if listNets == nil {
			listNets = DefaultLocalNets
		}
		hn, err := listNets()
		if err != nil {
			return fmt.Errorf("enumerate host networks: %w", err)
		}
		for _, h := range hn {
			// Overlap between different families is impossible and the
			// stdlib guards it; comparing only same-family prefixes keeps
			// the intent explicit.
			if h.Addr().Is4() != mesh.Addr().Is4() {
				continue
			}
			if h.Overlaps(mesh) {
				return fmt.Errorf(
					"mesh subnet %s collides with host interface %s; routes would "+
						"black-hole that local network", mesh, h)
			}
		}
	}
	return nil
}

// ipnetToPrefix converts a *net.IPNet to a netip.Prefix, returning false
// when the mask cannot be represented (non-canonical or malformed).
func ipnetToPrefix(ipn *net.IPNet) (netip.Prefix, bool) {
	addr, ok := netip.AddrFromSlice(ipn.IP)
	if !ok {
		return netip.Prefix{}, false
	}
	addr = addr.Unmap()
	ones, bits := ipn.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false
	}
	// bits is 32 or 128; netip expects the address's own bit length.
	if bits != addr.BitLen() {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, ones), true
}
