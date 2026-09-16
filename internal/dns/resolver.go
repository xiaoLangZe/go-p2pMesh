// Package dns implements the local DNS proxy that answers `.xiaolangze`
// names (A3). It is the discovery layer between human-facing names and
// mesh addresses: `[node-id].xiaolangze` resolves to that node's mesh IP,
// and every other name is forwarded to the upstream resolver.
//
// The proxy listens on 127.0.0.1:53 (UDP). It is deliberately NOT a full
// DNS server: no zone transfer, no recursion of its own, no TCP — just a
// resolver shim for the mesh TLD plus upstream passthrough.
package dns

import (
	"fmt"
	"net"
	"strings"
)

// TLD is the private top-level domain served by the proxy. It is a
// deliberately fictional TLD (B6/A3): it can never be publicly verified,
// so it cannot leak node names into Certificate Transparency logs or
// collide with a real registration.
const TLD = ".xiaolangze"

// View is the address knowledge the resolver consults. It abstracts both
// the client's routing table (same-room peers) and, later, the DHT (§16.5)
// for out-of-room peers. The DNS layer stays independent of the routing
// backend.
type View interface {
	// Lookup returns the mesh addresses for a node ID, or ok=false.
	Lookup(nodeID string) (ipv6, ipv4 string, ok bool)
}

// Resolver turns a qualified name inside the mesh TLD into addresses.
type Resolver struct {
	view     View
	upstream Upstream
}

// Upstream resolves a name that is not in the mesh TLD. Injection point
// for tests; defaults to the system resolver.
type Upstream interface {
	LookupIP(host string) ([]net.IP, error)
}

type systemUpstream struct{}

func (systemUpstream) LookupIP(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

// NewResolver creates a Resolver over the given address view.
func NewResolver(view View) *Resolver {
	return &Resolver{view: view, upstream: systemUpstream{}}
}

// Resolve maps a DNS name to its answer set.
//
// Names under the mesh TLD must be exactly `<node-id>.xiaolangze` — one
// label only. Anything else inside the TLD is refused (NXDOMAIN) rather
// than guessed, so a typo never leaks a query upstream and never returns a
// wrong node. Names outside the TLD are forwarded upstream.
func (r *Resolver) Resolve(name string) ([]net.IP, error) {
	host := canonicalName(name)
	if !strings.HasSuffix(host, TLD) {
		return r.upstream.LookupIP(host)
	}

	label := strings.TrimSuffix(host, TLD)
	if label == "" || strings.Contains(label, ".") {
		return nil, fmt.Errorf("%s: not a node name (want <node-id>%s)", host, TLD)
	}

	ipv6, ipv4, ok := r.view.Lookup(label)
	if !ok {
		return nil, fmt.Errorf("%s: node %q not known (or not in this room)", host, label)
	}

	var out []net.IP
	if v6 := net.ParseIP(ipv6); v6 != nil {
		out = append(out, v6)
	}
	if v4 := net.ParseIP(ipv4); v4 != nil {
		out = append(out, v4)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: node %q has no address", host, label)
	}
	return out, nil
}

// canonicalName normalises a query name: trims the trailing dot and
// lower-cases it (domain names are case-insensitive).
func canonicalName(name string) string {
	n := strings.TrimSuffix(name, ".")
	return strings.ToLower(n)
}
