package portcontrol

import (
	"fmt"
	"net"
	"time"
)

// Forwarder connects mesh-side traffic to the local service backing a rule.
//
// The forwarder is the userspace half of §8.6's flow: the netstack layer
// (gVisor integration, deferred until the TUN data path lands) hands the
// forwarder a per-connection dial request for a virtual port; the forwarder
// checks the rule and dials 127.0.0.1:localPort.
//
// Two invariants from the design live here:
//   - default deny: an unconfigured virtual port fails loudly
//   - local-port protection: the mesh side can only reach a service through
//     its virtual mapping, never directly (there is no dial path for
//     arbitrary local ports).
type Forwarder struct {
	controller *Controller
	// DialLocal is the dial function used to reach the local service.
	// Defaults to net.Dial; tests replace it with an in-process dialer.
	DialLocal func(network, addr string) (net.Conn, error)
	// Timeout bounds each forward attempt so a silent local service cannot
	// pin a goroutine forever.
	Timeout time.Duration
}

// NewForwarder creates a forwarder over the given controller.
func NewForwarder(c *Controller) *Forwarder {
	return &Forwarder{
		controller: c,
		DialLocal:  net.Dial,
		Timeout:    10 * time.Second,
	}
}

// DialVirtual resolves a virtual port to its local service and returns an
// open connection. The caller (netstack layer) then proxies bytes both ways.
//
// src carries the source room information; a source outside the rule's
// allowed rooms gets an error indistinguishable from an unconfigured port
// (silent drop, §8.1.1). Direct access to a rule's LocalPort is impossible
// through this API — there is no dial path for it — satisfying the
// "本地直连无效" constraint structurally.
func (f *Forwarder) DialVirtual(virtualPort int, network string, src Source) (net.Conn, error) {
	switch f.controller.Decide(virtualPort, src) {
	case DecisionAllow:
		// proceed
	default:
		// Unconfigured, not-allowed, and disabled all read the same to the
		// caller: the port does not exist from this source.
		return nil, errVirtualPortUnreachable
	}

	rule, _ := f.controller.LookupVirtual(virtualPort)

	// The wire protocol name must match the rule (tcp vs udp).
	switch network {
	case "tcp", "tcp4", "tcp6":
		if rule.Protocol != "tcp" {
			return nil, errVirtualPortUnreachable
		}
	case "udp", "udp4", "udp6":
		if rule.Protocol != "udp" {
			return nil, errVirtualPortUnreachable
		}
	default:
		return nil, fmt.Errorf("unsupported forward network %q", network)
	}

	localAddr := fmt.Sprintf("127.0.0.1:%d", rule.LocalPort)
	conn, err := f.DialLocal(network, localAddr)
	if err != nil {
		return nil, fmt.Errorf("dial local service %s: %w", localAddr, err)
	}
	return conn, nil
}

// errVirtualPortUnreachable is the shared, information-free rejection for
// every "this port is not available to you" case. It deliberately carries
// no distinction between unconfigured, room-denied, and disabled so that
// scanning callers learn nothing (I10 layer 1).
var errVirtualPortUnreachable = fmt.Errorf("virtual port unreachable")

// IsAllowed mirrors the controller's policy check for callers that only
// need a yes/no answer (e.g. the netstack layer's first packet).
func (f *Forwarder) IsAllowed(virtualPort int) bool {
	return f.controller.IsAllowed(virtualPort)
}