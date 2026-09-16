package dns

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"sync"
)

// Proxy is a UDP DNS proxy bound to a loopback port. It answers `.xiaolangze`
// queries from the Resolver and forwards everything else upstream.
type Proxy struct {
	conn     *net.UDPConn
	resolver *Resolver
	logger   *slog.Logger

	mu     sync.Mutex
	closed bool
}

// NewProxy creates a proxy but does not bind yet; call Start.
func NewProxy(resolver *Resolver, logger *slog.Logger) *Proxy {
	if logger == nil {
		logger = slog.Default()
	}
	return &Proxy{resolver: resolver, logger: logger}
}

// Start binds to 127.0.0.1:53 (root needed for the privileged port; callers
// may pass a different port through Bind for tests or non-root use).
func (p *Proxy) Start(addr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return err
	}
	p.conn = conn
	p.logger.Info("dns proxy listening", "addr", addr)
	return nil
}

// Serve runs the query loop until Close. Each query is answered from the
// current calling goroutine's read; slow upstreams could stall the loop,
// so upstream resolution is bounded by the resolver's own timeouts.
func (p *Proxy) Serve(ctx context.Context) error {
	if p.conn == nil {
		return errors.New("dns proxy not started")
	}
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		n, peer, err := p.conn.ReadFromUDP(buf)
		if err != nil {
			if p.isClosed() {
				return nil
			}
			p.logger.Debug("dns read", "err", err)
			continue
		}
		go p.handle(peer, append([]byte(nil), buf[:n]...))
	}
}

func (p *Proxy) handle(peer *net.UDPAddr, pkt []byte) {
	q, err := ParseQuery(pkt)
	if err != nil {
		p.logger.Debug("dns parse", "err", err, "peer", peer)
		return // unparseable query: drop, like a real server
	}
	ips, resolveErr := p.resolver.Resolve(q.QName)
	var reply []byte
	switch {
	case resolveErr != nil && isNXDomainErr(resolveErr):
		reply = BuildReply(q, nil)
	case resolveErr != nil:
		p.logger.Debug("dns resolve", "err", resolveErr, "name", q.QName)
		reply = BuildServFail(q)
	default:
		reply = BuildReply(q, ips)
	}
	if _, err := p.conn.WriteToUDP(reply, peer); err != nil {
		p.logger.Debug("dns write", "err", err)
	}
}

// Close stops the proxy.
func (p *Proxy) Close() error {
	p.mu.Lock()
	p.closed = true
	p.mu.Unlock()
	if p.conn != nil {
		return p.conn.Close()
	}
	return nil
}

func (p *Proxy) isClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.closed
}

// isNXDomainErr reports whether a resolve failure should surface as
// NXDOMAIN. Node-unknown and malformed-mesh-name errors map to NXDOMAIN;
// upstream failures map to SERVFAIL.
func isNXDomainErr(err error) bool {
	msg := err.Error()
	// The Resolver distinguishes node errors by phrasing; anything that is
	// a "name problem" (node unknown, bad node name) is NXDOMAIN. All
	// other errors (upstream failure, no address) are SERVFAIL or empty.
	return containsAny(msg,
		"not known (or not in this room)",
		"not a node name")
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if len(sub) > 0 && len(s) >= len(sub) {
			found := false
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					found = true
					break
				}
			}
			if found {
				return true
			}
		}
	}
	return false
}