package dns

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

// testView is a View backed by a map.
type testView map[string][2]string // nodeID -> (ipv6, ipv4)

func (v testView) Lookup(nodeID string) (string, string, bool) {
	a, ok := v[nodeID]
	if !ok {
		return "", "", false
	}
	return a[0], a[1], true
}

// testUpstream returns fixed IPs.
type testUpstream struct {
	ips []net.IP
}

func (u testUpstream) LookupIP(host string) ([]net.IP, error) {
	return u.ips, nil
}

// TestResolveNodeByName checks `[id].xiaolangze` → addresses.
func TestResolveNodeByName(t *testing.T) {
	view := testView{
		"a3f9k2m8-7p1q": {"fd00:9bd8::a3f9", "240.0.0.10"},
	}
	r := NewResolver(view)
	ips, err := r.Resolve("a3f9k2m8-7p1q.xiaolangze")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("got %d addresses, want 2", len(ips))
	}
	if ips[0].String() != "fd00:9bd8::a3f9" {
		t.Errorf("ipv6 = %s, want fd00:9bd8::a3f9", ips[0])
	}
	if ips[1].String() != "240.0.0.10" {
		t.Errorf("ipv4 = %s, want 240.0.0.10", ips[1])
	}
}

// TestResolveNodeUnknown checks NXDOMAIN semantics.
func TestResolveNodeUnknown(t *testing.T) {
	r := NewResolver(testView{})
	_, err := r.Resolve("nosuch.xiaolangze")
	if err == nil {
		t.Fatal("expected error for unknown node")
	}
	if !isNXDomainErr(err) {
		t.Errorf("unknown-node error should map to NXDOMAIN, got: %v", err)
	}
}

// TestResolveBadMeshName checks malformed mesh names are refused.
func TestResolveBadMeshName(t *testing.T) {
	r := NewResolver(testView{})
	for _, name := range []string{
		"a.b.xiaolangze", // more than one label
		".xiaolangze",    // empty label
	} {
		if _, err := r.Resolve(name); err == nil {
			t.Errorf("%q should be refused", name)
		}
	}
}

// TestResolveUpstream checks passthrough.
func TestResolveUpstream(t *testing.T) {
	want := []net.IP{net.ParseIP("9.9.9.9")}
	r := NewResolver(testView{})
	r.upstream = testUpstream{ips: want}
	ips, err := r.Resolve("example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(ips) != 1 || !ips[0].Equal(want[0]) {
		t.Errorf("ips = %v, want %v", ips, want)
	}
}

// TestParseQueryRoundTrip builds a query on the wire and parses it back.
func TestParseQueryRoundTrip(t *testing.T) {
	name := encodeName("a3f9k2m8-7p1q.xiaolangze")
	pkt := make([]byte, 12+len(name)+4)
	binary.BigEndian.PutUint16(pkt[0:2], 0x4242) // ID
	binary.BigEndian.PutUint16(pkt[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(pkt[4:6], 1)      // QDCOUNT
	copy(pkt[12:], name)
	binary.BigEndian.PutUint16(pkt[12+len(name):], TypeAAAA)
	binary.BigEndian.PutUint16(pkt[12+len(name)+2:], ClassIN)

	q, err := ParseQuery(pkt)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	if q.ID != 0x4242 {
		t.Errorf("ID = %#x, want 0x4242", q.ID)
	}
	if q.QName != "a3f9k2m8-7p1q.xiaolangze" {
		t.Errorf("QName = %q", q.QName)
	}
	if q.QType != TypeAAAA {
		t.Errorf("QType = %d, want AAAA", q.QType)
	}
	if !q.WantRec {
		t.Error("RD flag not parsed")
	}
}

// TestBuildReplyA checks A-record construction.
func TestBuildReplyA(t *testing.T) {
	q := &Query{ID: 7, QName: "node.xiaolangze", QType: TypeA, QClass: ClassIN, WantRec: true}
	reply := BuildReply(q, []net.IP{
		net.ParseIP("240.0.0.10"),     // v4: kept
		net.ParseIP("fd00:9bd8::10"),  // v6: filtered out for TypeA
	})
	if len(reply) < 12 {
		t.Fatal("reply too short")
	}
	if binary.BigEndian.Uint16(reply[0:2]) != 7 {
		t.Error("ID not echoed")
	}
	if binary.BigEndian.Uint16(reply[2:4])&0x000F != rcodeNoError {
		t.Error("rcode != NOERROR")
	}
	if an := binary.BigEndian.Uint16(reply[6:8]); an != 1 {
		t.Errorf("ANCOUNT = %d, want 1", an)
	}
}

// TestBuildReplyNXDomain checks NXDOMAIN construction.
func TestBuildReplyNXDomain(t *testing.T) {
	q := &Query{ID: 9, QName: "nosuch.xiaolangze", QType: TypeA, QClass: ClassIN}
	reply := BuildReply(q, nil)
	if rcode := binary.BigEndian.Uint16(reply[2:4]) & 0x000F; rcode != rcodeNXDomain {
		t.Errorf("rcode = %d, want NXDOMAIN(%d)", rcode, rcodeNXDomain)
	}
	if an := binary.BigEndian.Uint16(reply[6:8]); an != 0 {
		t.Errorf("NXDOMAIN ANCOUNT = %d, want 0", an)
	}
}

// TestBuildReplyAAAA checks IPv6 answers.
func TestBuildReplyAAAA(t *testing.T) {
	q := &Query{ID: 1, QName: "node.xiaolangze", QType: TypeAAAA, QClass: ClassIN}
	reply := BuildReply(q, []net.IP{net.ParseIP("fd00:9bd8::10")})
	if an := binary.BigEndian.Uint16(reply[6:8]); an != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", an)
	}
	// Walk to the RDATA: question section then answer header.
	off := 12
	for off < len(reply) && reply[off] != 0 {
		off += int(reply[off]) + 1
	}
	off += 1 + 4 // null label + qtype(2) + qclass(2)
	off += 2     // pointer
	// answer type, class, ttl, rdlength
	if binary.BigEndian.Uint16(reply[off:off+2]) != TypeAAAA {
		t.Error("answer type != AAAA")
	}
	rdlen := binary.BigEndian.Uint16(reply[off+8 : off+10])
	if rdlen != 16 {
		t.Errorf("AAAA rdlength = %d, want 16", rdlen)
	}
}

// TestProxyEndToEnd runs a live DNS query through the proxy on an ephemeral port.
func TestProxyEndToEnd(t *testing.T) {
	view := testView{"peer-1": {"fd00:9bd8::42", "240.0.0.42"}}
	r := NewResolver(view)
	p := NewProxy(r, nil)
	if err := p.Start("127.0.0.1:0"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer p.Close()
	addr := p.conn.LocalAddr().String()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = p.Serve(ctx)
	}()

	// Wait for Serve to enter its loop.
	time.Sleep(50 * time.Millisecond)

	// Build a query for peer-1.xiaolangze AAAA.
	name := encodeName("peer-1.xiaolangze")
	pkt := make([]byte, 12+len(name)+4)
	binary.BigEndian.PutUint16(pkt[0:2], 0x7777)
	binary.BigEndian.PutUint16(pkt[2:4], flagRD)
	binary.BigEndian.PutUint16(pkt[4:6], 1)
	copy(pkt[12:], name)
	binary.BigEndian.PutUint16(pkt[12+len(name):], TypeAAAA)
	binary.BigEndian.PutUint16(pkt[14+len(name):], ClassIN)

	conn, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write(pkt); err != nil {
		t.Fatalf("Write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n < 12 {
		t.Fatalf("reply too short: %d", n)
	}
	if rcode := binary.BigEndian.Uint16(buf[2:4]) & 0x000F; rcode != rcodeNoError {
		t.Errorf("rcode = %d, want 0", rcode)
	}
	if an := binary.BigEndian.Uint16(buf[6:8]); an != 1 {
		t.Errorf("ANCOUNT = %d, want 1", an)
	}
}