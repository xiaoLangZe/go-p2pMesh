// Package dns — DNS wire codec.
//
// Implements the bare minimum of RFC 1035 needed for a resolver shim:
// parsing a query (header + one question), and building a reply carrying
// A and AAAA answers, NXDOMAIN, or an empty answer section. No compression
// on write; name pointers on read are followed for the standard
// back-reference case. Kept deliberately small: the proxy answers one
// question at a time.
package dns

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
)

// Record types and classes supported on the wire.
const (
	TypeA    = 1
	TypeAAAA = 28
	ClassIN  = 1

	rcodeNoError  = 0
	rcodeServFail = 2
	rcodeNXDomain = 3

	flagQR = 0x8000
	flagRD = 0x0100
	flagRA = 0x0080
)

// Query is a decoded DNS query: the ID to echo, the question, and the
// recursion-desired flag.
type Query struct {
	ID      uint16
	QName   string
	QType   uint16
	QClass  uint16
	WantRec bool
}

// ParseQuery decodes a DNS query from a UDP datagram. It accepts exactly
// one question, which is all the proxy answers.
func ParseQuery(pkt []byte) (*Query, error) {
	if len(pkt) < 12 {
		return nil, errors.New("dns: packet shorter than header")
	}
	q := &Query{ID: binary.BigEndian.Uint16(pkt[0:2])}
	if binary.BigEndian.Uint16(pkt[4:6]) != 1 {
		return nil, errors.New("dns: proxy requires exactly one question")
	}
	q.WantRec = binary.BigEndian.Uint16(pkt[2:4])&flagRD != 0

	name, off, err := decodeName(pkt, 12)
	if err != nil {
		return nil, err
	}
	q.QName = name
	if off+4 > len(pkt) {
		return nil, errors.New("dns: truncated question")
	}
	q.QType = binary.BigEndian.Uint16(pkt[off : off+2])
	q.QClass = binary.BigEndian.Uint16(pkt[off+2 : off+4])
	return q, nil
}

// decodeName reads a possibly-compressed name starting at off.
// Returns the dotted name and the offset just past it.
func decodeName(pkt []byte, off int) (string, int, error) {
	var labels []string
	for {
		if off >= len(pkt) {
			return "", 0, errors.New("dns: name runs past end")
		}
		l := int(pkt[off])
		switch {
		case l == 0:
			return join(labels), off + 1, nil
		case l&0xC0 == 0xC0: // compression pointer
			if off+1 >= len(pkt) {
				return "", 0, errors.New("dns: truncated pointer")
			}
			ptr := int(binary.BigEndian.Uint16(pkt[off:off+2]) & 0x3FFF)
			tail, _, err := decodeName(pkt, ptr)
			if err != nil {
				return "", 0, err
			}
			labels = append(labels, tail)
			return join(labels), off + 2, nil
		case l&0xC0 != 0:
			return "", 0, errors.New("dns: unsupported label type")
		}
		off++
		if off+l > len(pkt) {
			return "", 0, errors.New("dns: label runs past end")
		}
		labels = append(labels, string(pkt[off:off+l]))
		off += l
	}
}

func join(labels []string) string {
	return strings.Join(labels, ".")
}

// BuildReply constructs an answer for a query.
//
// ips == nil → NXDOMAIN (name does not exist / node unknown).
// ips non-empty → NOERROR with one A/AAAA record per address of the
// question's family; a name that exists but has no record of that type
// yields an empty answer section (RFC-correct "name exists, type absent").
func BuildReply(q *Query, ips []net.IP) []byte {
	rcode := rcodeNoError
	if ips == nil {
		rcode = rcodeNXDomain
	}

	// Keep only answers matching the question family.
	var answers []net.IP
	if ips != nil {
		for _, ip := range ips {
			ip = ip.To16()
			if ip == nil {
				continue
			}
			if q.QType == TypeA && ip.To4() != nil {
				answers = append(answers, ip.To4())
			} else if q.QType == TypeAAAA && ip.To4() == nil {
				answers = append(answers, ip)
			}
		}
	}

	rdlen := 4
	if q.QType == TypeAAAA {
		rdlen = 16
	}

	// Header: ID, flags, one question, N answers.
	flags := flagQR | flagRA | uint16(rcode)
	if q.WantRec {
		flags |= flagRD
	}
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], q.ID)
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	binary.BigEndian.PutUint16(hdr[4:6], 1)             // QDCOUNT
	binary.BigEndian.PutUint16(hdr[6:8], uint16(len(answers))) // ANCOUNT

	// Question section: the original name uncompressed.
	out := append(hdr, encodeName(q.QName)...)
	out = binary.BigEndian.AppendUint16(out, q.QType)
	out = binary.BigEndian.AppendUint16(out, q.QClass)

	// Answers: name as a back-pointer to offset 12, then type/class/ttl/rdlen/rdata.
	for _, ip := range answers {
		out = append(out, 0xC0, 0x0C)
		out = binary.BigEndian.AppendUint16(out, q.QType)
		out = binary.BigEndian.AppendUint16(out, ClassIN)
		out = binary.BigEndian.AppendUint32(out, 60) // short TTL: mesh addresses migrate
		out = binary.BigEndian.AppendUint16(out, uint16(rdlen))
		for _, b := range ip {
			out = append(out, b)
		}
	}
	return out
}

// BuildServFail constructs a SERVFAIL reply for a query whose resolution
// path errored.
func BuildServFail(q *Query) []byte {
	flags := flagQR | uint16(rcodeServFail)
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], q.ID)
	binary.BigEndian.PutUint16(hdr[2:4], flags)
	out := append(hdr, encodeName(q.QName)...)
	out = binary.BigEndian.AppendUint16(out, q.QType)
	out = binary.BigEndian.AppendUint16(out, q.QClass)
	return out
}

// encodeName writes a dotted name in uncompressed wire format.
func encodeName(name string) []byte {
	if name == "" {
		return []byte{0}
	}
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out
}