// Package dht implements the Kademlia routing used for peer discovery.
//
// Per DESIGN.md §16.5, the DHT is a *discovery* layer only: it locates
// nodes, it never forwards payloads. Data paths take the shortest reachable
// route among discovered candidates — using DHT hop-by-hop for traffic is
// explicitly forbidden in the design.
//
// Mapping of Kademlia primitives to this scheme:
//
//	k             = 20    (bucket capacity)
//	alpha         = 3     (lookup parallelism)
//	key space     = 160 bits, derived by SHA-1 of the NodeID
//	table size    = O(log₂ N) × k ≈ 340 entries at 100k nodes
//	lookup hops   = O(log₂ N), worst ~17
//
// The DHT carries no authority: lookups only answer "who is close to this
// key" (an observation, not a judgement), which keeps invariants I2 and I3
// intact.
package dht

import (
	"crypto/sha256"
	"fmt"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// KeySize is the DHT key width in bits (160).
const KeySizeBits = 160

// Key is a 160-bit DHT key (20 bytes).
type Key [20]byte

// KeyForNodeID derives a node's DHT key from its NodeID.
//
// The NodeID alphabet (base32, 26 chars) does not cover the full key width
// by itself; hashing it into the key space gives every node a well-spread,
// deterministic identifier. SHA-256 is truncated to 160 bits here — this is
// a *routing* spread (no security property rides on it: authentication and
// encryption live in the Noise/Ed25519 layers), but a modern hash is used
// anyway so no deprecated primitive appears anywhere in the codebase.
func KeyForNodeID(id types.NodeID) Key {
	var out Key
	sum := sha256.Sum256([]byte(id.String()))
	copy(out[:], sum[:20])
	return out
}

// Xor returns a ^ b.
func (k Key) Xor(o Key) Key {
	var out Key
	for i := range out {
		out[i] = k[i] ^ o[i]
	}
	return out
}

// Bit returns the bit (0 = most significant) of the key.
func (k Key) Bit(i int) bool {
	return k[i/8]&(1<<uint(7-i%8)) != 0
}

// CommonPrefixLen counts the leading bits two keys share.
func (k Key) CommonPrefixLen(o Key) int {
	x := k.Xor(o)
	shared := 0
	for i := 0; i < KeySizeBits; i++ {
		if x.Bit(i) {
			return shared
		}
		shared++
	}
	return shared
}

// Less reports whether k is numerically closer to zero than o (used for
// bucket ordering; the distance metric lives in Distance).
func (k Key) Less(o Key) bool {
	for i := 0; i < len(k); i++ {
		if k[i] != o[i] {
			return k[i] < o[i]
		}
	}
	return false
}

// Distance returns the XOR distance between two keys, big-endian, so that
// byte-wise comparison orders keys by distance.
func Distance(a, b Key) Key {
	return a.Xor(b)
}

// String renders the key in hex for logs.
func (k Key) String() string {
	const hexdigits = "0123456789abcdef"
	var buf [40]byte
	for i, b := range k {
		buf[i*2] = hexdigits[b>>4]
		buf[i*2+1] = hexdigits[b&0xF]
	}
	return string(buf[:])
}

// ParseKey decodes a 40-char hex string back into a Key.
func ParseKey(s string) (Key, error) {
	var k Key
	if len(s) != 40 {
		return k, fmt.Errorf("dht: key string must be 40 hex chars, got %d", len(s))
	}
	for i := 0; i < 20; i++ {
		hi, err := hexVal(s[i*2])
		if err != nil {
			return k, err
		}
		lo, err := hexVal(s[i*2+1])
		if err != nil {
			return k, err
		}
		k[i] = hi<<4 | lo
	}
	return k, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("dht: invalid hex char %q", rune(c))
}
