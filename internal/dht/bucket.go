package dht

import (
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// Bucket capacity from the design (§16.5): k = 20.
const K = 20

// bucket holds up to K nodes that share a common-prefix length with the
// local node. Order is most-recently-seen last, so the head is always the
// least-recently-seen candidate for eviction (classic Kademlia).
type bucket struct {
	entries []*Node
}

// index returns the position of a node by ID, or -1.
func (b *bucket) index(id types.NodeID) int {
	for i, n := range b.entries {
		if n.ID == id {
			return i
		}
	}
	return -1
}

// seen records a successful exchange with an existing node: move it to the
// tail and refresh LastSeen.
func (b *bucket) seen(idx int, now time.Time) {
	n := b.entries[idx]
	n.LastSeen = now
	b.entries = append(b.entries[:idx], b.entries[idx+1:]...)
	b.entries = append(b.entries, n)
}

// push adds a node as most-recently-seen (tail).
func (b *bucket) push(n *Node) {
	b.entries = append(b.entries, n)
}

// full reports whether the bucket is at capacity.
func (b *bucket) full() bool {
	return len(b.entries) >= K
}

// leastRecentlySeen returns the head (eviction candidate) without removing.
func (b *bucket) leastRecentlySeen() *Node {
	if len(b.entries) == 0 {
		return nil
	}
	return b.entries[0]
}

// remove deletes a node by ID, returning whether it existed.
func (b *bucket) remove(id types.NodeID) bool {
	i := b.index(id)
	if i < 0 {
		return false
	}
	b.entries = append(b.entries[:i], b.entries[i+1:]...)
	return true
}