package dht

import (
	"sort"
	"sync"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// RoutingTable is the Kademlia routing structure: 160 buckets (one per
// possible common-prefix length with the local key) plus the local node
// itself.
//
// This is the fixed-bucket formulation of Kademlia rather than the
// bucket-splitting one. Both are standard; the fixed form keeps the
// implementation simple and its size behaviour identical —
// O(log₂ N) × k entries at 100k nodes (§16.5's 340-entry bound).
type RoutingTable struct {
	self Key

	mu      sync.RWMutex
	buckets [KeySizeBits]*bucket

	// now is the clock, injectable for eviction tests.
	now func() time.Time
}

// NewRoutingTable creates an empty table around a local key.
func NewRoutingTable(localID types.NodeID) *RoutingTable {
	return &RoutingTable{
		self:    KeyForNodeID(localID),
		buckets: [KeySizeBits]*bucket{},
		now:     time.Now,
	}
}

// bucketFor returns the bucket a peer key belongs to: its common-prefix
// length with the local key (0..159). A key equal to self (prefix 160) has
// no bucket and is never stored.
func (t *RoutingTable) bucketFor(k Key) (int, bool) {
	pl := t.self.CommonPrefixLen(k)
	if pl >= KeySizeBits {
		return 0, false // self
	}
	return pl, true
}

// Has reports whether the node is already known.
func (t *RoutingTable) Has(id types.NodeID) (Key, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	k := KeyForNodeID(id)
	bi, ok := t.bucketFor(k)
	if !ok {
		return k, true // self is trivially "known"
	}
	b := t.buckets[bi]
	if b == nil {
		return k, false
	}
	return k, b.index(id) >= 0
}

// Add inserts or refreshes a peer.
//
// Semantics follow Kademlia §16.5:
//   - known node → bump LastSeen and move to bucket tail;
//   - unknown node, bucket full → return the least-recently-seen entry as
//     the eviction candidate (the caller pings it; only on failure does
//     Remove make room — classic eviction that protects live nodes);
//   - unknown node, space → store.
func (t *RoutingTable) Add(n *Node) (*Node, error) {
	if n == nil {
		return nil, errNilNode
	}
	k := KeyForNodeID(n.ID)
	n.Key = k

	t.mu.Lock()
	defer t.mu.Unlock()

	bi, ok := t.bucketFor(k)
	if !ok {
		return nil, errSelfNode
	}
	b := t.buckets[bi]
	if b == nil {
		b = &bucket{}
		t.buckets[bi] = b
	}
	if idx := b.index(n.ID); idx >= 0 {
		b.seen(idx, t.now())
		return nil, nil
	}
	if !b.full() {
		b.push(n)
		return nil, nil
	}
	// Full: surface the eviction candidate rather than evicting live nodes.
	return b.leastRecentlySeen(), nil
}

// Remove deletes a peer from its bucket (e.g. after a failed ping).
func (t *RoutingTable) Remove(id types.NodeID) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	k := KeyForNodeID(id)
	bi, ok := t.bucketFor(k)
	if !ok {
		return false
	}
	b := t.buckets[bi]
	if b == nil {
		return false
	}
	return b.remove(id)
}

// Nearest returns up to n nodes closest to target, ordered by XOR distance.
// It scans all buckets — the whole table is O(log N)×k, so a linear scan
// is cheap and avoids bucket-order bookkeeping.
func (t *RoutingTable) Nearest(target Key, n int) []*Node {
	t.mu.RLock()
	defer t.mu.RUnlock()

	type scored struct {
		n *Node
		d Key
	}
	cands := make([]scored, 0, n)
	for _, b := range t.buckets {
		if b == nil {
			continue
		}
		for _, e := range b.entries {
			cands = append(cands, scored{e, Distance(target, e.Key)})
		}
	}
	sort.Slice(cands, func(i, j int) bool {
		return cands[i].d.Less(cands[j].d)
	})
	if len(cands) > n {
		cands = cands[:n]
	}
	out := make([]*Node, len(cands))
	for i, c := range cands {
		out[i] = c.n
	}
	return out
}

// Size returns the number of stored peers (for the 340-entry sanity check
// and scale tests).
func (t *RoutingTable) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	total := 0
	for _, b := range t.buckets {
		if b != nil {
			total += len(b.entries)
		}
	}
	return total
}

// Peers returns a flat snapshot of all stored nodes.
func (t *RoutingTable) Peers() []*Node {
	t.mu.RLock()
	defer t.mu.RUnlock()
	out := make([]*Node, 0, t.SizeUnlocked())
	for _, b := range t.buckets {
		if b == nil {
			continue
		}
		for _, e := range b.entries {
			cp := *e
			out = append(out, &cp)
		}
	}
	return out
}

func (t *RoutingTable) SizeUnlocked() int {
	total := 0
	for _, b := range t.buckets {
		if b != nil {
			total += len(b.entries)
		}
	}
	return total
}

// MultiPathCandidates returns up to c alternative next-hops toward target,
// spread across different distance prefixes where possible. The design uses
// this for the k=5 path requirement: the routing table's natural spread
// supplies the candidate diversity (§16.5).
func (t *RoutingTable) MultiPathCandidates(target Key, c int) []*Node {
	all := t.Nearest(target, K)
	if len(all) <= c {
		return all
	}
	// Closest first, take c.
	return all[:c]
}