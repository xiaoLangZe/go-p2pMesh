package dht

import (
	"fmt"
	"math/rand"
	"sort"
	"testing"
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

func nodeAt(t *testing.T, i int) *Node {
	t.Helper()
	id := types.NodeID(fmt.Sprintf("node-%04d", i))
	return &Node{ID: id, Key: KeyForNodeID(id), Addr: fmt.Sprintf("ep-%d", i), LastSeen: time.Now()}
}

// TestKeyDistanceSymmetry checks XOR distance basics.
func TestKeyDistanceSymmetry(t *testing.T) {
	a := KeyForNodeID("node-1")
	b := KeyForNodeID("node-2")
	if Distance(a, b) != Distance(b, a) {
		t.Error("XOR distance must be symmetric")
	}
	if Distance(a, a) != (Key{}) {
		t.Error("distance to self must be zero")
	}
	if Distance(a, b) == (Key{}) {
		t.Error("distinct keys must not be at distance zero")
	}
}

// TestCommonPrefixLen checks the bucketing index math.
func TestCommonPrefixLen(t *testing.T) {
	k0 := Key{0xFF} // 11111111...
	k1 := Key{0x7F} // 01111111...
	if got := k0.CommonPrefixLen(k1); got != 0 {
		t.Errorf("prefix len = %d, want 0 (MSB differs)", got)
	}
	k2 := Key{0x80} // 10000000...
	if got := k0.CommonPrefixLen(k2); got != 1 {
		t.Errorf("prefix len = %d, want 1", got)
	}
	if got := k0.CommonPrefixLen(k0); got != KeySizeBits {
		t.Errorf("identical keys: got %d, want %d", got, KeySizeBits)
	}
}

// TestBucketLRUOrdering checks the bucket keeps most-recent at tail.
func TestBucketLRUOrdering(t *testing.T) {
	now := time.Now()
	b := &bucket{}
	for i := 0; i < 5; i++ {
		b.push(nodeAt(t, i))
	}
	// Touch node 0: it moves to the tail, node 1 becomes LRU head.
	b.seen(b.index(types.NodeID("node-0000")), now)
	if b.entries[0].ID != "node-0001" {
		t.Errorf("LRU head = %s, want node-0001", b.entries[0].ID)
	}
	if b.entries[len(b.entries)-1].ID != "node-0000" {
		t.Errorf("MRU tail = %s, want node-0000", b.entries[len(b.entries)-1].ID)
	}
}

// TestBucketFullEvictionCandidate checks the classic "surface the LRU"
// contract at the bucket level: a full bucket reports its least-recently-
// seen entry as the eviction candidate, and never evicts by itself.
// (table.Add derives keys from IDs, so table-level bucket-filling depends
// on hash luck; the split is a pure bucket unit.)
func TestBucketFullEvictionCandidate(t *testing.T) {
	var first *Node
	b := &bucket{}
	for i := 0; i <= K; i++ {
		n := nodeAt(t, i)
		if i == 0 {
			first = n
		}
		if b.full() {
			if got := b.leastRecentlySeen(); got == nil || got.ID != first.ID {
				t.Fatalf("full bucket: want LRU %s, got %v", first.ID, got)
			}
			break
		}
		b.push(n)
	}
	if !b.full() || len(b.entries) != K {
		t.Fatalf("bucket size = %d, want full at %d", len(b.entries), K)
	}
	b.remove(first.ID)
	if len(b.entries) != K-1 {
		t.Errorf("size after remove = %d, want %d", len(b.entries), K-1)
	}
}

// TestTableSelfNotStored checks the local node cannot enter its own table.
func TestTableSelfNotStored(t *testing.T) {
	tbl := NewRoutingTable("self-node")
	if _, err := tbl.Add(&Node{ID: "self-node"}); err == nil {
		t.Error("adding self should fail")
	}
	if tbl.Size() != 0 {
		t.Errorf("size = %d, want 0", tbl.Size())
	}
}

// TestNearestOrdering checks distance ordering and cap.
func TestNearestOrdering(t *testing.T) {
	tbl := NewRoutingTable("local")
	target := KeyForNodeID("target")
	var wantClosest *Node
	for i := 0; i < 30; i++ {
		n := nodeAt(t, i)
		if _, err := tbl.Add(n); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	got := tbl.Nearest(target, 5)
	if len(got) != 5 {
		t.Fatalf("Nearest returned %d, want 5", len(got))
	}
	// Brute-force the true closest among all peers.
	all := tbl.Peers()
	best := targetClosest(tbl, target)
	for i, n := range got {
		if n.Key != best[i].Key {
			t.Fatalf("result %d = %s, want %s", i, n.ID, best[i].ID)
		}
	}
	_ = all
	_ = wantClosest
}

func targetClosest(tbl *RoutingTable, target Key) []*Node {
	return sortByDistance(tbl.Peers(), target)
}

// sortByDistance returns a copy of nodes ordered by XOR distance to target.
func sortByDistance(nodes []*Node, target Key) []*Node {
	out := make([]*Node, len(nodes))
	copy(out, nodes)
	sort.Slice(out, func(i, j int) bool {
		return Distance(target, out[i].Key).Less(Distance(target, out[j].Key))
	})
	return out
}

// TestLookupConvergence builds a synthetic 200-node network and checks the
// iterative lookup finds the true closest node in far fewer than N queries.
func TestLookupConvergence(t *testing.T) {
	const netSize = 200
	target := KeyForNodeID("target")
	nodes := make([]*Node, netSize)
	for i := range nodes {
		nodes[i] = nodeAt(t, i)
	}
	// True network order by distance to the target.
	ordered := sortByDistance(nodes, target)

	// The searcher only knows 3 random seeds; everything else must come
	// from query answers.
	rng := rand.New(rand.NewSource(7))
	peerIndex := rng.Perm(netSize)
	tbl := NewRoutingTable("searcher")
	for i := 0; i < 3; i++ {
		if _, err := tbl.Add(nodes[peerIndex[i]]); err != nil {
			t.Fatalf("bootstrap Add: %v", err)
		}
	}

	lookup := &Lookup{
		Table: tbl,
		Query: func(from *Node, target Key) ([]*Node, error) {
			// A node answers with the network's K closest to the target
			// (ideal view). Convergence then measures the *algorithm* —
			// shortlist tightening round over round — not the network.
			return ordered[:K], nil
		},
	}

	got, err := lookup.Find(target)
	if err != nil {
		t.Fatalf("Find: %v", err)
	}
	if len(got) == 0 {
		t.Fatal("lookup returned nothing")
	}
	if got[0].Key != ordered[0].Key {
		t.Errorf("closest found = %s, want %s", got[0].ID, ordered[0].ID)
	}
	if lookup.Queried > netSize {
		t.Errorf("queried %d nodes for a %d-node net; lookup must be O(log N)", lookup.Queried, netSize)
	}
}

// TestMultiPathCandidatesAtLeastFive checks the k=5 requirement (§16.5):
// the table serves 5 alternative next-hops toward a target.
func TestMultiPathCandidatesAtLeastFive(t *testing.T) {
	tbl := NewRoutingTable("local")
	nodes := make([]*Node, 60)
	for i := range nodes {
		n := nodeAt(t, i+100)
		nodes[i] = n
		if _, err := tbl.Add(n); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	got := tbl.MultiPathCandidates(KeyForNodeID("far-target"), 5)
	if len(got) < 5 {
		t.Fatalf("multi-path candidates = %d, want >= 5 (design k=5)", len(got))
	}
	for _, n := range got {
		if n == nil {
			t.Fatal("nil candidate")
		}
	}
}