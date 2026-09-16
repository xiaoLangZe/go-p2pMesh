package dht

import (
	"errors"
	"sort"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// LookupParams carries the tunables of an iterative Kademlia lookup.
// Defaults match the design: alpha = 3, k = K = 20.
type LookupParams struct {
	Alpha     int // concurrent queries per round
	K         int // number of closest nodes to converge on
	MaxRounds int // safety bound (0 = derive: KeySizeBits)
}

func (p LookupParams) withDefaults() LookupParams {
	if p.Alpha <= 0 {
		p.Alpha = 3
	}
	if p.K <= 0 {
		p.K = K
	}
	if p.MaxRounds <= 0 {
		p.MaxRounds = KeySizeBits
	}
	return p
}

// Lookup is the iterative closest-nodes search (§16.5: key → node).
//
// It starts from the local table's closest candidates, queries up to Alpha
// of them per round in parallel, feeds their responses back in, and stops
// when no round returns a closer node than the current best set. Query
// abstracts the transport (a control-plane RPC in production, an injectable
// map for tests).
type Lookup struct {
	Table  *RoutingTable
	Query  func(from *Node, target Key) ([]*Node, error)
	Params LookupParams

	// Queried counts the queries issued (hop accounting for §22.4's
	// convergence measurements).
	Queried int
}

// Find returns up to K closest nodes to target discovered by the queried
// part of the network, in distance order. It never returns the local node.
func (l *Lookup) Find(target Key) ([]*Node, error) {
	if l.Query == nil {
		return nil, errors.New("dht: lookup has no Query function")
	}
	if l.Table == nil {
		return nil, errors.New("dht: lookup has no routing table")
	}
	p := l.Params.withDefaults()

	best := l.Table.Nearest(target, p.K)
	// Drop self if the table somehow included it (it cannot, but be safe).
	best = filterSelf(best, l.Table.self)

	queried := make(map[types.NodeID]bool)

	for round := 0; round < p.MaxRounds; round++ {
		todo := make([]*Node, 0, p.Alpha)
		for _, n := range best {
			if queried[n.ID] {
				continue
			}
			todo = append(todo, n)
			if len(todo) == p.Alpha {
				break
			}
		}
		if len(todo) == 0 {
			break
		}

		type resp struct{ nodes []*Node }
		results := make(chan resp, len(todo))
		for _, n := range todo {
			queried[n.ID] = true
			l.Queried++
			go func(from *Node) {
				nodes, _ := l.Query(from, target)
				results <- resp{nodes}
			}(n)
		}

		progressed := false
		for range todo {
			r := <-results
			for _, n := range r.nodes {
				if n == nil || queried[n.ID] {
					continue
				}
				if n.Key == l.Table.self {
					continue // local node is never a candidate
				}
				best = mergeBest(best, n, target, p.K)
				progressed = true
			}
		}
		if !progressed {
			break
		}
	}
	return best, nil
}

func filterSelf(nodes []*Node, self Key) []*Node {
	out := nodes[:0:0]
	for _, n := range nodes {
		if n.Key == self {
			continue
		}
		out = append(out, n)
	}
	return out
}

// mergeBest inserts one node into a distance-sorted cap-K shortlist.
func mergeBest(best []*Node, n *Node, target Key, cap int) []*Node {
	for _, e := range best {
		if e.ID == n.ID {
			return best
		}
	}
	best = append(best, n)
	sort.Slice(best, func(i, j int) bool {
		return Distance(target, best[i].Key).Less(Distance(target, best[j].Key))
	})
	if len(best) > cap {
		best = best[:cap]
	}
	return best
}