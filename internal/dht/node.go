package dht

import (
	"time"

	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"
)

// Node is one entry in a routing table: the peer's identifier, its DHT key,
// and the endpoint the transport layer needs to reach it.
type Node struct {
	ID   types.NodeID
	Key  Key
	Addr string // transport endpoint (dial string); opaque to the DHT

	// LastSeen is bumped on every successful exchange and is what
	// eviction (§16.5 失效) sorts by.
	LastSeen time.Time
}
