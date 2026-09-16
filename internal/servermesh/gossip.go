package servermesh

// gossip.go holds the gossip message types and protocol logic.
// The actual wire-level gossip protocol will be implemented in a
// later phase. The framing was completed in the P1 baseline; the
// mesh currently uses periodic full-table pushes over the
// bootstrap control-plane connection.

// GossipMessage represents a table update notification.
type GossipMessage struct {
	Type    string        // "full" | "incremental"
	Servers []ServerEntry // full or changed entries
}

// GossipEvent represents a single table change event.
type GossipEvent struct {
	Action string // "add" | "remove" | "update"
	Entry  ServerEntry
}
