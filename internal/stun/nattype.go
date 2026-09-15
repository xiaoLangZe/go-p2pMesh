// Package stun implements the STUN client and NAT type detection.
// Only a STUN client is implemented — the project never runs a STUN server.
package stun

// NATType enumerates the NAT classification results.
type NATType string

const (
	// NATOpen means the node has a public IP (no NAT).
	NATOpen NATType = "Open"
	// NATFullCone: any external host can send to the mapped port.
	NATFullCone NATType = "FullCone"
	// NATRestrictedCone: only hosts that have received packets can reply.
	NATRestrictedCone NATType = "RestrictedCone"
	// NATPortRestricted: only the specific host:port that was contacted can reply.
	NATPortRestricted NATType = "PortRestricted"
	// NATSymmetric: port changes per destination (hardest to punch).
	NATSymmetric NATType = "Symmetric"
	// NATUnknown: detection failed.
	NATUnknown NATType = "Unknown"
)

func (n NATType) String() string { return string(n) }

// IsSymmetric returns true if the NAT type is Symmetric.
func (n NATType) IsSymmetric() bool { return n == NATSymmetric }

// IsCone returns true if the NAT type is a cone variant.
func (n NATType) IsCone() bool {
	return n == NATFullCone || n == NATRestrictedCone || n == NATPortRestricted
}
