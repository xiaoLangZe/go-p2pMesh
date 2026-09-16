//go:build !linux

package portcontrol

// PlatformFirewall returns a firewall implementation for this platform.
// Non-Linux platforms use the no-op firewall until their native filters
// (pf on macOS, WFP on Windows) are implemented; the authoritative port
// decisions live in the Controller either way.
func PlatformFirewall() Firewall {
	return NoopFirewall{}
}