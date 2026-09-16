//go:build linux

package portcontrol

// PlatformFirewall returns the platform's firewall implementation.
func PlatformFirewall() Firewall {
	return IptablesFirewall{}
}
