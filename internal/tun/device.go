// Package tun provides a cross-platform virtual NIC abstraction.
//
// Platform-specific implementations:
//   - Linux: /dev/net/tun
//   - macOS: utun (system private interface)
//   - Windows: wintun.dll (runtime-loaded)
package tun

// Device is the virtual network interface abstraction.
type Device interface {
	// Read reads one IP packet from the TUN device.
	Read([]byte) (int, error)
	// Write writes one IP packet to the TUN device.
	Write([]byte) (int, error)
	// Close closes the device.
	Close() error
	// Name returns the OS-assigned interface name.
	Name() string
	// MTU returns the configured MTU.
	MTU() int
}

// Config holds the parameters for creating a TUN device.
type Config struct {
	Name   string // desired interface name (may be ignored by OS)
	IPv6   string // IPv6 /128 address to assign
	MTU    int    // MTU (default 1280)
}
