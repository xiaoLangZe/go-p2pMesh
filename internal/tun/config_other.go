//go:build !linux

package tun

import "fmt"

// ConfigureAddress is only meaningful on Linux in the current phase.
// macOS/Windows TUN creation is not yet implemented (see tun_darwin.go /
// tun_windows.go), so address configuration returns the same class of error.
func ConfigureAddress(name, ipv6, ipv4 string) error {
	return fmt.Errorf("TUN address configuration not implemented on this platform")
}

// ConfigureRoute is only meaningful on Linux in the current phase.
func ConfigureRoute(name, subnet string) error {
	return fmt.Errorf("TUN route configuration not implemented on this platform")
}

// PrivilegeCheck on non-Linux platforms returns nil — the platform-specific
// TUN creation (when implemented) will carry its own privilege checks
// (e.g. Windows UAC elevation, macOS root).
func PrivilegeCheck() error {
	return nil
}