//go:build linux

package sysutil

import "fmt"

// linuxInstaller installs the binary as a systemd unit.
type linuxInstaller struct{}

func (linuxInstaller) Install(name, execPath string) error {
	return fmt.Errorf("systemd install not implemented in current phase")
}

func (linuxInstaller) Uninstall(name string) error {
	return fmt.Errorf("systemd uninstall not implemented in current phase")
}

// DefaultInstaller returns the Linux (systemd) service installer.
func DefaultInstaller() ServiceInstaller { return linuxInstaller{} }

// detectPrivileges checks for root or CAP_NET_ADMIN.
func detectPrivileges() (bool, error) {
	// P8: check /proc/self/status for CapEff.
	return false, nil
}
