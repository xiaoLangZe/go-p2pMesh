//go:build darwin

package sysutil

import "fmt"

// darwinInstaller installs the binary as a launchd plist.
type darwinInstaller struct{}

func (darwinInstaller) Install(name, execPath string) error {
	return fmt.Errorf("launchd install not implemented in current phase")
}

func (darwinInstaller) Uninstall(name string) error {
	return fmt.Errorf("launchd uninstall not implemented in current phase")
}

// DefaultInstaller returns the macOS (launchd) service installer.
func DefaultInstaller() ServiceInstaller { return darwinInstaller{} }

// detectPrivileges checks if the process is running as root.
func detectPrivileges() (bool, error) {
	// P4: check os.Geteuid() == 0.
	return false, nil
}
