//go:build windows

package sysutil

import "fmt"

// windowsInstaller installs the binary as a Windows Service.
type windowsInstaller struct{}

func (windowsInstaller) Install(name, execPath string) error {
	return fmt.Errorf("windows service install not implemented in current phase")
}

func (windowsInstaller) Uninstall(name string) error {
	return fmt.Errorf("windows service uninstall not implemented in current phase")
}

// DefaultInstaller returns the Windows service installer.
func DefaultInstaller() ServiceInstaller { return windowsInstaller{} }

// detectPrivileges checks if the process is running as Administrator.
func detectPrivileges() (bool, error) {
	// P8: check for elevated token via golang.org/x/sys/windows.
	return false, nil
}
