//go:build !windows && !linux && !darwin

package sysutil

// noopInstaller is a no-op for unsupported platforms.
type noopInstaller struct{}

func (noopInstaller) Install(name, execPath string) error { return notImplemented }
func (noopInstaller) Uninstall(name string) error         { return notImplemented }

// DefaultInstaller returns the platform's ServiceInstaller.
func DefaultInstaller() ServiceInstaller { return noopInstaller{} }

// detectPrivileges is a no-op on unsupported platforms.
func detectPrivileges() (bool, error) { return false, notImplemented }
