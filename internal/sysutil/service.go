// Package sysutil provides cross-platform system service installation
// and privilege detection.
package sysutil

// ServiceInstaller is the interface for installing/uninstalling
// go-p2pmesh as an OS-level service (Windows Service, systemd, launchd).
type ServiceInstaller interface {
	Install(name, execPath string) error
	Uninstall(name string) error
}

// ErrNotImplemented is returned by scaffolds completed in the P1 baseline.
var notImplemented = errorString("sysutil not implemented in current phase")

type errorString string

func (e errorString) Error() string { return string(e) }

// DetectPrivileges reports whether the current process has the
// necessary privileges to create a TUN device and modify routes.
func DetectPrivileges() (bool, error) {
	// Platform-specific implementation in service_*.go.
	return false, notImplemented
}
