//go:build darwin

package tun

import "fmt"

// ErrNotImplemented is returned on macOS until utun is implemented.
//
// macOS utun requires the kernel control interface (CTLIOCGINFO + SYSPROTO_CONTROL),
// which needs CGO or a syscall wrapper. Since the project requires CGO_ENABLED=0,
// this is deferred until a pure-Go utun driver is available.
//
// Workaround: run the client with sudo and use a manual utun interface, or
// use the -install service mode which runs as root via launchd.
var ErrNotImplemented = fmt.Errorf("macOS utun not implemented (requires CGO or pure-Go utun driver); use -install service mode or manual interface")

// Create attempts to open a utun device. Currently returns ErrNotImplemented.
func Create(cfg Config) (Device, error) {
	return nil, ErrNotImplemented
}

func createPlatform(cfg Config) (Device, error) {
	return Create(cfg)
}
