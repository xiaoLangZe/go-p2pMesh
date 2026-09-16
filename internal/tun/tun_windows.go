//go:build windows

package tun

import "fmt"

// ErrNotImplemented is returned on Windows until wintun.dll integration is complete.
//
// wintun.dll is bundled (DESIGN.md §21.3: "随包内置，运行时释放") and will be
// loaded via golang.org/x/sys/windows LoadDLL. The adapter is created via
// WintunCreateAdapter, and read/write go through the ring buffer API.
//
// This is deferred to a later sub-phase of P4 because the wintun API
// requires CGO-free DLL binding work that is not yet done.
var ErrNotImplemented = fmt.Errorf("Windows wintun.dll not yet integrated; the DLL is bundled but the adapter API needs implementation")

// Create attempts to load wintun.dll and create a virtual adapter.
// Currently returns ErrNotImplemented.
func Create(cfg Config) (Device, error) {
	return nil, ErrNotImplemented
}

func createPlatform(cfg Config) (Device, error) {
	return Create(cfg)
}
