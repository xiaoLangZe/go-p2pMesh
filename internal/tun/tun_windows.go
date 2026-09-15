//go:build windows

package tun

import "fmt"

// ErrNotImplemented is returned by scaffolds completed in the P1 baseline.
var ErrNotImplemented = fmt.Errorf("Windows wintun not implemented in current phase")

// Create loads wintun.dll and creates a virtual adapter.
func Create(cfg Config) (Device, error) {
	return nil, ErrNotImplemented
}
