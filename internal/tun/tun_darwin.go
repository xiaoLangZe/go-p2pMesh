//go:build darwin

package tun

import "fmt"

// ErrNotImplemented is returned in P0.
var ErrNotImplemented = fmt.Errorf("macOS utun not implemented in current phase")

// Create opens a utun device and returns a Device.
func Create(cfg Config) (Device, error) {
	return nil, ErrNotImplemented
}
