//go:build linux

package tun

import "fmt"

// ErrNotImplemented is returned by scaffolds completed in the P1 baseline.
var ErrNotImplemented = fmt.Errorf("linux TUN not implemented in current phase")

// Create opens /dev/net/tun and returns a Device.
func Create(cfg Config) (Device, error) {
	return nil, ErrNotImplemented
}
