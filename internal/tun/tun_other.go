//go:build !linux && !darwin && !windows

package tun

import "fmt"

func createPlatform(cfg Config) (Device, error) {
	return nil, fmt.Errorf("TUN not supported on this platform")
}
