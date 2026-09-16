//go:build linux

package tun

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// LinuxTUN wraps a /dev/net/tun file descriptor.
type LinuxTUN struct {
	f   *os.File
	name string
	mtu  int
}

// Create opens /dev/net/tun and returns a Device.
//
// The device is created in TUN mode (no Ethernet headers — IP packets
// only), with the name from cfg.Name or auto-assigned if empty.
func Create(cfg Config) (Device, error) {
	f, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open /dev/net/tun: %w", err)
	}

	var ifr [18]byte // flags(2) + name(16)

	// IFF_TUN = 0x0001, IFF_NO_PI = 0x1000 (no packet info header)
	const (
		IFF_TUN   = 0x0001
		IFF_NO_PI = 0x1000
	)
	ifr[0] = byte(IFF_TUN)
	ifr[1] = byte(IFF_NO_PI >> 8)

	if len(cfg.Name) > 0 && len(cfg.Name) < 16 {
		copy(ifr[2:18], []byte(cfg.Name))
	}

	const TUNSETIFF = 0x400454ca
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		uintptr(TUNSETIFF),
		uintptr(unsafe.Pointer(&ifr[0])),
	)
	if errno != 0 {
		f.Close()
		return nil, fmt.Errorf("TUNSETIFF: %w", errno)
	}

	// Extract the actual interface name (null-terminated).
	name := ""
	for i := 2; i < 18; i++ {
		if ifr[i] == 0 {
			name = string(ifr[2:i])
			break
		}
	}
	if name == "" {
		name = "tun0" // fallback
	}

	mtu := cfg.MTU
	if mtu <= 0 {
		mtu = 1280
	}

	return &LinuxTUN{f: f, name: name, mtu: mtu}, nil
}

func (t *LinuxTUN) Read(p []byte) (int, error) {
	return t.f.Read(p)
}

func (t *LinuxTUN) Write(p []byte) (int, error) {
	return t.f.Write(p)
}

func (t *LinuxTUN) Close() error {
	return t.f.Close()
}

func (t *LinuxTUN) Name() string { return t.name }

func (t *LinuxTUN) MTU() int { return t.mtu }

func createPlatform(cfg Config) (Device, error) {
	return Create(cfg)
}
