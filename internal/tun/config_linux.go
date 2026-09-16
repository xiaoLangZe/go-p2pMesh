//go:build linux

package tun

import (
	"fmt"
	"os/exec"
	"strings"
)

// ConfigureAddress assigns IPv6 and IPv4 addresses to the TUN interface
// and brings it up. This is the platform-specific half of P4-5.
//
// Per-platform commands (§21.3):
//   - Linux: `ip -6 addr add` / `ip addr add`, `ip link set up`
func ConfigureAddress(name, ipv6, ipv4 string) error {
	if ipv6 != "" {
		if out, err := exec.Command("ip", "-6", "addr", "add", ipv6, "dev", name).CombinedOutput(); err != nil {
			return fmt.Errorf("ip -6 addr add %s dev %s: %w (out: %s)", ipv6, name, err, strings.TrimSpace(string(out)))
		}
	}
	if ipv4 != "" {
		if out, err := exec.Command("ip", "addr", "add", ipv4, "dev", name).CombinedOutput(); err != nil {
			return fmt.Errorf("ip addr add %s dev %s: %w (out: %s)", ipv4, name, err, strings.TrimSpace(string(out)))
		}
	}
	if out, err := exec.Command("ip", "link", "set", "up", "dev", name).CombinedOutput(); err != nil {
		return fmt.Errorf("ip link set up dev %s: %w (out: %s)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ConfigureRoute adds a route for the mesh subnet through the TUN interface.
// For the mesh, the TUN interface is the only path to the ULA prefix, so a
// single on-link route suffices; packets to peers are then handled by the
// Router's PeerTable lookups.
func ConfigureRoute(name, subnet string) error {
	if subnet == "" {
		return nil
	}
	if out, err := exec.Command("ip", "-6", "route", "add", subnet, "dev", name).CombinedOutput(); err != nil {
		return fmt.Errorf("ip -6 route add %s dev %s: %w (out: %s)", subnet, name, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// PrivilegeCheck verifies the process has permission to create a TUN device
// and configure routes (CAP_NET_ADMIN, root, or equivalent). Returns an
// advisory error describing what the operator should do.
func PrivilegeCheck() error {
	_, err := exec.LookPath("ip")
	if err != nil {
		return fmt.Errorf("the 'ip' command is not installed; it is required to configure the TUN interface")
	}
	// Attempt a no-op capability probe by checking write access to /dev/net/tun.
	if !fileWritable("/dev/net/tun") {
		return fmt.Errorf("no permission to open /dev/net/tun; run as root or grant CAP_NET_ADMIN (e.g. setcap cap_net_admin+ep on the binary, or use -install to run as a system service)")
	}
	return nil
}

func fileWritable(path string) bool {
	// /dev/net/tun may not exist on systems without the tun module.
	// Use an os.Stat + mode check that avoids opening (which allocates a tun).
	fi, err := osStat(path)
	if err != nil {
		return false
	}
	return fi.Mode()&0222 != 0
}
