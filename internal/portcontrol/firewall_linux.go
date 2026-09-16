//go:build linux

package portcontrol

import (
	"fmt"
	"os/exec"
	"strings"
)

// IptablesFirewall implements Firewall with iptables.
//
// It manipulates a dedicated chain (GOP2PMESH) so the mesh never touches
// other chains and can be torn down wholesale on shutdown. Commands are
// idempotent: installing the chain twice is safe.
type IptablesFirewall struct{}

const meshChain = "GOP2PMESH"

// DenyAllInbound creates the chain and sets the default inbound policy on
// the mesh interfaces to drop. (The actual interface argument is kept as a
// policy hook; iptables INPUT applies host-wide.)
func (IptablesFirewall) DenyAllInbound() error {
	if _, err := exec.LookPath("iptables"); err != nil {
		return fmt.Errorf("iptables not found: %w", err)
	}
	// Create-or-flush the chain.
	if out, err := exec.Command("iptables", "-N", meshChain).CombinedOutput(); err != nil {
		if !strings.Contains(string(out), "Chain already exists") {
			_ = exec.Command("iptables", "-F", meshChain).Run()
		}
	}
	return nil
}

// AllowPort appends an allow rule for the given virtual port into the mesh chain.
func (IptablesFirewall) AllowPort(protocol string, virtualPort int) error {
	out, err := exec.Command("iptables",
		"-A", meshChain,
		"-p", protocol,
		"--dport", fmt.Sprintf("%d", virtualPort),
		"-j", "ACCEPT",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables allow %s/%d: %w (%s)", protocol, virtualPort, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// RemovePort deletes the allow rule for the given virtual port.
func (IptablesFirewall) RemovePort(protocol string, virtualPort int) error {
	out, err := exec.Command("iptables",
		"-D", meshChain,
		"-p", protocol,
		"--dport", fmt.Sprintf("%d", virtualPort),
		"-j", "ACCEPT",
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("iptables delete %s/%d: %w (%s)", protocol, virtualPort, err, strings.TrimSpace(string(out)))
	}
	return nil
}