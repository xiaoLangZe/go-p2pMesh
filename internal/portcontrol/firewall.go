package portcontrol

// Firewall abstracts the OS packet filter the client uses for its default
// deny boundary (§8.5: "防火墙层只做默认拒绝这一粗粒度门禁").
//
// The design is explicit that the *silent* drop (reject scanning, I10) must
// NOT rely on the firewall — platform DROP behaviour differs (some return
// RST) — so silence lives in the netstack layer. The firewall therefore only
// has two duties here:
//
//  1. Block inbound traffic on the mesh interfaces by default.
//  2. Allow traffic on each configured virtual port.
//
// These are coarse, best-effort gates; the authoritative decision stays in
// the Controller (IsAllowed) and Forwarder (DialVirtual).
type Firewall interface {
	// DenyAllInbound blocks all inbound traffic on the mesh interfaces.
	DenyAllInbound() error
	// AllowPort permits inbound traffic for one virtual port/protocol.
	AllowPort(protocol string, virtualPort int) error
	// RemovePort removes the allow rule for one virtual port.
	RemovePort(protocol string, virtualPort int) error
}

// NoopFirewall implements Firewall without touching the OS. It is the
// default when the client runs without the privileges to install filters;
// the authoritative port decisions still hold because they live in the
// Controller, not the firewall.
type NoopFirewall struct{}

func (NoopFirewall) DenyAllInbound() error            { return nil }
func (NoopFirewall) AllowPort(p string, v int) error  { return nil }
func (NoopFirewall) RemovePort(p string, v int) error { return nil }
