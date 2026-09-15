package config

import "fmt"

// ClientConfig holds all configuration values for the client binary.
type ClientConfig struct {
	// [client]
	Bootstrap   []string
	ListenPort  int
	NodeID      string

	// [room]
	AutoJoin    string
	RoomKey     string

	// [stun]
	StunServers  []string
	StunTimeout  int // milliseconds
	PredictSamples int
	StunIPv6     bool

	// [holepunch]
	PredictWindow   int
	PredictParallel int
	TurnEnabled     bool
	TurnAddr        string

	// [tunnel]
	TunnelMTU   int
	KCPWindow   int
	// AllowUnreliableFallback permits degrading a KCP tunnel to raw UDP when
	// KCP is judged failed (invariant I6: "降级不静默"). When false the tunnel
	// fails loudly instead of silently losing reliability.
	AllowUnreliableFallback bool

	// [network]
	NetworkCIDR string

	// [portcontrol]
	PortControlPolicy string
	PortControlDB     string

	// [identity]
	KeyFile string

	// [log]
	LogLevel string
	LogFile  string
}

// DefaultClientConfig returns the client configuration with default values.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		Bootstrap: []string{},
		ListenPort: 0,
		StunServers: []string{
			"stun.l.google.com:19302",
			"stun1.l.google.com:19302",
			"stun2.l.google.com:19302",
			"stun.cloudflare.com:3478",
		},
		StunTimeout:    3000,
		PredictSamples: 8,
		StunIPv6:       true,
		PredictWindow:  64,
		PredictParallel: 256,
		TunnelMTU:      1280,
		KCPWindow:      256,
		// I6: no silent degradation by default. Operators must opt in.
		AllowUnreliableFallback: false,
		NetworkCIDR:    "fd00:9bd8::/64",
		PortControlPolicy: "deny",
		PortControlDB:  "portcontrol.db",
		KeyFile:        "identity.key",
		LogLevel:       "info",
	}
}

// LoadClientConfig parses a client INI file path into a ClientConfig.
func LoadClientConfig(path string) (*ClientConfig, error) {
	cfg := DefaultClientConfig()
	m, err := LoadINI(path)
	if err != nil {
		return nil, err
	}
	cfg.Bootstrap = GetStringSlice(m, "client", "bootstrap", cfg.Bootstrap)
	cfg.ListenPort = GetInt(m, "client", "listen_port", cfg.ListenPort)
	cfg.NodeID = GetString(m, "client", "node_id", cfg.NodeID)

	cfg.AutoJoin = GetString(m, "room", "auto_join", cfg.AutoJoin)
	cfg.RoomKey = GetString(m, "room", "room_key", cfg.RoomKey)

	cfg.StunServers = GetStringSlice(m, "stun", "servers", cfg.StunServers)
	cfg.StunTimeout = GetInt(m, "stun", "timeout_ms", cfg.StunTimeout)
	cfg.PredictSamples = GetInt(m, "stun", "predict_samples", cfg.PredictSamples)
	cfg.StunIPv6 = GetBool(m, "stun", "ipv6", cfg.StunIPv6)

	cfg.PredictWindow = GetInt(m, "holepunch", "predict_window", cfg.PredictWindow)
	cfg.PredictParallel = GetInt(m, "holepunch", "predict_parallel", cfg.PredictParallel)
	cfg.TurnEnabled = GetBool(m, "holepunch", "turn", cfg.TurnEnabled)
	cfg.TurnAddr = GetString(m, "holepunch", "turn_addr", cfg.TurnAddr)

	cfg.TunnelMTU = GetInt(m, "tunnel", "mtu", cfg.TunnelMTU)
	cfg.KCPWindow = GetInt(m, "tunnel", "kcp_window", cfg.KCPWindow)
	cfg.AllowUnreliableFallback = GetBool(m, "tunnel", "allow_unreliable_fallback", cfg.AllowUnreliableFallback)

	cfg.NetworkCIDR = GetString(m, "network", "cidr", cfg.NetworkCIDR)

	cfg.PortControlPolicy = GetString(m, "portcontrol", "default_policy", cfg.PortControlPolicy)
	cfg.PortControlDB = GetString(m, "portcontrol", "db_file", cfg.PortControlDB)

	cfg.KeyFile = GetString(m, "identity", "key_file", cfg.KeyFile)

	cfg.LogLevel = GetString(m, "log", "level", cfg.LogLevel)
	cfg.LogFile = GetString(m, "log", "file", cfg.LogFile)

	return cfg, nil
}

// Validate checks the client config for obvious errors.
func (c *ClientConfig) Validate() error {
	if len(c.Bootstrap) == 0 {
		return fmt.Errorf("no bootstrap servers configured")
	}
	if c.TunnelMTU < 576 {
		return fmt.Errorf("tunnel MTU %d too small", c.TunnelMTU)
	}
	switch c.PortControlPolicy {
	case "deny", "allow":
	default:
		return fmt.Errorf("invalid port control policy %q", c.PortControlPolicy)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log level %q", c.LogLevel)
	}
	return nil
}
