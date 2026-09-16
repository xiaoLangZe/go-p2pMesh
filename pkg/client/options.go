package client

// Option configures a Client using the functional-options pattern.
type Option func(*Config)

// WithBootstrap sets the list of bootstrap server addresses (host:port).
func WithBootstrap(addrs []string) Option {
	return func(c *Config) { c.Bootstrap = addrs }
}

// WithListenPort sets the sub-server listen port (0 = disabled).
func WithListenPort(port int) Option {
	return func(c *Config) { c.ListenPort = port }
}

// WithRoom sets the room to join on startup and an optional room key.
func WithRoom(roomID, key string) Option {
	return func(c *Config) {
		c.RoomID = roomID
		c.RoomKey = key
	}
}

// WithSTUNServers sets the list of third-party STUN servers.
func WithSTUNServers(servers []string) Option {
	return func(c *Config) { c.StunServers = servers }
}

// WithHolepunchParams sets the port prediction window and parallelism.
func WithHolepunchParams(window, parallel int) Option {
	return func(c *Config) {
		c.HolepunchWindow = window
		c.HolepunchParallel = parallel
	}
}

// WithTurn enables TURN relay fallback and sets the relay address.
func WithTurn(addr string) Option {
	return func(c *Config) {
		c.TurnEnabled = addr != ""
		c.TurnAddr = addr
	}
}

// WithTunnelMTU sets the KCP tunnel MTU (default 1280).
func WithTunnelMTU(mtu int) Option {
	return func(c *Config) { c.TunnelMTU = mtu }
}

// WithAllowUnreliableFallback controls whether KCP may degrade to raw UDP.
// Setting false (invariant I6) forbids the fallback so a connection fails
// loudly rather than silently losing reliability.
func WithAllowUnreliableFallback(allow bool) Option {
	return func(c *Config) { c.AllowUnreliableFallback = allow }
}

// WithPortControlPolicy sets the default port policy: "deny" or "allow".
func WithPortControlPolicy(policy string) Option {
	return func(c *Config) { c.PortControlPolicy = policy }
}

// WithLogLevel sets the log verbosity: "debug", "info", "warn", "error".
func WithLogLevel(level string) Option {
	return func(c *Config) { c.LogLevel = level }
}

// WithLogFile sets the log file path; empty means stdout.
func WithLogFile(path string) Option {
	return func(c *Config) { c.LogFile = path }
}
