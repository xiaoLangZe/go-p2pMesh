package server

// Option configures a Server using the functional-options pattern.
type Option func(*Config)

// WithHost sets the listening host for the control-plane listener.
func WithHost(host string) Option {
	return func(c *Config) { c.Host = host }
}

// WithPort sets the listening port for the control-plane listener (default 29683).
func WithPort(port int) Option {
	return func(c *Config) { c.Port = port }
}

// WithAPIHost sets the REST API listening host.
func WithAPIHost(host string) Option {
	return func(c *Config) { c.APIHost = host }
}

// WithAPIPort sets the REST API listening port (default 29684).
func WithAPIPort(port int) Option {
	return func(c *Config) { c.APIPort = port }
}

// WithAPICertFile sets the HTTPS certificate file path for the REST API.
func WithAPICertFile(path string) Option {
	return func(c *Config) { c.APICertFile = path }
}

// WithAPIKeyFile sets the HTTPS private key file path for the REST API.
func WithAPIKeyFile(path string) Option {
	return func(c *Config) { c.APIKeyFile = path }
}

// WithAdminCredentials sets the initial admin username and password.
// If the password is empty, a random one is generated at first boot.
func WithAdminCredentials(user, pass string) Option {
	return func(c *Config) {
		c.AdminUser = user
		c.AdminPass = pass
	}
}

// WithDatabase sets the database backend type and DSN.
// Supported types: "sqlite", "mysql", "postgresql", "mongodb".
func WithDatabase(dbType, dsn string) Option {
	return func(c *Config) {
		c.DatabaseType = dbType
		c.DatabaseDSN = dsn
	}
}

// WithLogLevel sets the log verbosity: "debug", "info", "warn", "error".
func WithLogLevel(level string) Option {
	return func(c *Config) { c.LogLevel = level }
}

// WithLogFile sets the log file path; empty means stdout.
func WithLogFile(path string) Option {
	return func(c *Config) { c.LogFile = path }
}
