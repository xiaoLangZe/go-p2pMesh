package config

import (
	"fmt"
	"strconv"
	"strings"
)

// ServerConfig holds all configuration values for the server binary.
type ServerConfig struct {
	// [server]
	Host      string
	Port      int
	MeshPeers []string

	// [api]
	APIEnabled       bool
	APIHost          string
	APIPort          int
	APICertFile      string
	APIKeyFile       string
	APIClientCAFile  string
	JWTSecret        string
	TokenTTLHours    int
	AdminUser        string
	AdminPassword    string

	// [database]
	DatabaseType     string
	DatabaseDSN      string
	MaxOpenConns     int
	MaxIdleConns     int

	// [network]
	NetworkCIDR      string

	// [security]
	RootKeyFile      string
	TrustOnFirstUse  bool
	NodeTimeout      string

	// [log]
	LogLevel         string
	LogFile          string
}

// DefaultServerConfig returns the server configuration with default values.
//
// The API listener defaults to loopback (invariant I5). Set `api.host = 0.0.0.0`
// (or a specific address) in the config to expose management externally — that
// is an explicit decision, not a default.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		Host:           "0.0.0.0",
		Port:           29683,
		APIEnabled:     true,
		APIHost:        "127.0.0.1",
		APIPort:        29684,
		TokenTTLHours:  24,
		AdminUser:      "admin",
		DatabaseType:   "sqlite",
		DatabaseDSN:    "data/gop2pmesh.db",
		MaxOpenConns:   50,
		MaxIdleConns:   10,
		NetworkCIDR:    "fd00:9bd8::/64",
		RootKeyFile:    "root.key",
		TrustOnFirstUse: false,
		NodeTimeout:    "90s",
		LogLevel:       "info",
	}
}

// LoadServerConfig parses a server INI file path into a ServerConfig.
func LoadServerConfig(path string) (*ServerConfig, error) {
	cfg := DefaultServerConfig()
	m, err := LoadINI(path)
	if err != nil {
		return nil, err
	}
	cfg.Host = GetString(m, "server", "host", cfg.Host)
	cfg.Port = GetInt(m, "server", "port", cfg.Port)
	cfg.MeshPeers = GetStringSlice(m, "server", "mesh_peers", cfg.MeshPeers)

	cfg.APIEnabled = GetBool(m, "api", "enabled", cfg.APIEnabled)
	cfg.APIHost = GetString(m, "api", "host", cfg.APIHost)
	cfg.APIPort = GetInt(m, "api", "port", cfg.APIPort)
	cfg.APICertFile = GetString(m, "api", "cert_file", cfg.APICertFile)
	cfg.APIKeyFile = GetString(m, "api", "key_file", cfg.APIKeyFile)
	cfg.APIClientCAFile = GetString(m, "api", "client_ca_file", cfg.APIClientCAFile)
	cfg.JWTSecret = GetString(m, "api", "jwt_secret", cfg.JWTSecret)
	cfg.TokenTTLHours = GetInt(m, "api", "token_ttl_hours", cfg.TokenTTLHours)
	cfg.AdminUser = GetString(m, "api", "admin_user", cfg.AdminUser)
	cfg.AdminPassword = GetString(m, "api", "admin_password", cfg.AdminPassword)

	cfg.DatabaseType = GetString(m, "database", "type", cfg.DatabaseType)
	cfg.DatabaseDSN = GetString(m, "database", "dsn", cfg.DatabaseDSN)
	cfg.MaxOpenConns = GetInt(m, "database", "max_open_conns", cfg.MaxOpenConns)
	cfg.MaxIdleConns = GetInt(m, "database", "max_idle_conns", cfg.MaxIdleConns)

	cfg.NetworkCIDR = GetString(m, "network", "cidr", cfg.NetworkCIDR)

	cfg.RootKeyFile = GetString(m, "security", "root_key_file", cfg.RootKeyFile)
	cfg.TrustOnFirstUse = GetBool(m, "security", "trust_on_first_use", cfg.TrustOnFirstUse)
	cfg.NodeTimeout = GetString(m, "security", "node_timeout", cfg.NodeTimeout)

	cfg.LogLevel = GetString(m, "log", "level", cfg.LogLevel)
	cfg.LogFile = GetString(m, "log", "file", cfg.LogFile)

	return cfg, nil
}

// Validate checks the server config for obvious errors.
func (c *ServerConfig) Validate() error {
	if c.Port < 1 || c.Port > 65535 {
		return fmt.Errorf("invalid server port %d", c.Port)
	}
	if c.APIPort < 1 || c.APIPort > 65535 {
		return fmt.Errorf("invalid api port %d", c.APIPort)
	}
	switch c.DatabaseType {
	case "sqlite", "mysql", "postgresql", "mongodb":
	default:
		return fmt.Errorf("unsupported database type %q", c.DatabaseType)
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log level %q", c.LogLevel)
	}
	return nil
}

// HostPort returns the server's "host:port" string.
func (c *ServerConfig) HostPort() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

// APIHostPort returns the API server's "host:port" string.
func (c *ServerConfig) APIHostPort() string {
	return fmt.Sprintf("%s:%d", c.APIHost, c.APIPort)
}

// ToServerOptions converts the config into pkg/server Option values.
func (c *ServerConfig) ToServerOptions() []string {
	return []string{
		fmt.Sprintf("host=%s", c.Host),
		fmt.Sprintf("port=%d", c.Port),
		fmt.Sprintf("api_host=%s", c.APIHost),
		fmt.Sprintf("api_port=%d", c.APIPort),
		fmt.Sprintf("db_type=%s", c.DatabaseType),
		fmt.Sprintf("db_dsn=%s", c.DatabaseDSN),
		fmt.Sprintf("log_level=%s", c.LogLevel),
	}
}

// ParseHostPort splits "host:port" into the individual parts.
func ParseHostPort(addr string) (string, int, error) {
	// Handle [::1]:8080 style IPv6 addresses.
	if strings.HasPrefix(addr, "[") {
		end := strings.LastIndex(addr, "]")
		if end < 0 {
			return "", 0, fmt.Errorf("invalid IPv6 address: %q", addr)
		}
		host := addr[1:end]
		rest := addr[end+1:]
		if !strings.HasPrefix(rest, ":") {
			return "", 0, fmt.Errorf("missing port: %q", addr)
		}
		port, err := strconv.Atoi(rest[1:])
		if err != nil {
			return "", 0, fmt.Errorf("invalid port in %q: %w", addr, err)
		}
		return host, port, nil
	}
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return "", 0, fmt.Errorf("missing port: %q", addr)
	}
	host := addr[:idx]
	port, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return "", 0, fmt.Errorf("invalid port in %q: %w", addr, err)
	}
	return host, port, nil
}
