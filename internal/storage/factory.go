package storage

import "fmt"

// NewStore creates a Store instance from DatabaseConfig.
// SQLite uses the pure-Go modernc.org/sqlite driver (no CGO).
// MySQL and PostgreSQL use their respective drivers.
func NewStore(cfg DatabaseConfig) (Store, error) {
	switch cfg.Type {
	case "sqlite":
		return NewSQLStore("sqlite", cfg.DSN, cfg.MaxOpenConns, cfg.MaxIdleConns)
	case "mysql":
		return NewSQLStore("mysql", cfg.DSN, cfg.MaxOpenConns, cfg.MaxIdleConns)
	case "postgresql", "postgres":
		return NewSQLStore("postgresql", cfg.DSN, cfg.MaxOpenConns, cfg.MaxIdleConns)
	case "mongodb":
		// MongoDB adapter not yet implemented (P6).
		return noopStore{}, fmt.Errorf("mongodb support planned for P6, using noop")
	default:
		return nil, fmt.Errorf("unsupported database type %q", cfg.Type)
	}
}
