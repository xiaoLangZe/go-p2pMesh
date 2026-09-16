package storage

import (
	"bytes"
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/xiaoLangZe/go-p2pmesh/pkg/types"

	// Pure-Go SQLite driver (no CGO required).
	_ "modernc.org/sqlite"
)

//go:embed migrations/001_init.sql
var migrationSQL string

//go:embed migrations/002_ipv4.sql
var migrationIPv4SQL string

//go:embed migrations/003_allowed_rooms.sql
var migrationAllowedRoomsSQL string

// SQLStore implements Store using database/sql + sqlx.
// It works with SQLite (via modernc.org/sqlite), MySQL, and PostgreSQL.
// All queries use parameter binding — no string concatenation is permitted.
type SQLStore struct {
	db *sqlx.DB
	// placeholderStyle controls the bind parameter style:
	//   "?" for SQLite/MySQL, "$1" for PostgreSQL.
	placeholder string
}

// NewSQLStore creates a new SQL-backed store.
// driverName must be one of: "sqlite", "mysql", "postgres".
func NewSQLStore(driverName, dsn string, maxOpen, maxIdle int) (*SQLStore, error) {
	var db *sqlx.DB
	var err error
	var placeholder string

	switch driverName {
	case "sqlite":
		db, err = sqlx.Connect("sqlite", dsn)
		placeholder = "?"
	case "mysql":
		db, err = sqlx.Connect("mysql", dsn)
		placeholder = "?"
	case "postgresql", "postgres", "pgx":
		db, err = sqlx.Connect("pgx", dsn)
		placeholder = "$1"
	default:
		return nil, fmt.Errorf("unsupported SQL driver %q", driverName)
	}
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w", driverName, err)
	}

	db.SetMaxOpenConns(maxOpen)
	db.SetMaxIdleConns(maxIdle)
	db.SetConnMaxLifetime(30 * time.Minute)

	s := &SQLStore{db: db, placeholder: placeholder}
	if err := s.migrate(); err != nil {
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return s, nil
}

// migrate executes embedded migration SQL scripts in order.
func (s *SQLStore) migrate() error {
	// Execute the initial schema.
	if _, err := s.db.Exec(migrationSQL); err != nil {
		return fmt.Errorf("migration 001: %w", err)
	}
	// Execute the IPv4 schema additions.
	// SQLite ALTER TABLE statements must be run individually.
	if err := s.runAlterStatements(migrationIPv4SQL, "002"); err != nil {
		return err
	}
	// Execute the allowed-rooms addition.
	if err := s.runAlterStatements(migrationAllowedRoomsSQL, "003"); err != nil {
		return err
	}
	return nil
}

// runAlterStatements executes an ALTER-style migration statement by
// statement, tolerating duplicate-column errors for idempotent re-runs.
func (s *SQLStore) runAlterStatements(script, name string) error {
	for _, stmt := range splitStatements(script) {
		stmt = trimSpace(stmt)
		if stmt == "" {
			continue
		}
		if _, err := s.db.Exec(stmt); err != nil {
			// Ignore "duplicate column" errors (idempotent migrations).
			if isDuplicateColumnErr(err) {
				continue
			}
			return fmt.Errorf("migration %s: %w", name, err)
		}
	}
	return nil
}

// rebind translates "?" placeholders to the driver-specific style.
func (s *SQLStore) rebind(query string) string {
	if s.placeholder == "?" {
		return query
	}
	return s.db.Rebind(query)
}

// --- Nodes ---

// RegisterNode binds a NodeID to a public key.
//
// Invariant I8: if the ID is already bound to a *different* key, the attempt is
// rejected with ErrNodeIDConflict instead of overwriting. Without this check an
// attacker who guesses a victim's NodeID (which is derived from non-secret
// machine fingerprints) could take over the record by re-registering.
func (s *SQLStore) RegisterNode(ctx context.Context, n *Node) error {
	// Look up any existing binding for this ID.
	var existing struct {
		PubKey []byte `db:"pubkey"`
	}
	err := s.db.GetContext(ctx, &existing, s.rebind(
		`SELECT pubkey FROM nodes WHERE id = ?`), n.ID.String())
	switch {
	case err == nil:
		// ID exists: the key must match, otherwise refuse.
		if !bytes.Equal(existing.PubKey, n.PubKey) {
			return fmt.Errorf("%w: %s", ErrNodeIDConflict, n.ID)
		}
	case errors.Is(err, sql.ErrNoRows):
		// New node — fall through to insert.
	default:
		return fmt.Errorf("look up node %s: %w", n.ID, err)
	}

	_, err = s.db.ExecContext(ctx, s.rebind(`
		INSERT INTO nodes (id, pubkey, room_id, ipv6_addr, ipv4_addr, public_addr, nat_type, status, created_at, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			room_id = excluded.room_id,
			ipv6_addr = excluded.ipv6_addr,
			ipv4_addr = excluded.ipv4_addr,
			public_addr = excluded.public_addr,
			nat_type = excluded.nat_type,
			status = excluded.status,
			last_seen = excluded.last_seen`),
		n.ID.String(), n.PubKey, n.RoomID, n.IPv6Addr, n.IPv4Addr, n.PublicAddr,
		n.NATType, string(n.Status), time.Now().UTC(), time.Now().UTC())
	return err
}

func (s *SQLStore) GetNode(ctx context.Context, id string) (*Node, error) {
	var n Node
	err := s.db.GetContext(ctx, &n, s.rebind(`
		SELECT id, pubkey, room_id, ipv6_addr, ipv4_addr, public_addr, nat_type, status, created_at, last_seen
		FROM nodes WHERE id = ?`), id)
	if err != nil {
		return nil, err
	}
	n.ID = types.NodeID(n.ID.String())
	return &n, nil
}

func (s *SQLStore) ListNodes(ctx context.Context, filter NodeFilter) ([]*Node, error) {
	query := `SELECT id, pubkey, room_id, ipv6_addr, ipv4_addr, public_addr, nat_type, status, created_at, last_seen FROM nodes`
	args := []interface{}{}
	if filter.RoomID != "" {
		query += ` WHERE room_id = ?`
		args = append(args, filter.RoomID)
	}
	if filter.Status != "" {
		if len(args) > 0 {
			query += ` AND`
		} else {
			query += ` WHERE`
		}
		query += ` status = ?`
		args = append(args, string(filter.Status))
	}
	query += ` ORDER BY created_at DESC`
	if filter.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, filter.Limit)
	}
	if filter.Offset > 0 {
		query += ` OFFSET ?`
		args = append(args, filter.Offset)
	}
	var nodes []*Node
	err := s.db.SelectContext(ctx, &nodes, s.rebind(query), args...)
	return nodes, err
}

func (s *SQLStore) UpdateNodeStatus(ctx context.Context, id string, status NodeStatus) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`
		UPDATE nodes SET status = ?, last_seen = ? WHERE id = ?`),
		string(status), time.Now().UTC(), id)
	return err
}

func (s *SQLStore) DeleteNode(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM nodes WHERE id = ?`), id)
	return err
}

// UnbindNodeID releases the NodeID↔pubkey binding (D5).
//
// The row is deleted rather than the key nulled so the next registration is a
// clean first-use bind. Deleting the node also drops its room membership and
// port rules via the ON DELETE CASCADE constraints, which is the intended
// semantics: an unbound identity owns nothing.
func (s *SQLStore) UnbindNodeID(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM nodes WHERE id = ?`), id)
	if err != nil {
		return fmt.Errorf("unbind node %s: %w", id, err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("unbind node %s: %w", id, sql.ErrNoRows)
	}
	return nil
}

// --- Rooms ---

func (s *SQLStore) CreateRoom(ctx context.Context, r *types.Room) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`
		INSERT INTO rooms (id, name, owner_id, encrypted, max_members, created_at)
		VALUES (?, ?, ?, ?, ?, ?)`),
		string(r.ID), r.Name, string(r.OwnerID), r.Encrypted, r.MaxMembers, time.Now().UTC())
	return err
}

func (s *SQLStore) GetRoom(ctx context.Context, id string) (*types.Room, error) {
	var r types.Room
	err := s.db.GetContext(ctx, &r, s.rebind(`
		SELECT id, name, owner_id, encrypted, max_members, created_at
		FROM rooms WHERE id = ?`), id)
	if err != nil {
		return nil, err
	}
	r.ID = types.RoomID(r.ID)
	r.OwnerID = types.NodeID(r.OwnerID)
	return &r, nil
}

func (s *SQLStore) ListRooms(ctx context.Context) ([]*types.Room, error) {
	var rooms []*types.Room
	err := s.db.SelectContext(ctx, &rooms, `SELECT id, name, owner_id, encrypted, max_members, created_at FROM rooms ORDER BY created_at DESC`)
	return rooms, err
}

func (s *SQLStore) AddRoomMember(ctx context.Context, roomID, nodeID string) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`
		INSERT INTO room_members (room_id, node_id, joined_at) VALUES (?, ?, ?)
		ON CONFLICT(room_id, node_id) DO NOTHING`),
		roomID, nodeID, time.Now().UTC())
	return err
}

func (s *SQLStore) RemoveRoomMember(ctx context.Context, roomID, nodeID string) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM room_members WHERE room_id = ? AND node_id = ?`),
		roomID, nodeID)
	return err
}

func (s *SQLStore) ListRoomMembers(ctx context.Context, roomID string) ([]*Node, error) {
	var nodes []*Node
	err := s.db.SelectContext(ctx, &nodes, s.rebind(`
		SELECT n.id, n.pubkey, n.room_id, n.ipv6_addr, n.ipv4_addr, n.public_addr, n.nat_type, n.status, n.created_at, n.last_seen
		FROM nodes n
		JOIN room_members rm ON rm.node_id = n.id
		WHERE rm.room_id = ? AND n.status = ?`),
		roomID, string(NodeStatusOnline))
	return nodes, err
}

// --- Port rules ---

func (s *SQLStore) SetPortRule(ctx context.Context, rule *PortRule) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`
		INSERT INTO port_rules (id, node_id, protocol, local_port, virtual_port, description, allowed_rooms, enabled, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			protocol = excluded.protocol,
			local_port = excluded.local_port,
			virtual_port = excluded.virtual_port,
			description = excluded.description,
			allowed_rooms = excluded.allowed_rooms,
			enabled = excluded.enabled`),
		rule.ID, rule.NodeID, rule.Protocol, rule.LocalPort,
		rule.VirtualPort, rule.Description, rule.AllowedRooms, rule.Enabled, time.Now().UTC())
	return err
}

func (s *SQLStore) GetPortRules(ctx context.Context, nodeID string) ([]*PortRule, error) {
	var rules []*PortRule
	err := s.db.SelectContext(ctx, &rules, s.rebind(`
		SELECT id, node_id, protocol, local_port, virtual_port, description, allowed_rooms, enabled, created_at
		FROM port_rules WHERE node_id = ? AND enabled = TRUE
		ORDER BY virtual_port`), nodeID)
	return rules, err
}

func (s *SQLStore) DeletePortRule(ctx context.Context, ruleID string) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`DELETE FROM port_rules WHERE id = ?`), ruleID)
	return err
}

// --- API users ---

func (s *SQLStore) CreateAPIUser(ctx context.Context, u *APIUser) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`
		INSERT INTO api_users (id, username, password_hash, role, created_at)
		VALUES (?, ?, ?, ?, ?)`),
		u.ID, u.Username, u.PasswordHash, u.Role, time.Now().UTC())
	return err
}

func (s *SQLStore) GetAPIUser(ctx context.Context, username string) (*APIUser, error) {
	var u APIUser
	err := s.db.GetContext(ctx, &u, s.rebind(`
		SELECT id, username, password_hash, role, created_at, last_login
		FROM api_users WHERE username = ?`), username)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *SQLStore) RevokeAPIToken(ctx context.Context, tokenID string) error {
	_, err := s.db.ExecContext(ctx, s.rebind(`UPDATE api_tokens SET revoked = TRUE WHERE id = ?`), tokenID)
	return err
}

// Close closes the database connection.
func (s *SQLStore) Close() error {
	if s.db != nil {
		return s.db.Close()
	}
	return nil
}

// Ping checks database connectivity.
func (s *SQLStore) Ping() error {
	return s.db.Ping()
}

// DB returns the underlying sqlx.DB for advanced use.
func (s *SQLStore) DB() *sqlx.DB { return s.db }

// Ensure *SQLStore satisfies the Store interface at compile time.
var _ Store = (*SQLStore)(nil)

// Ensure *sql.NullString is handled (used for nullable fields in scans).
var _ = sql.NullString{}

// splitStatements splits a SQL script into individual statements
// by semicolons, respecting string literals and comments.
func splitStatements(script string) []string {
	var statements []string
	var current []byte
	inString := false
	for i := 0; i < len(script); i++ {
		ch := script[i]
		if ch == '\'' {
			inString = !inString
		}
		if ch == ';' && !inString {
			stmt := string(current)
			if trimSpace(stmt) != "" {
				statements = append(statements, stmt)
			}
			current = current[:0]
			continue
		}
		current = append(current, ch)
	}
	if len(current) > 0 {
		stmt := string(current)
		if trimSpace(stmt) != "" {
			statements = append(statements, stmt)
		}
	}
	return statements
}

// trimSpace removes leading and trailing whitespace.
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

// isDuplicateColumnErr returns true if the error is about a column
// already existing (for idempotent ALTER TABLE migrations).
func isDuplicateColumnErr(err error) bool {
	return err != nil && containsStr(err.Error(), "duplicate column")
}

// containsStr reports whether s contains substr.
func containsStr(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
