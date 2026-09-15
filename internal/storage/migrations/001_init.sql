-- migrations/001_init.sql
-- Initial schema for go-p2pmesh server database.
-- Compatible with SQLite, MySQL (with minor dialect tweaks), PostgreSQL.

CREATE TABLE IF NOT EXISTS nodes (
    id          VARCHAR(64) PRIMARY KEY,
    pubkey      BLOB NOT NULL,
    room_id     VARCHAR(64),
    ipv6_addr   VARCHAR(39) UNIQUE,
    public_addr VARCHAR(255),
    nat_type    VARCHAR(32),
    status      VARCHAR(16) DEFAULT 'offline',
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen   TIMESTAMP
);

CREATE TABLE IF NOT EXISTS rooms (
    id          VARCHAR(64) PRIMARY KEY,
    name        VARCHAR(128) NOT NULL,
    owner_id    VARCHAR(64),
    encrypted   BOOLEAN DEFAULT FALSE,
    max_members INTEGER DEFAULT 100,
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS room_members (
    room_id   VARCHAR(64) NOT NULL,
    node_id   VARCHAR(64) NOT NULL,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (room_id, node_id),
    FOREIGN KEY (room_id) REFERENCES rooms(id) ON DELETE CASCADE,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS port_rules (
    id           VARCHAR(64) PRIMARY KEY,
    node_id      VARCHAR(64) NOT NULL,
    protocol     VARCHAR(8) NOT NULL,
    local_port   INTEGER NOT NULL,
    virtual_port INTEGER,
    description  TEXT,
    enabled      BOOLEAN DEFAULT TRUE,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (node_id) REFERENCES nodes(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS api_users (
    id            VARCHAR(64) PRIMARY KEY,
    username      VARCHAR(64) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role          VARCHAR(16) DEFAULT 'admin',
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login    TIMESTAMP
);

CREATE TABLE IF NOT EXISTS api_tokens (
    id         VARCHAR(64) PRIMARY KEY,
    user_id    VARCHAR(64) NOT NULL,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP,
    revoked    BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES api_users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    VARCHAR(64),
    action     VARCHAR(128) NOT NULL,
    resource   VARCHAR(255),
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_nodes_room ON nodes(room_id);
CREATE INDEX IF NOT EXISTS idx_nodes_status ON nodes(status);
CREATE INDEX IF NOT EXISTS idx_port_rules_node ON port_rules(node_id);
CREATE INDEX IF NOT EXISTS idx_room_members_node ON room_members(node_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
