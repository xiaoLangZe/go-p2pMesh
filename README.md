# go-p2pmesh

English | [简体中文](README.zh-CN.md)

A Go-based P2P mesh networking library, built as two binaries (a server and a
client) that share one module.

> Status: under active development. Interfaces may change.

## Overview

- **Server**: deployed on machines with a public IPv4 address. It handles
  signaling, room management, node discovery and port authorization, and
  exposes a REST API for external management panels. It never relays business
  traffic.
- **Client**: deployed on machines behind NAT. It establishes P2P tunnels with
  other peers, creates a virtual NIC, and enforces port access rules.

## Features

- Control plane over TCP with a Noise (IK) handshake; bootstrap servers only
  coordinate discovery and hole punching.
- Data plane over UDP with a KCP reliability layer, falling back to TCP when UDP
  is unavailable. An optional TURN relay can be enabled as a last resort.
- NAT traversal: IPv6 direct connection first, then UDP hole punching, with port
  prediction for symmetric NAT.
- Cross-platform virtual NIC (TUN) on Windows, Linux and macOS, sharing a single
  IPv6 ULA prefix.
- Room isolation and per-node port access control.
- Pluggable storage backend, SQLite by default.

## Build

```bash
go build -o gop2pmesh-server ./cmd/server
go build -o gop2pmesh-client ./cmd/client
```

Cross-compiling needs no CGO:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gop2pmesh-server ./cmd/server
```

## Usage

```bash
# Server with the default config
gop2pmesh-server

# Server with a specific config file
gop2pmesh-server -c /etc/gop2pmesh.ini

# Client with the default config
gop2pmesh-client

# Client pointing at a specific bootstrap server
gop2pmesh-client -bootstrap 203.0.113.10:29683
```

Both binaries can be installed as a system service with `-install` and removed
with `-uninstall`.

## Configuration

Both binaries read an INI file passed with `-c`. The default file names are
`server.ini` and `client.ini`; when the file is absent, built-in defaults are
used. Templates with the same keys and comments live in `configs/`.

### Server (`server.ini`)

`[server]`

| Key | Default | Description |
| --- | --- | --- |
| `host` | `0.0.0.0` | Address the control-plane listener binds to. |
| `port` | `29683` | Control-plane port used for signaling and discovery. |
| `mesh_peers` | none | Other bootstrap servers to sync with, comma-separated. |

`[api]`

| Key | Default | Description |
| --- | --- | --- |
| `enabled` | `true` | Enable the REST management API. |
| `host` | `0.0.0.0` | Address the API listener binds to. |
| `port` | `29684` | API listener port. |
| `cert_file` | `server.crt` | TLS certificate used to serve HTTPS. |
| `key_file` | `server.key` | TLS private key for that certificate. |
| `client_ca_file` | `clients_ca.crt` | CA used to verify client certificates (mTLS). |
| `jwt_secret` | auto | JWT signing secret; generated on first start when empty. |
| `token_ttl_hours` | `24` | Lifetime of issued API tokens. |
| `admin_user` | `admin` | Initial admin account, created on first start. |
| `admin_password` | auto | Initial admin password; a random one is generated when empty. |

`[database]`

| Key | Default | Description |
| --- | --- | --- |
| `type` | `sqlite` | One of `sqlite`, `mysql`, `postgresql`, `mongodb`. |
| `dsn` | `data/gop2pmesh.db` | Driver-specific connection string. |
| `max_open_conns` | `50` | Maximum number of open connections in the pool. |
| `max_idle_conns` | `10` | Maximum number of idle connections in the pool. |

`[network]`

| Key | Default | Description |
| --- | --- | --- |
| `cidr` | `fd00:9bd8::/64` | Internal IPv6 ULA prefix assigned to nodes. |

`[security]`

| Key | Default | Description |
| --- | --- | --- |
| `root_key_file` | `root.key` | Root key that signs node certificates; generated on first start. |
| `trust_on_first_use` | `false` | Accept a node on first contact without a verified certificate chain. |
| `node_timeout` | `90s` | How long a node may stay silent before it is marked offline. |

`[log]`

| Key | Default | Description |
| --- | --- | --- |
| `level` | `info` | One of `debug`, `info`, `warn`, `error`. |
| `file` | empty | Log file path; empty logs to standard output. |

### Client (`client.ini`)

`[client]`

| Key | Default | Description |
| --- | --- | --- |
| `bootstrap` | none | Bootstrap server addresses, comma-separated; the lowest-latency one is selected. |
| `listen_port` | `0` | Port on which this client also serves as a sub-bootstrap server; `0` disables it. |
| `node_id` | auto | Node identifier; generated and persisted on first start when empty. |

`[room]`

| Key | Default | Description |
| --- | --- | --- |
| `auto_join` | empty | Room to join at startup. |
| `room_key` | empty | End-to-end encryption key for that room. |

`[stun]`

| Key | Default | Description |
| --- | --- | --- |
| `servers` | public STUN list | Third-party STUN servers used for NAT discovery. |
| `timeout_ms` | `3000` | Per-request STUN timeout, in milliseconds. |
| `predict_samples` | `8` | Samples collected for NAT port prediction. |
| `ipv6` | `true` | Also probe the IPv6 path. |

`[holepunch]`

| Key | Default | Description |
| --- | --- | --- |
| `predict_window` | `64` | Size of the predicted port window. |
| `predict_parallel` | `256` | Number of parallel hole-punch attempts. |
| `turn` | `false` | Enable the TURN relay as a last resort. |
| `turn_addr` | empty | TURN server address; required when `turn` is enabled. |

`[tunnel]`

| Key | Default | Description |
| --- | --- | --- |
| `mtu` | `1280` | MTU of the tunnel interface; must be at least `576`. |
| `kcp_window` | `256` | KCP send and receive window size. |

`[network]`

| Key | Default | Description |
| --- | --- | --- |
| `cidr` | `fd00:9bd8::/64` | Internal IPv6 ULA prefix; must match the server. |

`[portcontrol]`

| Key | Default | Description |
| --- | --- | --- |
| `default_policy` | `deny` | `deny` rejects unconfigured ports, `allow` permits them. |
| `db_file` | `portcontrol.db` | SQLite file holding the port rules. |

`[identity]`

| Key | Default | Description |
| --- | --- | --- |
| `key_file` | `identity.key` | Private key identifying this node; generated on first start. |

`[log]`

| Key | Default | Description |
| --- | --- | --- |
| `level` | `info` | One of `debug`, `info`, `warn`, `error`. |
| `file` | empty | Log file path; empty logs to standard output. |

### Command-line overrides

| Flag | Applies to | Effect |
| --- | --- | --- |
| `-c` | both | Path to the config file. |
| `-install`, `-uninstall` | both | Install or remove the system service. |
| `-host`, `-port` | server | Control-plane listen address. |
| `-db.type`, `-db.dsn` | server | Storage backend and connection string. |
| `-log.level` | both | Log level. |
| `-bootstrap` | client | Comma-separated bootstrap server addresses. |
| `-listen` | client | Sub-bootstrap listen port. |
| `-room`, `-roomkey` | client | Room to join at startup and its key. |

## As a Go library

```go
import (
    "github.com/yourorg/go-p2pmesh/pkg/server"
    "github.com/yourorg/go-p2pmesh/pkg/client"
)

srv, _ := server.New(server.WithHost("0.0.0.0"), server.WithPort(29683))
go srv.Start()
defer srv.Stop()
```

## License

MIT - see [LICENSE](LICENSE).
