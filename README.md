# go-p2pmesh

English | [简体中文](README.zh-CN.md)

A P2P networking architecture built with Go.

One codebase provides two roles: a **server** that only coordinates (discovery,
signaling, room state, port authorization) and a **client** that establishes
encrypted peer-to-peer tunnels to other nodes and exposes them to local
applications through a virtual NIC.

> Status: under active development. The protocol, cryptographic, identity,
> configuration and storage layers are implemented; the data plane is
> scaffolded and is being filled in phase by phase. See
> [Implementation status](#implementation-status) for the exact per-package
> state before you depend on any specific behaviour.

## What it does today

- **Deterministic node identity.** A NodeID is derived from a machine
  fingerprint: SHA-256 over the collected fingerprint, base32-encoded, truncated
  to 26 characters and formatted as `8-4-4-4-6` segments using the `[a-z0-9-]`
  alphabet. Two Ed25519/X25519 key pairs are generated alongside it and
  persisted to a local file with `0600` permissions.
- **Deterministic mesh addressing.** Each node's IPv6 ULA address is computed
  from its NodeID alone - no central allocator, no DHCP, and no lookup needed to
  route. The address is reproducible by any peer that knows the NodeID.
- **Authenticated key agreement.** A Noise `IK` handshake
  (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) with explicit initiator and responder
  state machines, transport ciphers after completion, and Ed25519-signed node
  certificates carrying a `client`, `bootstrap` or `root` role. Trust-on-first-use
  is available for offline deployments.
- **Typed control protocol.** Fourteen message types exchanged over a
  length-prefixed binary framing with JSON payloads.
- **Bootstrap server.** A TCP control listener with a per-connection message
  loop, a keepalive read deadline, the `HELLO`/`CHALLENGE` exchange, and dispatch
  for NAT reports, room join/leave and punch requests.
- **Server mesh.** An in-memory server table with TTL expiry plus a periodic
  full-table gossip round and a cleanup sweep.
- **Pluggable storage.** A `Store` interface with a SQL implementation on
  `database/sql` + `sqlx` and a migration covering nodes, rooms, room members,
  port rules, API users, API tokens and audit logs. The SQLite driver is pure Go,
  so no CGO toolchain is required.
- **Rooms.** A client-side membership cache driven by server pushes, and a room
  model carrying owner, encryption flag and member cap.
- **Port access control.** A default-deny (or default-allow) policy with
  per-node rules indexed by both virtual and local port.
- **Routing tables.** IPv6-to-peer lookup with room scoping, ready to back the
  TUN data path.
- **Configuration and operations.** INI configuration with defaults, validation
  and CLI overrides; both binaries install and uninstall themselves as a system
  service on Windows, Linux and macOS, and shut down gracefully on
  `SIGINT`/`SIGTERM`.

## Architecture

The system is split into three layers with deliberately different trust
properties.

**Control plane.** A bootstrap server, listening on TCP (default port `29683`),
performs discovery, signaling, room management and NAT-information exchange. It
is the only component that is expected to be reachable at a stable public
address. Clients also reconnect through it after network changes. Crucially, the
control plane is not in the payload path.

**Data plane.** Peers exchange traffic directly over UDP, with KCP layered on
top to provide reliable, ordered delivery with tunable latency/bandwidth
trade-offs over an unreliable datagram path. TCP is retained only as a fallback
for the case where UDP is unusable end to end. An optional TURN relay can be
enabled as a last resort for pairs that cannot punch through at all.

**Virtual NIC.** Each client creates a cross-platform TUN device (Linux
`/dev/net/tun`, macOS `utun`, Windows `wintun.dll` loaded at runtime) and assigns
itself an address inside one IPv6 ULA prefix. Applications talk to each other
through this interface without being modified.

**Hard constraint: the bootstrap server never relays business data.** It does
not create a TUN device, does not join the mesh as a data-plane peer, and does
not participate in hole punching. This keeps the operator of the coordination
point out of the data path entirely: a compromised or curious server can observe
who is talking to whom and when, but not what is transferred. Relaying, when it
happens at all, is a separate optional role that forwards only opaque ciphertext.

## Design rationale

**Why an overlay with a virtual NIC.** The alternative - a proxy or an SDK each
application must adopt - forces per-application work and moves access control
into user space. Putting an L3 interface under the applications means existing
software connects unchanged, and policy can be applied to addresses and ports
rather than to application identities.

**Why deterministic IPv6 ULA addressing.** A mesh has no natural place to run a
DHCP-equivalent, and a central allocator would become both a bottleneck and a
single point of failure. Deriving the address from the NodeID makes allocation
a pure function, lets any peer compute the destination before the tunnel exists,
and keeps the mapping stable across restarts. A `/64` also leaves room to
partition addresses by room or by service later.

**Why UDP with KCP rather than TCP.** A TCP tunnel over a lossy, hole-punched
path suffers from head-of-line blocking and collapses its congestion window
under exactly the conditions the mesh is built for. Raw UDP avoids that but
leaves reliability to the application. KCP sits in between: it provides reliable
ordered delivery while exposing the retransmission and window parameters, so the
transport can be tuned for the path's actual loss profile. TCP is kept as a
fallback rather than a peer of UDP because it is the option of last resort, not
a comparable choice.

**Why a Noise IK handshake.** `IK` assumes the initiator already knows the
responder's static public key, authenticates the responder in the first message,
and encrypts the initiator's own static key in that same message. That matches a
mesh's reality - peers learn each other's public keys from the control plane
before they connect - and it hides identities from a passive observer without
adding a round trip. The cipher suite is `25519/ChaChaPoly/BLAKE2s`.

**Why role-scoped certificates.** "Any client may act as a server" is a
man-in-the-middle invitation: without authorization, an attacker who can answer
faster than the real server simply becomes it. Certificates signed by a root key
and bound to the node's Noise static key let a peer verify that a claiming
sub-bootstrap server is actually authorized to hold that role. Trust-on-first-use
exists for deployments that cannot run a root key exchange.

**Why relaying is optional and separate.** Relay capacity is the scarcest and
most abusable resource in a mesh, and it is the only path where a third party
handles traffic between two peers. Keeping it off by default, out of the
bootstrap server, and limited to forwarding ciphertext means the default
deployment has no central element that can read payloads.

## Control protocol

Messages are framed as an 8-byte header (big-endian `uint32` message type,
big-endian `uint32` body length) followed by a JSON body of up to 16 MiB:

```
+----------------+----------------+---------------------+
| type (4 bytes) | length (4)     | JSON payload (N)    |
+----------------+----------------+---------------------+
```

JSON was chosen deliberately over protobuf for the current phase to avoid a code
generation step; the framing is independent of the payload encoding, so a later
switch does not affect connection handling.

| # | Message | Direction | Purpose |
| --- | --- | --- | --- |
| 1 | `HELLO` | client to server | Announces NodeID, public key, optional certificate and protocol version. |
| 2 | `CHALLENGE` | server to client | Returns a 32-byte nonce, the server certificate and a server-table snapshot. |
| 3 | `AUTH` | client to server | Carries the Noise handshake message. |
| 4 | `AUTH_OK` | server to client | Confirms authentication, assigns the IPv6 address and lists bootstrap peers. |
| 5 | `NAT_PROBE` | client to server | Reports detected NAT type, public address, optional public IPv6 address and port samples for symmetric prediction. |
| 6 | `NAT_RESULT` | server to client | Confirms NAT information and relays a peer's NAT details. |
| 7 | `PUNCH_REQ` | client to server | Requests punch information for a target node. |
| 8 | `PUNCH_INFO` | server to client | Returns the target's public address, NAT type, predicted port range and a synchronized firing timestamp. |
| 9 | `KEEPALIVE` | both ways | Heartbeat carrying a Unix timestamp. |
| 10 | `PEER_LIST` | server to client | Periodic push of online nodes with their addresses, NAT types and rooms. |
| 11 | `ROOM_MEMBERS` | server to client | Pushes the member list of a room. |
| 12 | `ROOM_JOIN` | client to server | Requests to join a room, with an optional password. |
| 13 | `ROOM_LEAVE` | client to server | Leaves the current room. |
| 14 | `PORT_RULE_SYNC` | server to client | Pushes the port access rules that apply to the client. |

The synchronized `PUNCH_INFO` timestamp is what lets both peers start firing at
the same instant without an extra negotiation round: the server, not either peer,
decides when the attempt begins.

## Identity and trust

A node's identity has three components:

| Component | Derivation | Use |
| --- | --- | --- |
| NodeID | SHA-256 of the machine fingerprint, base32, 26 chars, `8-4-4-4-6` segments | Stable, human-transcribable name and the input to address derivation. |
| Ed25519 key pair | Generated locally | Signing, and the root of the certificate chain. |
| X25519 key pair | Generated locally | The Noise static key used in the handshake. |

NodeIDs are case-insensitive and constrained to `[a-z0-9-]` with no leading,
trailing or consecutive dashes, so an ID can be safely used as a filename, a
database key or a URL path segment. A secondary fingerprint is available as the
SHA-256 of the X25519 public key, which is useful for pinning.

Certificates bind a NodeID, an X25519 public key, a role (`client`,
`bootstrap`, `root`) and an optional expiry, signed by the root Ed25519 key over
a canonical byte encoding of exactly those fields. Verification checks that
signature against the signer key embedded in the certificate; with
trust-on-first-use enabled, an unsigned first contact is accepted and the public
key is remembered for subsequent connections.

## NAT traversal

Traversal follows a fixed priority matrix, from the cheapest and most direct
option to the most expensive:

| Priority | Strategy | Applies when |
| --- | --- | --- |
| 1 | `ipv6_direct` | Both peers have a usable IPv6 path. No punching needed. |
| 2 | `udp_standard` | Both peers have cone NATs, so a single outbound packet opens the path. |
| 3 | `udp_predict` | At least one side is behind symmetric NAT and the mapped port must be predicted. |
| 4 | `tcp_simultaneous` | UDP is unusable end to end and a simultaneous TCP open is required. |
| 5 | `turn_relay` | No direct path can be established and a relay is configured. |

Symmetric NAT is the hard case: because the external port changes per
destination, the peers cannot learn the port that will be used toward each
other. The approach is port prediction - sampling observed mappings to infer the
allocation pattern - combined with synchronized parallel firing across a
predicted window. This is best-effort by nature and depends on the NAT's
allocation policy being predictable at all.

The NAT taxonomy used for classification is `Open`, `FullCone`,
`RestrictedCone`, `PortRestricted`, `Symmetric` and `Unknown`. Only a STUN
client is implemented; the project never operates a STUN server, relying on
third-party public servers instead.

## Rooms

A room is an isolation unit, not a chat channel: only members of the same room
are told about each other's addresses, and therefore only they can attempt
tunnels. Room membership is the authorization boundary for discovery.

A room carries an ID, a display name, an owner, an `encrypted` flag and a member
cap. The server-side manager and the client-side membership cache are separate
concerns: the client keeps the member set it was last told about and reacts to
join, leave and update pushes.

## Port access control

The default policy is deny. Under it, traffic addressed to an unconfigured port
is rejected; only explicitly configured rules are allowed. The alternative
policy, allow, inverts this and permits everything not explicitly configured,
which is appropriate only for a fully trusted room.

Rules map a **virtual port** - the port a peer addresses on the target's mesh
IPv6 address - to a **local port** on the target machine. The controller indexes
rules by both, so it can answer two different questions: whether an inbound
connection to a virtual port is permitted, and which rule owns a given local
port. Deliberately, a peer cannot reach a service by addressing its real local
port; only the virtual mapping is reachable, which keeps the mapping layer
between the mesh and the host a genuine boundary rather than a convenience.

## Server mesh

Bootstrap servers form their own mesh so that a client only needs to know one
reachable address. The server table holds each known server's address, public
key, ID, last-seen time, load and whether it is a root. Entries expire on a TTL,
and two loops keep the table current: a periodic full-table gossip round and a
cleanup sweep that drops entries older than the timeout. A client receives a
snapshot of this table in the `CHALLENGE` response and a peer list in
`AUTH_OK`, so it can fail over to another server without being reconfigured.

## Package layout

```
cmd/
  server/       server binary: flags, config, service install, signal handling
  client/       client binary: same, plus room and tunnel flags
internal/
  protocol/     control-plane message types and length-prefixed framing
  crypto/       Noise IK state machine, Ed25519 keys, certificate signing
  identity/     machine fingerprint, NodeID derivation, key persistence
  config/       INI loading, defaults, validation
  bootstrap/    control-plane server and client connection logic
  servermesh/   server table and gossip loops
  room/         room model, client cache, server manager
  routing/      IPv6-to-peer table and router
  portcontrol/  port access rules and virtual port mapping
  stun/         STUN client and NAT type taxonomy
  holepunch/    hole-punching strategy matrix
  tunnel/       KCP+Noise tunnel and tunnel manager
  tun/          cross-platform virtual NIC abstraction
  relay/        optional TURN relay
  storage/      Store interface, SQL backend, migrations
  api/          REST management API and middleware
  sysutil/      system service installation
pkg/
  server/       public library API for embedding the server
  client/       public library API for embedding the client
  types/        shared public types (NodeID, Room, addresses, identity)
```

The split between `internal/` and `pkg/` is intentional: `pkg/` is the supported
surface for third-party embedding, while `internal/` can change without notice.

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

cli, _ := client.New(
    client.WithBootstrap([]string{"203.0.113.10:29683"}),
    client.WithRoom("myroom", ""),
)
go cli.Start()
defer cli.Stop()
```

Options are functional: each `With*` mutates a config struct that is validated by
`New` before any subsystem is constructed. Passing an invalid combination - no
bootstrap server, an MTU below `576`, an unknown port policy - fails at
construction time rather than at first use.

## Implementation status

The codebase is being built in phases. The table below records what is
functional today, so that the architecture above is not mistaken for working
software.

| Area | State |
| --- | --- |
| Control-plane protocol (types, framing, encode/decode) | Implemented |
| Noise IK handshake, Ed25519 signing, certificates, TOFU | Implemented |
| Node identity, NodeID derivation, IPv6 address derivation | Implemented |
| Configuration loading, defaults, validation, CLI overrides | Implemented |
| Storage interface, SQL backend, schema and migrations | Implemented |
| Peer table, router lookup, server table, port rule registry | Implemented |
| Bootstrap server: listener, message loop, `HELLO`/`CHALLENGE`, dispatch | Implemented |
| Server mesh loops (gossip round, TTL cleanup) | Table and loops run; gossip sends no wire traffic yet |
| Client-side room membership cache | Implemented |
| Binary lifecycle: service install, signals, graceful shutdown | Implemented |
| KCP+Noise tunnel read/write | Scaffolded, returns `ErrNotImplemented` |
| Hole punching execution | Strategy matrix defined, execution not implemented |
| STUN binding and NAT classification | Types and pool implemented, probing not implemented |
| TUN device creation | Interface defined, platform implementations not implemented |
| Packet forwarding between TUN and tunnels | Not implemented |
| REST API handlers and middleware | Scaffolded; middleware currently passes through |
| Server-side room manager | Scaffolded, returns `ErrNotImplemented` |
| TURN relay | Scaffolded, returns `ErrNotImplemented` |
| Server-to-server gossip wire protocol | Message types declared, transport not implemented |

Several configuration keys are already parsed but not yet consumed by the
binaries while their subsystems are being implemented; setting them has no
effect until the corresponding phase lands.

## Roadmap

Phase markers in the source indicate how the remaining work is sequenced. The
table lists the markers that actually appear in the code, so the numbering is
deliberately not contiguous:

| Phase | Scope |
| --- | --- |
| P0 | Package scaffolding, type system, interfaces. |
| P1 | Control-plane protocol, handshake and message loop. |
| P2 | Storage-backed room manager, rule persistence, packet forwarding via a userspace network stack. |
| P3 | REST API security: JWT verification, mTLS, rate limiting, audit logging. |
| P5 | NAT traversal: STUN binding and health checks, port prediction and the hole-punching matrix. |
| P8 | Platform privilege checks for the system service (capability and elevation detection). |

## License

MIT - see [LICENSE](LICENSE).
