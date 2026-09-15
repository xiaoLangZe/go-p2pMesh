# go-p2pmesh

[English](README.md) | [简体中文](README.zh-CN.md)

A Go-based P2P mesh networking library, built as two binaries — a server and a
client — that share one module.

> Status: under active development. Interfaces may change.

## Overview

- **Server** — deployed on machines with a public IPv4 address. It handles
  signaling, room management, node discovery and port authorization, and
  exposes a REST API for external management panels. It never relays business
  traffic.
- **Client** — deployed on machines behind NAT. It establishes P2P tunnels with
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

Start from `configs/server.ini.example` or `configs/client.ini.example`; the
comments in those files document every option.

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

MIT — see [LICENSE](LICENSE).
