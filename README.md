# go-p2pmesh

A Go-based P2P mesh networking library with server/client separation, NAT traversal, virtual NIC, room isolation, and port access control.

## Overview

- **Server**: Deployed on machines with public IPv4. Handles signaling, room management, node discovery, port authorization, and provides a REST API for external management panels.
- **Client**: Deployed on machines without public IPv4. Establishes P2P tunnels with other clients, creates virtual NICs, and controls port access.

## Build

```bash
# Build server
go build -o gop2pmesh-server ./cmd/server

# Build client
go build -o gop2pmesh-client ./cmd/client

# Cross-compile (no CGO required)
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o gop2pmesh-server ./cmd/server
```

## Usage

```bash
# Server with default config
gop2pmesh-server

# Server with custom config
gop2pmesh-server -c /etc/gop2pmesh.ini

# Client with default config
gop2pmesh-client

# Client with specific bootstrap server
gop2pmesh-client -bootstrap 203.0.113.10:29683
```

## As a Go library

```go
import "github.com/yourorg/go-p2pmesh/pkg/server"
import "github.com/yourorg/go-p2pmesh/pkg/client"

srv, _ := server.New(server.WithHost("0.0.0.0"), server.WithPort(29683))
go srv.Start()
defer srv.Stop()
```

## License

MIT
