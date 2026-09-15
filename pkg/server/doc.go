/*
Package server provides the public API for embedding the go-p2pmesh
server into a third-party Go application.

The server is deployed on machines with public IPv4 and handles only
signaling, room management, node discovery, port authorization, and
provides a REST API for external management panels. It never forwards
business data, never creates a virtual NIC, and never participates in
hole punching.

# Quick start

	srv, err := server.New(
	    server.WithHost("0.0.0.0"),
	    server.WithPort(29683),
	    server.WithDatabase("sqlite", "data/gop2pmesh.db"),
	)
	if err != nil { log.Fatal(err) }

	go func() {
		if err := srv.Start(); err != nil {
			log.Fatal(err)
		}
	}()
	defer srv.Stop()
*/
package server
