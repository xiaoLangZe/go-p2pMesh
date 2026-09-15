/*
Package client provides the public API for embedding the go-p2pmesh
client into a third-party Go application.

The client is deployed on machines without public IPv4. It connects to
the server, joins rooms, establishes P2P tunnels with peers, creates a
virtual NIC, and controls port access. A client can optionally open a
sub-server port for other clients to connect through.

# Quick start

	cli, err := client.New(
	    client.WithBootstrap([]string{"203.0.113.10:29683"}),
	    client.WithRoom("myroom", ""),
	    client.WithPortControlPolicy("deny"),
	)
	if err != nil { log.Fatal(err) }

	go func() {
		if err := cli.Start(); err != nil {
			log.Fatal(err)
		}
	}()
	defer cli.Stop()
*/
package client
