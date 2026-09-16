// Package main is the entry point for the go-p2pmesh client binary.
//
// The client is deployed on machines without public IPv4.  It connects
// to the server, joins rooms, establishes P2P tunnels with peers, creates
// a virtual NIC, and controls port access.
//
// Usage:
//
//	gop2pmesh-client [flags]
//
// Flags:
//
//	-c string      path to config file (default: client.ini)
//	-bootstrap string  comma-separated bootstrap server addresses
//	-listen int    sub-server listen port (0 = disabled)
//	-room string   room to join on startup
//	-roomkey string room password/key
//	-install       install as system service
//	-uninstall     uninstall system service
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiaoLangZe/go-p2pmesh/internal/config"
	"github.com/xiaoLangZe/go-p2pmesh/internal/sysutil"
	"github.com/xiaoLangZe/go-p2pmesh/pkg/client"
)

func main() {
	var (
		configFile string
		bootstrap  string
		listenPort int
		room       string
		roomKey    string
		logLevel   string
		install    bool
		uninstall  bool
	)

	flag.StringVar(&configFile, "c", "client.ini", "path to config file")
	flag.StringVar(&bootstrap, "bootstrap", "", "comma-separated bootstrap server addresses")
	flag.IntVar(&listenPort, "listen", -1, "sub-server listen port (0 = disabled)")
	flag.StringVar(&room, "room", "", "room to join on startup")
	flag.StringVar(&roomKey, "roomkey", "", "room password/key")
	flag.StringVar(&logLevel, "log.level", "", "override log level")
	flag.BoolVar(&install, "install", false, "install as system service")
	flag.BoolVar(&uninstall, "uninstall", false, "uninstall system service")
	flag.Parse()

	// Handle -install / -uninstall.
	if install {
		installer := sysutil.DefaultInstaller()
		if err := installer.Install("gop2pmesh-client", os.Args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("installed gop2pmesh-client as system service")
		return
	}
	if uninstall {
		installer := sysutil.DefaultInstaller()
		if err := installer.Uninstall("gop2pmesh-client"); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("uninstalled gop2pmesh-client system service")
		return
	}

	// Load config.
	var cfg *config.ClientConfig
	if config.Exists(configFile) {
		cfg, _ = config.LoadClientConfig(configFile)
	} else {
		cfg = config.DefaultClientConfig()
	}

	// Apply overrides.
	if bootstrap != "" {
		cfg.Bootstrap = splitComma(bootstrap)
	}
	if listenPort >= 0 {
		cfg.ListenPort = listenPort
	}
	if room != "" {
		cfg.AutoJoin = room
	}
	if roomKey != "" {
		cfg.RoomKey = roomKey
	}
	if logLevel != "" {
		cfg.LogLevel = logLevel
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// Build client options.
	opts := []client.Option{
		client.WithBootstrap(cfg.Bootstrap),
		client.WithListenPort(cfg.ListenPort),
		client.WithSTUNServers(cfg.StunServers),
		client.WithHolepunchParams(cfg.PredictWindow, cfg.PredictParallel),
		client.WithTunnelMTU(cfg.TunnelMTU),
		client.WithAllowUnreliableFallback(cfg.AllowUnreliableFallback),
		client.WithPortControlPolicy(cfg.PortControlPolicy),
		client.WithLogLevel(cfg.LogLevel),
	}
	if cfg.AutoJoin != "" {
		opts = append(opts, client.WithRoom(cfg.AutoJoin, cfg.RoomKey))
	}
	if cfg.TurnEnabled {
		opts = append(opts, client.WithTurn(cfg.TurnAddr))
	}
	if cfg.LogFile != "" {
		opts = append(opts, client.WithLogFile(cfg.LogFile))
	}

	cli, err := client.New(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create client: %v\n", err)
		os.Exit(1)
	}

	// Start client.
	errCh := make(chan error, 1)
	go func() {
		if err := cli.Start(); err != nil {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "client error: %v\n", err)
			os.Exit(1)
		}
	case sig := <-sigCh:
		slog.Info("received signal, shutting down", "signal", sig.String())
	}

	cli.Stop()
}

// splitComma splits a comma-separated string into trimmed fields.
func splitComma(s string) []string {
	var result []string
	for _, part := range split(s, ",") {
		part = trim(part)
		if part != "" {
			result = append(result, part)
		}
	}
	return result
}

func split(s, sep string) []string {
	var result []string
	for {
		i := indexOf(s, sep)
		if i < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:i])
		s = s[i+len(sep):]
	}
	return result
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func trim(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

// Ensure context is used (for future shutdown propagation).
var _ = context.Background
