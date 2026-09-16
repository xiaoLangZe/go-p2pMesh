// Package main is the entry point for the go-p2pmesh server binary.
//
// The server is deployed on machines with public IPv4 and handles only
// signaling, room management, node discovery, port authorization, and
// provides a REST API for external management panels.  It never forwards
// business data, never creates a virtual NIC, and never participates in
// hole punching.
//
// Usage:
//
//	gop2pmesh-server [flags]
//
// Flags:
//
//	-c string    path to config file (default: server.ini)
//	-host string listening host:port override
//	-port int    listening port override
//	-install     install as system service
//	-uninstall   uninstall system service
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/xiaoLangZe/go-p2pmesh/internal/config"
	"github.com/xiaoLangZe/go-p2pmesh/internal/sysutil"
	"github.com/xiaoLangZe/go-p2pmesh/pkg/server"
)

func main() {
	var (
		configFile string
		hostPort   string
		port       int
		install    bool
		uninstall  bool
		dbType     string
		dbDSN      string
		logLevel   string
	)

	flag.StringVar(&configFile, "c", "server.ini", "path to config file")
	flag.StringVar(&hostPort, "host", "", "override listening host:port")
	flag.IntVar(&port, "port", 0, "override listening port")
	flag.BoolVar(&install, "install", false, "install as system service")
	flag.BoolVar(&uninstall, "uninstall", false, "uninstall system service")
	flag.StringVar(&dbType, "db.type", "", "override database type")
	flag.StringVar(&dbDSN, "db.dsn", "", "override database DSN")
	flag.StringVar(&logLevel, "log.level", "", "override log level")
	flag.Parse()

	// Handle -install / -uninstall before anything else.
	if install {
		installer := sysutil.DefaultInstaller()
		if err := installer.Install("gop2pmesh-server", os.Args[0]); err != nil {
			fmt.Fprintf(os.Stderr, "install failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("installed gop2pmesh-server as system service")
		return
	}
	if uninstall {
		installer := sysutil.DefaultInstaller()
		if err := installer.Uninstall("gop2pmesh-server"); err != nil {
			fmt.Fprintf(os.Stderr, "uninstall failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("uninstalled gop2pmesh-server system service")
		return
	}

	// Load config from file, or use defaults if file doesn't exist.
	var cfg *config.ServerConfig
	if config.Exists(configFile) {
		cfg, _ = config.LoadServerConfig(configFile)
	} else {
		cfg = config.DefaultServerConfig()
	}

	// Apply command-line overrides.
	if hostPort != "" {
		h, p, err := config.ParseHostPort(hostPort)
		if err == nil {
			cfg.Host = h
			cfg.Port = p
		}
	}
	if port != 0 {
		cfg.Port = port
	}
	if dbType != "" {
		cfg.DatabaseType = dbType
	}
	if dbDSN != "" {
		cfg.DatabaseDSN = dbDSN
	}
	if logLevel != "" {
		cfg.LogLevel = logLevel
	}

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "config error: %v\n", err)
		os.Exit(1)
	}

	// Build server options from config.
	opts := []server.Option{
		server.WithHost(cfg.Host),
		server.WithPort(cfg.Port),
		server.WithAPIHost(cfg.APIHost),
		server.WithAPIPort(cfg.APIPort),
		server.WithDatabase(cfg.DatabaseType, cfg.DatabaseDSN),
		server.WithAdminCredentials(cfg.AdminUser, cfg.AdminPassword),
		server.WithLogLevel(cfg.LogLevel),
	}
	if cfg.APICertFile != "" {
		opts = append(opts, server.WithAPICertFile(cfg.APICertFile))
	}
	if cfg.APIKeyFile != "" {
		opts = append(opts, server.WithAPIKeyFile(cfg.APIKeyFile))
	}
	if cfg.LogFile != "" {
		opts = append(opts, server.WithLogFile(cfg.LogFile))
	}

	srv, err := server.New(opts...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create server: %v\n", err)
		os.Exit(1)
	}

	// Start server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil {
			errCh <- err
		}
	}()

	// Wait for signal or startup error.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case err := <-errCh:
		if err != nil {
			fmt.Fprintf(os.Stderr, "server error: %v\n", err)
			os.Exit(1)
		}
	case sig := <-sigCh:
		slog.Info("received signal, shutting down", "signal", sig.String())
	}

	srv.Stop()
}
