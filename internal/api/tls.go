package api

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"time"
)

// BuildTLSConfig assembles the HTTPS listener configuration (§9.1 #1/#3):
// TLS ≥ 1.2 with mandatory certificate, and client-certificate
// verification exactly when a CA file is configured (mTLS opt-in).
//
// clientCAFile empty → no client-cert requirement (operator's explicit
// choice; the design recommends providing it).
func BuildTLSConfig(certFile, keyFile, clientCAFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("api: tls requires cert_file and key_file")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("api: load key pair: %w", err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	if clientCAFile != "" {
		pem, err := os.ReadFile(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("api: read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("api: no certificates in client CA file")
		}
		cfg.ClientCAs = pool
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return cfg, nil
}

// tokenLifetimes are the §9.1 #2 defaults: access 24h, refresh 7d.
const (
	DefaultAccessTTL   = 24 * time.Hour
	DefaultRefreshTTL  = 7 * 24 * time.Hour
)

// loginRatePerMin is the §9.1 #6 hard target.
const loginRatePerMin = 5