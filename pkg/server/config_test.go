package server

import (
	"net"
	"testing"
)

// TestInvariantI5_APIDefaultsToLoopback enforces invariant I5: a component that
// needs network exposure must not be reachable by default. If the API silently
// defaulted to 0.0.0.0, every default deployment would expose its management
// surface to the network.
func TestInvariantI5_APIDefaultsToLoopback(t *testing.T) {
	cfg := DefaultConfig()

	ip := net.ParseIP(cfg.APIHost)
	if ip == nil {
		t.Fatalf("default API host %q is not a valid IP", cfg.APIHost)
	}
	if !ip.IsLoopback() {
		t.Errorf("I5 violated: default API host is %q, expected a loopback address", cfg.APIHost)
	}
}

// TestExplicitAPIBindIsAllowed checks an operator can still deliberately expose
// the API — I5 requires the default to be safe, not the option to be removed.
func TestExplicitAPIBindIsAllowed(t *testing.T) {
	srv, err := New(WithAPIHost("10.0.0.5"), WithDatabase("sqlite", t.TempDir()+"/x.db"))
	if err != nil {
		t.Fatalf("creating a server with an explicit API bind must succeed: %v", err)
	}
	// Stop even though Start() never ran: New() opened the database, so it must
	// be released or the temp directory cannot be removed on Windows.
	defer srv.Stop()
	if srv.cfg.APIHost != "10.0.0.5" {
		t.Errorf("explicit API host not applied: got %q", srv.cfg.APIHost)
	}
}

// TestStopBeforeStartReleasesStore guards the resource leak that an early return
// in Stop() used to cause: a constructed-but-unstarted server must still close
// its database handle.
func TestStopBeforeStartReleasesStore(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(WithDatabase("sqlite", dir+"/leak.db"))
	if err != nil {
		t.Fatal(err)
	}
	if srv.Store() == nil {
		t.Fatal("expected a store after New()")
	}
	srv.Stop()
	if srv.Store() != nil {
		t.Error("Stop() did not release the store")
	}
	// A second Stop must be a no-op rather than a double close or a panic.
	srv.Stop()
}

// TestConfigValidationRejectsBadValues checks misconfiguration fails at
// construction rather than at first use.
func TestConfigValidationRejectsBadValues(t *testing.T) {
	cases := []struct {
		name string
		opt  Option
	}{
		{"port too high", WithPort(70000)},
		{"port zero", WithPort(0)},
		{"unknown database", WithDatabase("oracle", "x")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opt); err == nil {
				t.Error("expected a validation error")
			}
		})
	}
}
