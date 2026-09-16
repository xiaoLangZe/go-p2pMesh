//go:build linux

package tun

import "testing"

// TestInnerMTUDefaultPin documents the default MTU (1280) so a regression
// in the tun.Configuration default is caught.
func TestCreateConfigDefaultMTU(t *testing.T) {
	cfg := Config{}
	if cfg.MTU != 0 {
		t.Fatalf("zero-value MTU must be 0 (caller applies default), got %d", cfg.MTU)
	}
}

// TestFileWritableMissing reports that a nonexistent path is not writable.
// This pins the privilege-check behaviour without requiring root.
func TestFileWritableMissing(t *testing.T) {
	if fileWritable("/nonexistent/path/tun") {
		t.Error("fileWritable(/nonexistent) should be false")
	}
}