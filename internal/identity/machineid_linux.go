//go:build linux

package identity

import (
	"fmt"
	"os"
)

// machineID reads /etc/machine-id or /var/lib/dbus/machine-id on Linux.
func machineID() (string, error) {
	for _, path := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		data, err := os.ReadFile(path)
		if err == nil {
			return string(data), nil
		}
		if !os.IsNotExist(err) {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
	}
	return "", fmt.Errorf("no machine-id file found")
}
