//go:build darwin

package identity

import (
	"fmt"
	"os/exec"
	"strings"
)

// machineID reads the IOPlatformUUID on macOS via ioreg.
func machineID() (string, error) {
	cmd := exec.Command("ioreg", "-d2", "-c", "IOPlatformExpertDevice")
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("run ioreg: %w", err)
	}
	// Search for "IOPlatformUUID" in the output.
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			// Format: "IOPlatformUUID" = "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			uuid := strings.Trim(strings.TrimSpace(parts[1]), "\"")
			if uuid != "" {
				return uuid, nil
			}
		}
	}
	return "", fmt.Errorf("IOPlatformUUID not found in ioreg output")
}
