//go:build linux

package tun

import (
	"os"
)

// osStat is a thin wrapper around os.Stat kept in a separate function so
// the fileWritable helper stays testable.
func osStat(path string) (os.FileInfo, error) {
	return os.Stat(path)
}
