// Package config implements the configuration loading logic for go-p2pmesh.
//
// Priority: command-line flag > environment variable > config file > default.
// The P1-baseline implementation uses a simple INI-style parser written with the
// standard library (no external dependency).  A later phase can swap in
// gopkg.in/ini.v1 if more features are needed.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// LoadINI reads a simple INI file and returns a nested map:
// map[section]map[key]string.  Lines starting with ';' or '#' are comments.
// Inline comments are not supported (values are taken verbatim after trim).
func LoadINI(path string) (map[string]map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config %q: %w", path, err)
	}
	defer f.Close()

	result := make(map[string]map[string]string)
	section := "" // empty section = root

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			if _, ok := result[section]; !ok {
				result[section] = make(map[string]string)
			}
			continue
		}
		// Key = value
		idx := strings.IndexByte(line, '=')
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(line[idx+1:])
		if section != "" {
			if result[section] == nil {
				result[section] = make(map[string]string)
			}
			result[section][key] = val
		} else {
			if result[""] == nil {
				result[""] = make(map[string]string)
			}
			result[""][key] = val
		}
	}
	return result, scanner.Err()
}

// GetString reads a string value from the parsed INI, returning the
// fallback if the key is absent.
func GetString(m map[string]map[string]string, section, key, fallback string) string {
	if s, ok := m[section]; ok {
		if v, ok := s[key]; ok && v != "" {
			return v
		}
	}
	return fallback
}

// GetInt reads an integer value from the parsed INI.
func GetInt(m map[string]map[string]string, section, key string, fallback int) int {
	if s, ok := m[section]; ok {
		if v, ok := s[key]; ok && v != "" {
			if n, err := strconv.Atoi(v); err == nil {
				return n
			}
		}
	}
	return fallback
}

// GetBool reads a boolean value from the parsed INI.
// Accepts "true/false", "1/0", "yes/no", "on/off".
func GetBool(m map[string]map[string]string, section, key string, fallback bool) bool {
	if s, ok := m[section]; ok {
		if v, ok := s[key]; ok && v != "" {
			return parseBool(v)
		}
	}
	return fallback
}

// GetStringSlice reads a comma-separated string into a slice.
func GetStringSlice(m map[string]map[string]string, section, key string, fallback []string) []string {
	if s, ok := m[section]; ok {
		if v, ok := s[key]; ok && v != "" {
			parts := strings.Split(v, ",")
			result := make([]string, 0, len(parts))
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if p != "" {
					result = append(result, p)
				}
			}
			return result
		}
	}
	return fallback
}

func parseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "1", "yes", "on":
		return true
	default:
		return false
	}
}

// Exists reports whether the given file path exists.
func Exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
