package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Config wraps the raw key/value config with typed accessors mirroring the
// Python `config.get(key, default)` semantics.
type Config struct {
	Raw map[string]interface{}
}

// DefaultConfig returns the default configuration (cli.py DEFAULT_CONFIG).
func DefaultConfig() *Config {
	raw := map[string]interface{}{
		"LISTEN_HOST":            "0.0.0.0",
		"LISTEN_PORT":            40443,
		// CONNECT_IP / FAKE_SNI stay nil so that "user did not set this"
		// checks (Get(key, nil) == nil) behave correctly; call sites carry
		// their own string fallbacks.
		"CONNECT_IP":             nil,
		"CONNECT_PORT":           443,
		"FAKE_SNI":               nil,
		"BYPASS_METHOD":          "fragment",
		"FRAGMENT_STRATEGY":      "sni_split",
		"FRAGMENT_DELAY":         0.1,
		"FAKE_SNI_METHOD":        "prefix_fake",
		"CIPHER_SUITES":          nil,
		"FINALMASK_TCP":          nil,
		"MITM_CERT_FILE":         nil,
		"MITM_KEY_FILE":          nil,
		"MITM_CERT_CN":           "SNISPF-HJ",
		"MITM_ALPN":              []interface{}{"h2", "http/1.1"},
		"MITM_USE_CLIENT_SNI":    false,
		"MITM_RAW_INJECTION":     false,
		"BYPASS_VPN":             false,
		"MAX_ACTIVE_CONNS":       512,
		"HANDSHAKE_TIMEOUT":      20,
		"IDLE_TIMEOUT":           300,
		"FINGERPRINT":            nil,
		"FINGERPRINT_TLS_BIN":    nil,
		"FAKE_SNI_FRAGMENT_REAL": true,
	}
	return &Config{Raw: raw}
}

// LoadConfig loads and merges a JSON config file over the defaults.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var userConfig map[string]interface{}
	if err := json.Unmarshal(data, &userConfig); err != nil {
		return nil, err
	}
	cfg := DefaultConfig()
	for k, v := range userConfig {
		cfg.Raw[k] = v
	}
	return cfg, nil
}

// Get returns the raw value or a default.
func (c *Config) Get(key string, def interface{}) interface{} {
	if v, ok := c.Raw[key]; ok {
		return v
	}
	return def
}

// Set stores a value.
func (c *Config) Set(key string, value interface{}) {
	c.Raw[key] = value
}

// GetBool coerces a value to bool.
func (c *Config) GetBool(key string, def bool) bool {
	v := c.Get(key, nil)
	switch t := v.(type) {
	case bool:
		return t
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true", "1", "yes", "on":
			return true
		case "false", "0", "no", "off", "":
			return false
		}
	case float64:
		return t != 0
	case int:
		return t != 0
	}
	return def
}

// GetInt coerces a value to int.
func (c *Config) GetInt(key string, def int) int {
	v := c.Get(key, nil)
	switch t := v.(type) {
	case float64:
		return int(t)
	case int:
		return t
	case string:
		var n int
		if _, err := fmt.Sscanf(t, "%d", &n); err == nil {
			return n
		}
	}
	return def
}

// GetFloat coerces a value to float64.
func (c *Config) GetFloat(key string, def float64) float64 {
	v := c.Get(key, nil)
	switch t := v.(type) {
	case float64:
		return t
	case int:
		return float64(t)
	case string:
		var f float64
		if _, err := fmt.Sscanf(t, "%g", &f); err == nil {
			return f
		}
	}
	return def
}

// GetString coerces a value to string.
func (c *Config) GetString(key string, def string) string {
	v := c.Get(key, nil)
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return fmt.Sprintf("%v", t)
	case bool:
		return fmt.Sprintf("%v", t)
	case nil:
		return def
	}
	return def
}

// GetList returns a value as a []interface{} (nil-safe).
func (c *Config) GetList(key string) []interface{} {
	switch t := c.Get(key, nil).(type) {
	case []interface{}:
		return t
	case []string:
		out := make([]interface{}, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	default:
		return nil
	}
}

// GetStringList returns a value as a []string.
func (c *Config) GetStringList(key string) []string {
	var out []string
	for _, v := range c.GetList(key) {
		out = append(out, fmt.Sprint(v))
	}
	return out
}

// LoadFinalmaskRules normalizes the FINALMASK_TCP value into a rules slice.
// Accepts: null, a JSON array of rule dicts, xray's {"tcp": [...]} wrapper, a
// path to a JSON file containing either, or an inline JSON string.
func LoadFinalmaskRules(value interface{}) []interface{} {
	if value == nil {
		return nil
	}
	switch t := value.(type) {
	case []interface{}:
		return t
	case []string:
		out := make([]interface{}, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	case map[string]interface{}:
		if tcp, ok := t["tcp"]; ok {
			if arr, ok := tcp.([]interface{}); ok {
				return arr
			}
		}
		return nil
	case string:
		path := strings.TrimSpace(t)
		if path == "" {
			return nil
		}
		if _, err := os.Stat(path); err == nil {
			data, err := os.ReadFile(path)
			if err == nil {
				var parsed interface{}
				if json.Unmarshal(data, &parsed) == nil {
					return LoadFinalmaskRules(parsed)
				}
			}
			return nil
		}
		var parsed interface{}
		if json.Unmarshal([]byte(path), &parsed) == nil {
			return LoadFinalmaskRules(parsed)
		}
		return nil
	default:
		return nil
	}
}

// CipherSuitesToOpenSSL turns a CIPHER_SUITES config value into an OpenSSL
// cipher-list string (used for diagnostics; Go's crypto/tls uses the raw IDs).
func CipherSuitesToOpenSSL(value interface{}) string {
	if value == nil {
		return ""
	}
	switch t := value.(type) {
	case []interface{}:
		var parts []string
		for _, x := range t {
			s := strings.TrimSpace(fmt.Sprint(x))
			if s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ":")
	case []string:
		var parts []string
		for _, s := range t {
			s = strings.TrimSpace(s)
			if s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ":")
	default:
		return strings.TrimSpace(fmt.Sprint(value))
	}
}

// GetConfigPath is a helper to read a config path from argv or default.
func GetConfigPath(args []string) string {
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "--config" || args[i] == "-C" {
			return args[i+1]
		}
	}
	return ""
}
