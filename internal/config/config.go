package config

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
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
		"MITM_ECH_CONFIG_LIST":   "",
		"MITM_ECH_FORCE_QUERY":   "best-effort",
		"MITM_RAW_INJECTION":     false,
		"BYPASS_VPN":             false,
		"MAX_ACTIVE_CONNS":       512,
		"HANDSHAKE_TIMEOUT":      20,
		"IDLE_TIMEOUT":           300,
		"FINGERPRINT":            nil,
		"FINGERPRINT_TLS_BIN":    nil,
		"FAKE_SNI_FRAGMENT_REAL": true,
		"DATA_CHECK":             true,
		"DATA_CHECK_PATH":        "/cdn-cgi/trace",
		"DATA_CHECK_STRICT":      false,
		"DATA_CHECK_TIMEOUT":     3.0,
		"LAST_GOOD_FILE":         "",
		"LAST_GOOD_TTL_SECONDS":  86400,
		"LAST_GOOD_SAVE_SECONDS": 30,
		"CONFIG_WATCH":           true,
		"CONFIG_WATCH_SECONDS":   2.0,
	}
	return &Config{Raw: raw}
}

// KeyDefinition defines validation and reload rules for known config keys.
type KeyDefinition struct {
	Reloadable bool
}

var KnownKeys = map[string]KeyDefinition{
	"LISTEN_HOST":                      {Reloadable: false},
	"LISTEN_PORT":                      {Reloadable: false},
	"CONNECT_IP":                       {Reloadable: false},
	"CONNECT_PORT":                     {Reloadable: false},
	"CONNECT_IPS":                      {Reloadable: false},
	"FAKE_SNI":                         {Reloadable: false},
	"FAKE_SNIS":                        {Reloadable: false},
	"BYPASS_METHOD":                    {Reloadable: false},
	"FRAGMENT_STRATEGY":                {Reloadable: true},
	"FRAGMENT_DELAY":                   {Reloadable: true},
	"FAKE_SNI_METHOD":                  {Reloadable: true},
	"CIPHER_SUITES":                    {Reloadable: true},
	"FINALMASK_TCP":                    {Reloadable: true},
	"MITM_CERT_FILE":                   {Reloadable: false},
	"MITM_KEY_FILE":                    {Reloadable: false},
	"MITM_CERT_CN":                     {Reloadable: false},
	"MITM_ALPN":                        {Reloadable: true},
	"MITM_USE_CLIENT_SNI":              {Reloadable: true},
	"MITM_ECH_CONFIG_LIST":             {Reloadable: true},
	"MITM_ECH_FORCE_QUERY":             {Reloadable: true},
	"MITM_RAW_INJECTION":               {Reloadable: true},
	"BYPASS_VPN":                       {Reloadable: false},
	"MAX_ACTIVE_CONNS":                 {Reloadable: true},
	"HANDSHAKE_TIMEOUT":                {Reloadable: true},
	"IDLE_TIMEOUT":                     {Reloadable: true},
	"FINGERPRINT":                      {Reloadable: true},
	"FINGERPRINT_TLS_BIN":              {Reloadable: true},
	"FAKE_SNI_FRAGMENT_REAL":           {Reloadable: true},
	"DATA_CHECK":                       {Reloadable: true},
	"DATA_CHECK_PATH":                  {Reloadable: true},
	"DATA_CHECK_STRICT":                {Reloadable: true},
	"DATA_CHECK_TIMEOUT":               {Reloadable: true},
	"LAST_GOOD_FILE":                   {Reloadable: true},
	"LAST_GOOD_TTL_SECONDS":            {Reloadable: true},
	"LAST_GOOD_SAVE_SECONDS":           {Reloadable: true},
	"CONFIG_WATCH":                     {Reloadable: true},
	"CONFIG_WATCH_SECONDS":             {Reloadable: true},
	"ACTIVE_SLOTS":                     {Reloadable: true},
	"HEALTH_CHECK_INTERVAL":            {Reloadable: true},
	"HEALTH_CHECK_TIMEOUT":             {Reloadable: true},
	"PROBE_COUNT":                      {Reloadable: true},
	"LOSS_THRESHOLD":                   {Reloadable: true},
	"DEAD_THRESHOLD":                   {Reloadable: true},
	"DRAIN_TIMEOUT":                    {Reloadable: true},
	"MAX_DRAINING":                     {Reloadable: true},
	"EVICT_EVERY":                      {Reloadable: true},
	"EVICT_COUNT":                      {Reloadable: true},
	"RECYCLE_ENABLED":                  {Reloadable: true},
	"RECYCLE_EVERY":                    {Reloadable: true},
	"RECYCLE_BATCH":                    {Reloadable: true},
	"RECYCLE_MIN_COOLDOWN":             {Reloadable: true},
	"RECYCLE_MAX_QUARANTINE":           {Reloadable: true},
	"QUARANTINE_SCOPE":                 {Reloadable: true},
	"SNI_EVICT_EVERY":                  {Reloadable: true},
	"SNI_EVICT_COUNT":                  {Reloadable: true},
	"SNI_RECYCLE_ENABLED":              {Reloadable: true},
	"SNI_RECYCLE_EVERY":                {Reloadable: true},
	"SNI_RECYCLE_BATCH":                {Reloadable: true},
	"SNI_RECYCLE_MIN_COOLDOWN":         {Reloadable: true},
	"SNI_RECYCLE_MAX_QUARANTINE":       {Reloadable: true},
	"SNI_QUARANTINE_SCOPE":             {Reloadable: true},
	"DYNAMIC_IP_DISCOVERY":             {Reloadable: true},
	"DISCOVERY_BATCH":                  {Reloadable: true},
	"DISCOVERY_INTERVAL":               {Reloadable: true},
	"DISCOVERY_PROBE_TRIES":            {Reloadable: true},
	"DISCOVERY_TIMEOUT":                {Reloadable: true},
	"DISCOVERY_MIN_SUCCESS":            {Reloadable: true},
	"DISCOVERY_MAX_IPS":                {Reloadable: true},
	"DYNAMIC_SNI_DISCOVERY":            {Reloadable: true},
	"SNI_DISCOVERY_BATCH":              {Reloadable: true},
	"SNI_DISCOVERY_INTERVAL":           {Reloadable: true},
	"SNI_SOURCE_REFRESH_INTERVAL":      {Reloadable: true},
	"SNI_DISCOVERY_PROBE_TRIES":        {Reloadable: true},
	"SNI_DISCOVERY_TIMEOUT":            {Reloadable: true},
	"SNI_DISCOVERY_MIN_SUCCESS":        {Reloadable: true},
	"MAX_DYNAMIC_SNIS":                 {Reloadable: true},
	"SNI_DISCOVERY_DOMAINS_PER_SOURCE": {Reloadable: true},
}

// LoadConfig loads and merges a JSON config file over the defaults, using robust reading and validation.
func LoadConfig(path string) (*Config, error) {
	data, infoNote, err := ReadConfigBytes(path)
	if err != nil {
		return nil, err
	}
	if infoNote != "" {
		log.Printf("Note: %s", infoNote)
	}

	userConfig, err := DecodeConfig(data)
	if err != nil {
		// If decode error, wrap with path, line/col and hint
		if se, ok := err.(*json.SyntaxError); ok {
			// Find original line/col using ReadConfigBytes details or syntax offset
			// We can re-read norm and origMap or have ReadConfigBytes provide them.
			// For now, compute line/col from data or syntax error.
			line, col := syntaxOffsetToLineCol(data, se.Offset)
			return nil, &ConfigError{
				Path:    path,
				Line:    line,
				Column:  col,
				Message: se.Error(),
				Hint:    "could not parse; check for a missing comma or quote near line " + fmt.Sprint(line),
			}
		}
		return nil, &ConfigError{Path: path, Message: err.Error()}
	}

	if err := ValidateConfigMap(userConfig, path); err != nil {
		return nil, err
	}

	cfg := DefaultConfig()
	for k, v := range userConfig {
		cfg.Raw[k] = v
	}
	return cfg, nil
}

// ValidateConfigMap checks known keys and returns all problems in one error.
func ValidateConfigMap(userConfig map[string]interface{}, path string) error {
	var errs []string

	for k, v := range userConfig {
		if _, ok := KnownKeys[k]; !ok {
			log.Printf("config warning: unknown key %q", k)
			continue
		}

		switch k {
		case "LISTEN_PORT", "CONNECT_PORT":
			if iv, ok := toInt(v); !ok || iv < 1 || iv > 65535 {
				errs = append(errs, fmt.Sprintf("%s must be an integer between 1 and 65535", k))
			}
		case "CONNECT_IP":
			if v != nil {
				if sv, ok := v.(string); !ok || !isValidIPv4(sv) {
					errs = append(errs, fmt.Sprintf("%s must be a valid IPv4 address literal", k))
				}
			}
		case "CONNECT_IPS", "FAKE_SNIS":
			if v != nil {
				list, ok := v.([]interface{})
				if !ok {
					errs = append(errs, fmt.Sprintf("%s must be an array of strings", k))
				} else {
					for _, item := range list {
						if k == "CONNECT_IPS" {
							if sv, ok := item.(string); !ok || !isValidIPv4(sv) {
								errs = append(errs, fmt.Sprintf("%s contains invalid IPv4 literal %v", k, item))
							}
						}
					}
				}
			}
		case "BYPASS_METHOD":
			if sv, ok := v.(string); !ok || !isAllowedString(sv, "direct", "fragment", "fake_sni", "combined", "mitm") {
				errs = append(errs, fmt.Sprintf("BYPASS_METHOD must be one of direct, fragment, fake_sni, combined, mitm (got %v)", v))
			}
		case "FRAGMENT_STRATEGY":
			if sv, ok := v.(string); !ok || !isAllowedString(sv, "sni_split", "half", "multi", "tls_record_frag") {
				errs = append(errs, fmt.Sprintf("FRAGMENT_STRATEGY must be one of sni_split, half, multi, tls_record_frag (got %v)", v))
			}
		default:
			// Check durations/intervals if key ends with _SECONDS, _TIMEOUT, _DELAY, _INTERVAL
			if strings.HasSuffix(k, "_SECONDS") || strings.HasSuffix(k, "_TIMEOUT") || strings.HasSuffix(k, "_DELAY") || strings.HasSuffix(k, "_INTERVAL") {
				if fv, ok := toFloat(v); !ok || fv < 0 {
					errs = append(errs, fmt.Sprintf("%s must be a positive number", k))
				}
			}
		}
	}

	if len(errs) > 0 {
		return &ValidationErrors{Path: path, Errors: errs}
	}
	return nil
}

func isValidIPv4(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() != nil
}

func toInt(v interface{}) (int, bool) {
	switch t := v.(type) {
	case int:
		return t, true
	case float64:
		return int(t), true
	}
	return 0, false
}

func toFloat(v interface{}) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	}
	return 0, false
}

func isAllowedString(s string, allowed ...string) bool {
	for _, a := range allowed {
		if s == a {
			return true
		}
	}
	return false
}

func syntaxOffsetToLineCol(data []byte, offset int64) (int, int) {
	idx := int(offset) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(data) {
		idx = len(data) - 1
	}
	line := 1
	col := 1
	for i := 0; i < idx && i < len(data); i++ {
		if data[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

// CheckConfig checks the config file for validation and syntax errors. Returns warnings and error if any.
func CheckConfig(path string) ([]string, error) {
	data, infoNote, err := ReadConfigBytes(path)
	if err != nil {
		return nil, err
	}
	var warnings []string
	if infoNote != "" {
		warnings = append(warnings, infoNote)
	}

	userConfig, err := DecodeConfig(data)
	if err != nil {
		if se, ok := err.(*json.SyntaxError); ok {
			line, col := syntaxOffsetToLineCol(data, se.Offset)
			return warnings, &ConfigError{
				Path:    path,
				Line:    line,
				Column:  col,
				Message: se.Error(),
				Hint:    "could not parse; check for a missing comma or quote near line " + fmt.Sprint(line),
			}
		}
		return warnings, &ConfigError{Path: path, Message: err.Error()}
	}

	if err := ValidateConfigMap(userConfig, path); err != nil {
		return warnings, err
	}

	return warnings, nil
}

// WatchConfig polls the config file and triggers callback on change without breaking running program.
func WatchConfig(ctx context.Context, path string, currentCfg *Config, onReload func(newCfg *Config, restartRequired []string)) {
	if path == "" {
		return
	}
	interval := time.Duration(currentCfg.GetFloat("CONFIG_WATCH_SECONDS", 2.0) * float64(time.Second))
	if interval < 500*time.Millisecond {
		interval = 500 * time.Millisecond
	}

	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	lastMod := fi.ModTime()
	lastSize := fi.Size()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !currentCfg.GetBool("CONFIG_WATCH", true) {
				continue
			}
			fi, err := os.Stat(path)
			if err != nil {
				continue
			}
			if fi.ModTime() != lastMod || fi.Size() != lastSize {
				lastMod = fi.ModTime()
				lastSize = fi.Size()

				newCfg, err := LoadConfig(path)
				if err != nil {
					log.Printf("config reload error (keeping old config): %v", err)
					continue
				}

				// Check restart-required keys
				var restartRequired []string
				for k, v := range newCfg.Raw {
					oldV := currentCfg.Get(k, nil)
					if fmt.Sprint(v) != fmt.Sprint(oldV) {
						if def, ok := KnownKeys[k]; ok && !def.Reloadable {
							restartRequired = append(restartRequired, k)
							log.Printf("changed: %s (restart required)", k)
						}
					}
				}

				currentCfg.Raw = newCfg.Raw
				if onReload != nil {
					onReload(newCfg, restartRequired)
				}
			}
		}
	}
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

// CipherSuitesToOpenSSL turns a CIPHER_SUITES config value into an OpenSSL cipher-list string.
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
