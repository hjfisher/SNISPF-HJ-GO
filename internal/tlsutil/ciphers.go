package tlsutil

import (
	"fmt"
	"regexp"
	"strings"
)

// CipherSuiteIDs maps canonical IANA TLS cipher-suite names to their 2-byte
// registry IDs.
var CipherSuiteIDs = map[string]uint16{
	// --- TLS 1.3 ---
	"TLS_AES_128_GCM_SHA256":       0x1301,
	"TLS_AES_256_GCM_SHA384":       0x1302,
	"TLS_CHACHA20_POLY1305_SHA256": 0x1303,
	"TLS_AES_128_CCM_SHA256":       0x1304,
	"TLS_AES_128_CCM_8_SHA256":     0x1305,
	// --- TLS 1.2 ECDHE + GCM ---
	"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256": 0xC02B,
	"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384": 0xC02C,
	"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256":   0xC02F,
	"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384":   0xC030,
	// --- TLS 1.2 ECDHE + CHACHA20-POLY1305 ---
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": 0xCCA9,
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   0xCCA8,
	"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256":     0xCCAA,
	// --- TLS 1.2 ECDHE + CBC ---
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA":    0xC009,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA":    0xC00A,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA":      0xC013,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA":      0xC014,
	"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256": 0xC023,
	"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384": 0xC024,
	"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256":   0xC027,
	"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384":   0xC028,
	// --- TLS 1.2 DHE + GCM / CBC ---
	"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256": 0x009E,
	"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384": 0x009F,
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA":    0x0033,
	"TLS_DHE_RSA_WITH_AES_256_CBC_SHA":    0x0039,
	"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256": 0x0067,
	"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256": 0x006B,
	// --- TLS 1.2 RSA + GCM / CBC ---
	"TLS_RSA_WITH_AES_128_GCM_SHA256": 0x009C,
	"TLS_RSA_WITH_AES_256_GCM_SHA384": 0x009D,
	"TLS_RSA_WITH_AES_128_CBC_SHA":    0x002F,
	"TLS_RSA_WITH_AES_256_CBC_SHA":    0x0035,
	"TLS_RSA_WITH_AES_128_CBC_SHA256": 0x003C,
	"TLS_RSA_WITH_AES_256_CBC_SHA256": 0x003D,
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":   0x000A,
	// --- Special ---
	"TLS_EMPTY_RENEGOTIATION_INFO_SCSV": 0x00FF,
	"TLS_FALLBACK_SCSV":                 0x5600,
}

// IDToCipherName is the reverse lookup: 2-byte id -> canonical name.
var IDToCipherName = func() map[uint16]string {
	m := make(map[uint16]string, len(CipherSuiteIDs))
	for k, v := range CipherSuiteIDs {
		m[v] = k
	}
	return m
}()

var cipherSuiteLookup = func() map[string]uint16 {
	m := make(map[string]uint16, len(CipherSuiteIDs))
	for k, v := range CipherSuiteIDs {
		m[strings.ToLower(k)] = v
	}
	return m
}()

// ianaToOpenSSLOverrides are IANA names whose OpenSSL cipher-string spelling
// differs from the naive "strip TLS_ / replace _WITH_ and _ with -" form.
var ianaToOpenSSLOverrides = map[string]string{
	"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256": "ECDHE-ECDSA-CHACHA20-POLY1305",
	"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256":   "ECDHE-RSA-CHACHA20-POLY1305",
	"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256":     "DHE-RSA-CHACHA20-POLY1305",
	"TLS_RSA_WITH_3DES_EDE_CBC_SHA":                 "DES-CBC3-SHA",
}

var tls13SuiteNames = map[string]bool{
	"TLS_AES_128_GCM_SHA256":       true,
	"TLS_AES_256_GCM_SHA384":       true,
	"TLS_CHACHA20_POLY1305_SHA256": true,
	"TLS_AES_128_CCM_SHA256":       true,
	"TLS_AES_128_CCM_8_SHA256":     true,
}

var (
	aesCBCCountRe = regexp.MustCompile(`AES_(\d+)_CBC`)
	aesGCMCountRe = regexp.MustCompile(`AES_(\d+)_GCM`)
)

func ianaToOpenSSL(name string) (string, bool) {
	if tls13SuiteNames[name] {
		return "", false
	}
	if v, ok := ianaToOpenSSLOverrides[name]; ok {
		return v, true
	}
	s := name[4:] // strip the "TLS_" prefix
	s = strings.ReplaceAll(s, "_WITH_", "-")
	s = aesCBCCountRe.ReplaceAllString(s, `AES${1}`)
	s = aesGCMCountRe.ReplaceAllString(s, `AES${1}-GCM`)
	s = strings.ReplaceAll(s, "_", "-")
	return s, true
}

// ToOpenSSLCipherString turns a cipherSuites config value into an OpenSSL
// cipher-list string. TLS 1.3 suites are omitted (not settable via stdlib
// ssl in Python; in Go they map to the cipher suites list of crypto/tls).
// Returns "" when nothing usable remains.
func ToOpenSSLCipherString(value interface{}) string {
	ids := ParseCipherSuiteIDs(value)
	if len(ids) == 0 {
		return ""
	}
	var parts []string
	for _, cid := range ids {
		name, ok := IDToCipherName[cid]
		if !ok {
			continue
		}
		if ossl, ok := ianaToOpenSSL(name); ok {
			parts = append(parts, ossl)
		}
	}
	return strings.Join(parts, ":")
}

var splitRe = regexp.MustCompile(`[\s:,;]+`)

// ParseCipherSuiteIDs parses a cipherSuites value into a list of 2-byte
// cipher-suite IDs. Accepts a colon/comma/whitespace separated list of names
// or raw 4-hex-digit IDs. Returns nil when nothing recognizable is found.
func ParseCipherSuiteIDs(value interface{}) []uint16 {
	if value == nil {
		return nil
	}
	var tokens []string
	switch v := value.(type) {
	case []string:
		for _, x := range v {
			tokens = append(tokens, strings.TrimSpace(x))
		}
	case []interface{}:
		for _, x := range v {
			tokens = append(tokens, strings.TrimSpace(fmt.Sprint(x)))
		}
	case string:
		v = strings.TrimSpace(v)
		if v == "" {
			return nil
		}
		tokens = splitRe.Split(v, -1)
	default:
		return nil
	}

	var ids []uint16
	for _, tok := range tokens {
		low := strings.ToLower(tok)
		if id, ok := cipherSuiteLookup[low]; ok {
			ids = append(ids, id)
			continue
		}
		hexPart := low
		if strings.HasPrefix(hexPart, "0x") {
			hexPart = hexPart[2:]
		}
		var cid uint64
		n, err := fmt.Sscanf(hexPart, "%x", &cid)
		if err == nil && n == 1 && cid > 0 && cid <= 0xFFFF {
			ids = append(ids, uint16(cid))
			continue
		}
	}
	return ids
}

// BuildCipherSuitesField builds the raw TLS cipher-suites field (2-byte
// length prefix + 2-byte ids).
func BuildCipherSuitesField(ids []uint16) []byte {
	body := make([]byte, 0, len(ids)*2)
	for _, cid := range ids {
		body = append(body, byte(cid>>8), byte(cid))
	}
	out := []byte{byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

// ResolveCipherSuitesField turns a config CIPHER_SUITES value into a raw
// ClientHello field. Returns nil when empty/unrecognizable so callers can
// fall back to the built-in default list.
func ResolveCipherSuitesField(value interface{}) []byte {
	ids := ParseCipherSuiteIDs(value)
	if len(ids) == 0 {
		return nil
	}
	return BuildCipherSuitesField(ids)
}
