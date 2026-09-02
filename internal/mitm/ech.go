// ech.go - Real Encrypted Client Hello for the MITM upstream, ported from
// Xray-core transport/internet/tls/ech.go (Apache-2.0).
//
// The MITM relay terminates the client's TLS and originates its own upstream
// session, so the backend controls the ClientHello — that is the only place
// true ECH can be applied (the forward/fake_sni path must relay the client's
// bytes untouched and cannot encrypt them).
//
// Config formats (Xray-compatible):
//   "MITM_ECH_CONFIG_LIST": "cloudflare.com+https://cloudflare-dns.com/dns-query"
//                          | "https://1.1.1.1/dns-query"
//                          | "udp://1.1.1.1"
//                          | "<base64 ECHConfigList>"
// MITM_ECH_FORCE_QUERY: "full"       — fail the connection if the ECH config
//                                       cannot be fetched (SNI never leaks)
//                       "best-effort" — fall back to plain TLS on failure
package mitm

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

// echResolve returns the raw ECHConfigList bytes for the configured source.
// serverName is the per-connection upstream SNI, used as the query domain
// when the config has no "domain+" prefix (xray behavior) — so each target's
// own ECH config is fetched and targets without ECH fall back cleanly.
// Results are cached per (server, domain) with the DNS TTL; an expired-but-
// recent cache entry is served immediately and refreshed in the background.
func echResolve(echConfigList, serverName string) ([]byte, error) {
	list := strings.TrimSpace(echConfigList)
	if list == "" {
		return nil, fmt.Errorf("ECH: empty config list")
	}

	// Direct base64 config.
	if !strings.Contains(list, "://") {
		cfg, err := base64.StdEncoding.DecodeString(list)
		if err != nil {
			return nil, fmt.Errorf("ECH: bad base64 config: %w", err)
		}
		return cfg, nil
	}

	// DNS-sourced config: "domain+https://doh" / "https://doh" / "udp://dns".
	var nameToQuery, dnsServer string
	parts := strings.SplitN(list, "+", 2)
	if len(parts) == 2 {
		nameToQuery = parts[0]
		dnsServer = parts[1]
	} else {
		dnsServer = parts[0]
	}
	if nameToQuery == "" {
		// Per-connection SNI (xray behavior when only the server URL is set).
		if serverName == "" {
			return nil, fmt.Errorf("ECH: DNS source needs \"domain+\" before the server URL (example.com+https://1.1.1.1/dns-query)")
		}
		nameToQuery = serverName
	}
	return echQueryRecord(nameToQuery, dnsServer)
}

// echConfigCache caches one (server, domain) -> config with TTL expiry.
type echConfigCache struct {
	mu         sync.Mutex
	config     []byte
	expire     time.Time
	lastExpire time.Time
}

var (
	echCaches   sync.Map // string -> *echConfigCache
	echDOHClients sync.Map // string -> *http.Client
)

func echCacheKey(server, domain string) string { return server + "|" + domain }

func echQueryRecord(domain, server string) ([]byte, error) {
	key := echCacheKey(server, domain)
	ccAny, _ := echCaches.LoadOrStore(key, &echConfigCache{})
	cc := ccAny.(*echConfigCache)

	cc.mu.Lock()
	now := time.Now()
	if cc.expire.After(now) {
		cfg := cc.config
		cc.mu.Unlock()
		return cfg, nil
	}
	// Expired: if it is only mildly stale, return the old config and refresh
	// asynchronously; if never fetched or very stale, fetch synchronously.
	fresh := !cc.expire.IsZero() && cc.lastExpire.Add(4*time.Hour).After(now)
	if fresh {
		cc.mu.Unlock()
		go func() {
			_, _ = echFetchAndStore(cc, domain, server)
		}()
		return cc.config, nil
	}
	defer cc.mu.Unlock()
	return echFetchAndStore(cc, domain, server)
}

func echFetchAndStore(cc *echConfigCache, domain, server string) ([]byte, error) {
	cfg, ttl, err := echDNSQuery(server, domain)
	if err != nil {
		return nil, err
	}
	cc.mu.Lock()
	cc.config = cfg
	cc.expire = time.Now().Add(time.Duration(ttl) * time.Second)
	cc.lastExpire = cc.expire
	cc.mu.Unlock()
	return cfg, nil
}

// echDNSQuery sends a type-HTTPS (65) query and extracts the ECH config.
func echDNSQuery(server, domain string) ([]byte, uint32, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeHTTPS)

	var dnsResolve []byte
	switch {
	case strings.HasPrefix(server, "https://"):
		m.SetEdns0(4096, false)
		m.Id = 0 // always 0 in DoH
		msg, err := m.Pack()
		if err != nil {
			return nil, 0, err
		}
		client, err := echDOHClient(server)
		if err != nil {
			return nil, 0, err
		}
		req, err := http.NewRequest("POST", server, bytes.NewReader(msg))
		if err != nil {
			return nil, 0, err
		}
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("Content-Type", "application/dns-message")
		resp, err := client.Do(req)
		if err != nil {
			return nil, 0, err
		}
		defer resp.Body.Close()
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, 0, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, 0, fmt.Errorf("ECH DoH query failed: HTTP %d", resp.StatusCode)
		}
		dnsResolve = respBody

	case strings.HasPrefix(server, "udp://"):
		u, err := url.Parse(server)
		if err != nil {
			return nil, 0, fmt.Errorf("ECH: bad udp dns server %q: %w", server, err)
		}
		host := u.Host
		if u.Port() == "" {
			host = host + ":53"
		}
		dnsTimeoutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var d net.Dialer
		conn, err := d.DialContext(dnsTimeoutCtx, "udp", host)
		if err != nil {
			return nil, 0, err
		}
		defer conn.Close()
		msg, err := m.Pack()
		if err != nil {
			return nil, 0, err
		}
		if _, err := conn.Write(msg); err != nil {
			return nil, 0, err
		}
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return nil, 0, err
		}
		dnsResolve = buf[:n]

	default:
		return nil, 0, fmt.Errorf("ECH: unsupported DNS server %q (use https:// or udp://)", server)
	}

	respMsg := new(dns.Msg)
	if err := respMsg.Unpack(dnsResolve); err != nil {
		return nil, 0, fmt.Errorf("ECH: bad DNS response: %w", err)
	}
	for _, answer := range respMsg.Answer {
		if https, ok := answer.(*dns.HTTPS); ok && https.Hdr.Name == dns.Fqdn(domain) {
			for _, v := range https.Value {
				if ec, ok := v.(*dns.SVCBECHConfig); ok {
					return ec.ECH, answer.Header().Ttl, nil
				}
			}
		}
	}
	return nil, 0, fmt.Errorf("ECH: no ECH config in DNS answer for %s", domain)
}

func echDOHClient(server string) (*http.Client, error) {
	if c, ok := echDOHClients.Load(server); ok {
		return c.(*http.Client), nil
	}
	u, err := url.Parse(server)
	if err != nil {
		return nil, err
	}
	tr := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			var d net.Dialer
			raw, err := d.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			conn := utls.UClient(raw, &utls.Config{ServerName: u.Hostname()}, utls.HelloChrome_Auto)
			if err := conn.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return conn, nil
		},
	}
	c := &http.Client{Timeout: 30 * time.Second, Transport: tr}
	actual, _ := echDOHClients.LoadOrStore(server, c)
	return actual.(*http.Client), nil
}

// invalidECHConfig mirrors xray's fail-closed sentinel: a syntactically
// invalid config that makes the ECH handshake fail loudly instead of
// silently falling back and leaking the SNI.
var invalidECHConfig = []byte{1, 1, 4, 5, 1, 4}

// applyECH resolves the config (per forceQuery semantics) and returns a
// utls.Config field value ready to use, plus whether ECH is active.
func applyECH(echConfigList, forceQuery, serverName string) (configList []byte, failClosed bool, err error) {
	if echConfigList == "" {
		return nil, false, nil
	}
	cfg, rErr := echResolve(echConfigList, serverName)
	if rErr != nil {
		if forceQuery == "full" {
			// Fail closed: use an invalid config so the handshake fails and
			// the SNI is never sent in plaintext.
			return invalidECHConfig, true, rErr
		}
		return nil, false, rErr
	}
	return cfg, false, nil
}
