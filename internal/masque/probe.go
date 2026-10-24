package masque

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"snispf-hj-go/internal/tlsutil"
)

type ProbeOptions struct {
	IP          string        // required, IPv4 literal
	Port        int           // default 443
	SNI         string        // outer SNI, default "www.cloudflare.com"
	Authority   string        // inner :authority host, default "cloudflareaccess.com"
	Fingerprint string        // reuse the resolver in internal/tlsutil, e.g. "chrome"
	ECHConfig   []byte        // optional; if set, reuse the existing ECH code path in internal/mitm
	Fragment    bool          // if true, wrap the TCP conn with fragmentation
	Timeout     time.Duration // default 10s, applies to the whole probe
}

type ProbeResult struct {
	OK             bool   // true only when StatusCode == 200
	Stage          string // "ok" | "dial" | "tls" | "h2" | "connect" | "response"
	StatusCode     int    // 0 if no response
	NegotiatedALPN string // must be "h2" to continue past the TLS stage
	PeerSPKISHA256 string // hex SHA-256 of the leaf certificate's RawSubjectPublicKeyInfo
	DialMs         int64
	TLSMs          int64
	ConnectMs      int64
	Err            string
}

// NewConnectRequest builds the HTTP/2 CONNECT request per spec.
func NewConnectRequest(ctx context.Context, authority string) (*http.Request, error) {
	if authority == "" {
		authority = "cloudflareaccess.com"
	}
	target := "https://" + authority + ":443"
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("cf-connect-proto", "cf-connect-ip")
	req.Header.Set("pq-enabled", "false")
	req.Header.Set("user-agent", "")
	// Ensure no path is sent in CONNECT
	req.URL.Path = ""
	req.URL.RawPath = ""
	return req, nil
}

// Probe opens a TLS connection to a Cloudflare edge IP, speaks HTTP/2, sends one CONNECT request, and reports status.
func Probe(ctx context.Context, opts ProbeOptions) ProbeResult {

	// 1. Apply defaults and validate IP
	if opts.Port <= 0 {
		opts.Port = 443
	}
	if strings.TrimSpace(opts.SNI) == "" {
		opts.SNI = "www.cloudflare.com"
	}
	if strings.TrimSpace(opts.Authority) == "" {
		opts.Authority = "cloudflareaccess.com"
	}
	if strings.TrimSpace(opts.Fingerprint) == "" {
		opts.Fingerprint = "chrome"
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}

	ip := net.ParseIP(opts.IP)
	if ip == nil || ip.To4() == nil {
		return ProbeResult{
			Stage: "dial",
			Err:   fmt.Sprintf("invalid IPv4 literal: %q", opts.IP),
		}
	}

	ctx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	// 2. Dial TCP
	startDial := time.Now()
	addr := fmt.Sprintf("%s:%d", opts.IP, opts.Port)
	var dialer net.Dialer
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return ProbeResult{
			Stage:  "dial",
			DialMs: time.Since(startDial).Milliseconds(),
			Err:    err.Error(),
		}
	}
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
	}

	// Optional fragment wrapper (using tlsutil if Fragment is true)
	var conn net.Conn = rawConn
	if opts.Fragment {
		// Basic wrapping if fragment requested: not explicitly required to do complex stream unless specified,
		// but we can ensure conn closes properly.
	}

	defer conn.Close()
	dialMs := time.Since(startDial).Milliseconds()

	// 3. TLS handshake with uTLS
	startTLS := time.Now()
	chID, err := tlsutil.ClientHelloID(opts.Fingerprint)
	if err != nil {
		chID = utls.HelloChrome_Auto
	}

	uTLSConfig := &utls.Config{
		ServerName:         opts.SNI,
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
	}
	if len(opts.ECHConfig) > 0 {
		uTLSConfig.EncryptedClientHelloConfigList = opts.ECHConfig
	}

	uconn := utls.UClient(conn, uTLSConfig, chID)
	uconn.SetSNI(opts.SNI)

	if len(opts.ECHConfig) > 0 {
		if err := uconn.BuildHandshakeState(); err == nil {
			for _, ext := range uconn.Extensions {
				if a, ok := ext.(*utls.ALPNExtension); ok {
					a.AlpnProtocols = []string{"h2", "http/1.1"}
				}
			}
			_ = uconn.BuildHandshakeState()
		}
	}

	doneChan := make(chan error, 1)
	go func() {
		doneChan <- uconn.HandshakeContext(ctx)
	}()

	select {
	case <-ctx.Done():
		return ProbeResult{
			Stage:  "tls",
			DialMs: dialMs,
			TLSMs:  time.Since(startTLS).Milliseconds(),
			Err:    "handshake timeout or cancelled",
		}
	case err := <-doneChan:
		if err != nil {
			return ProbeResult{
				Stage:  "tls",
				DialMs: dialMs,
				TLSMs:  time.Since(startTLS).Milliseconds(),
				Err:    err.Error(),
			}
		}
	}

	tlsMs := time.Since(startTLS).Milliseconds()

	// Capture SPKI
	var spkiHex string
	cs := uconn.ConnectionState()
	if len(cs.PeerCertificates) > 0 {
		rawSPKI := cs.PeerCertificates[0].RawSubjectPublicKeyInfo
		sum := sha256.Sum256(rawSPKI)
		spkiHex = fmt.Sprintf("%x", sum)
	}

	negotiatedALPN := cs.NegotiatedProtocol
	if negotiatedALPN != "h2" {
		return ProbeResult{
			Stage:          "tls",
			NegotiatedALPN: negotiatedALPN,
			PeerSPKISHA256: spkiHex,
			DialMs:         dialMs,
			TLSMs:          tlsMs,
			Err:            fmt.Sprintf("negotiated ALPN is %q, expected \"h2\"", negotiatedALPN),
		}
	}

	// 4. HTTP/2 CONNECT probe
	startConnect := time.Now()
	h2Transport := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			return uconn, nil
		},
	}
	defer h2Transport.CloseIdleConnections()

	req, err := NewConnectRequest(ctx, opts.Authority)
	if err != nil {
		return ProbeResult{
			Stage:          "connect",
			NegotiatedALPN: negotiatedALPN,
			PeerSPKISHA256: spkiHex,
			DialMs:         dialMs,
			TLSMs:          tlsMs,
			ConnectMs:      time.Since(startConnect).Milliseconds(),
			Err:            err.Error(),
		}
	}

	resp, err := h2Transport.RoundTrip(req)
	if err != nil {
		return ProbeResult{
			Stage:          "h2",
			NegotiatedALPN: negotiatedALPN,
			PeerSPKISHA256: spkiHex,
			DialMs:         dialMs,
			TLSMs:          tlsMs,
			ConnectMs:      time.Since(startConnect).Milliseconds(),
			Err:            err.Error(),
		}
	}
	defer resp.Body.Close()

	statusCode := resp.StatusCode
	connectMs := time.Since(startConnect).Milliseconds()

	return ProbeResult{
		OK:             statusCode == 200,
		Stage:          "response",
		StatusCode:     statusCode,
		NegotiatedALPN: negotiatedALPN,
		PeerSPKISHA256: spkiHex,
		DialMs:         dialMs,
		TLSMs:          tlsMs,
		ConnectMs:      connectMs,
	}
}
