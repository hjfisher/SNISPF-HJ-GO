// echprobe - diagnostic tool for the MITM ECH path.
//
// Fetches an ECH config (same code path as the backend) and performs a uTLS
// ECH handshake against a target IP:port, reporting the exact TLS result and
// negotiated ALPN. Run against the same pool IPs the app uses:
//
//	go run ./cmd/echprobe -ip 162.159.192.102 -sni crypto.cloudflare.com \
//	    -list "crypto.cloudflare.com+https://cloudflare-dns.com/dns-query"
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
)

func resolveECH(list string) ([]byte, error) {
	list = strings.TrimSpace(list)
	if !strings.Contains(list, "://") {
		return base64.StdEncoding.DecodeString(list)
	}
	var nameToQuery, dnsServer string
	parts := strings.SplitN(list, "+", 2)
	if len(parts) == 2 {
		nameToQuery, dnsServer = parts[0], parts[1]
	} else {
		dnsServer = parts[0]
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(nameToQuery), dns.TypeHTTPS)
	var respBytes []byte
	if strings.HasPrefix(dnsServer, "https://") {
		m.SetEdns0(4096, false)
		m.Id = 0
		msg, err := m.Pack()
		if err != nil {
			return nil, err
		}
		tr := &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				d := &net.Dialer{Timeout: 10 * time.Second}
				raw, err := d.DialContext(ctx, network, addr)
				if err != nil {
					return nil, err
				}
				u, _ := url.Parse(dnsServer)
				conn := utls.UClient(raw, &utls.Config{ServerName: u.Hostname()}, utls.HelloChrome_Auto)
				if err := conn.HandshakeContext(ctx); err != nil {
					return nil, err
				}
				return conn, nil
			},
		}
		client := &http.Client{Timeout: 30 * time.Second, Transport: tr}
		req, _ := http.NewRequest("POST", dnsServer, bytes.NewReader(msg))
		req.Header.Set("Accept", "application/dns-message")
		req.Header.Set("Content-Type", "application/dns-message")
		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		respBytes, err = io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}
	} else {
		d := &net.Dialer{Timeout: 5 * time.Second}
		conn, err := d.Dial("udp", strings.TrimPrefix(dnsServer, "udp://")+":53")
		if err != nil {
			return nil, err
		}
		defer conn.Close()
		msg, _ := m.Pack()
		conn.Write(msg)
		buf := make([]byte, 4096)
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		respBytes = buf[:n]
	}
	rm := new(dns.Msg)
	if err := rm.Unpack(respBytes); err != nil {
		return nil, err
	}
	for _, a := range rm.Answer {
		if h, ok := a.(*dns.HTTPS); ok {
			for _, v := range h.Value {
				if ec, ok := v.(*dns.SVCBECHConfig); ok {
					fmt.Printf("[echprobe] config fetched: %d bytes (ttl=%d)\n", len(ec.ECH), a.Header().Ttl)
					return ec.ECH, nil
				}
			}
		}
	}
	return nil, fmt.Errorf("no ECH config in DNS answer for %s", nameToQuery)
}

func main() {
	ip := flag.String("ip", "162.159.192.102", "target IP")
	port := flag.Int("port", 443, "target port")
	sni := flag.String("sni", "crypto.cloudflare.com", "upstream SNI (inner hello)")
	list := flag.String("list", "crypto.cloudflare.com+https://cloudflare-dns.com/dns-query", "ECH config list source")
	alpn := flag.String("alpn", "http/1.1", "comma-separated ALPN for the inner hello")
	noECH := flag.Bool("no-ech", false, "baseline: handshake without ECH")
	httpGet := flag.Bool("http", false, "after handshake, send a real GET and print the response status")
	flag.Parse()

	fmt.Printf("[echprobe] target=%s:%d sni=%s ech=%v http=%v\n", *ip, *port, *sni, !*noECH, *httpGet)

	var echList []byte
	if !*noECH {
		cfg, err := resolveECH(*list)
		if err != nil {
			fmt.Printf("[echprobe] CONFIG FETCH FAILED: %v\n", err)
			return
		}
		echList = cfg
		fmt.Printf("[echprobe] config id=0x%02x public_name present=%v\n", echList[2], strings.Contains(string(echList), "ech"))
	}

	d := &net.Dialer{Timeout: 15 * time.Second}
	raw, err := d.Dial("tcp", net.JoinHostPort(*ip, fmt.Sprint(*port)))
	if err != nil {
		fmt.Printf("[echprobe] TCP DIAL FAILED: %v\n", err)
		return
	}
	defer raw.Close()

	var alpnList []string
	for _, a := range strings.Split(*alpn, ",") {
		if a = strings.TrimSpace(a); a != "" {
			alpnList = append(alpnList, a)
		}
	}

	uconn := utls.UClient(raw, &utls.Config{
		ServerName:                      *sni,
		InsecureSkipVerify:              true,
		NextProtos:                      alpnList,
		EncryptedClientHelloConfigList:  echList,
	}, utls.HelloChrome_Auto)
	uconn.SetSNI(*sni)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := time.Now()
	if err := uconn.HandshakeContext(ctx); err != nil {
		fmt.Printf("[echprobe] HANDSHAKE FAILED after %v: %v\n", time.Since(start).Round(time.Millisecond), err)
		return
	}
	state := uconn.ConnectionState()
	fmt.Printf("[echprobe] HANDSHAKE OK in %v: tls=%s alpn=%q cipher=0x%04x echAccepted=%v\n",
		time.Since(start).Round(time.Millisecond), tlsVersion(uint16(state.Version)), state.NegotiatedProtocol,
		state.CipherSuite, state.ECHAccepted)

	// HTTP-level check: a real GET through the tunnel. Cloudflare returns
	// 421 Misdirected Request when the zone does not have ECH enabled (or
	// SNI/Host routing disagrees), which the MITM relay passes to the client
	// as a failed WS upgrade with NO backend-side error.
	if *httpGet {
		req := "GET / HTTP/1.1\r\nHost: " + *sni + "\r\nUser-Agent: echprobe\r\nAccept: */*\r\nConnection: close\r\n\r\n"
		_ = uconn.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err := uconn.Write([]byte(req)); err != nil {
			fmt.Printf("[echprobe] HTTP WRITE FAILED: %v\n", err)
			return
		}
		buf, _ := io.ReadAll(uconn)
		head := string(buf)
		if i := strings.Index(head, "\r\n\r\n"); i >= 0 {
			head = head[:i]
		}
		if len(head) > 300 {
			head = head[:300]
		}
		fmt.Printf("[echprobe] HTTP RESPONSE:\n%s\n", head)
	}
}

func tlsVersion(v uint16) string {
	switch v {
	case 0x0304:
		return "1.3"
	case 0x0303:
		return "1.2"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
