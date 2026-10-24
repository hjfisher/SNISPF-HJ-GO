package masque

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestNewConnectRequestHeaders(t *testing.T) {
	ctx := context.Background()
	req, err := NewConnectRequest(ctx, "cloudflareaccess.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if req.Method != http.MethodConnect {
		t.Fatalf("expected method CONNECT, got %s", req.Method)
	}
	if req.Header.Get("cf-connect-proto") != "cf-connect-ip" {
		t.Fatalf("missing or wrong cf-connect-proto header")
	}
	if req.Header.Get("pq-enabled") != "false" {
		t.Fatalf("missing or wrong pq-enabled header")
	}
	if req.Header.Get("user-agent") != "" {
		t.Fatalf("expected empty user-agent header")
	}
	if req.URL.Path != "" {
		t.Fatalf("expected empty URL path, got %q", req.URL.Path)
	}
}

func TestBadOrIPv6IPReturnsDialStage(t *testing.T) {
	ctx := context.Background()
	// IPv6 address
	res := Probe(ctx, ProbeOptions{IP: "2001:db8::1", Timeout: time.Second})
	if res.Stage != "dial" {
		t.Fatalf("expected stage 'dial', got %q", res.Stage)
	}

	// Malformed IP
	res2 := Probe(ctx, ProbeOptions{IP: "not.an.ip", Timeout: time.Second})
	if res2.Stage != "dial" {
		t.Fatalf("expected stage 'dial', got %q", res2.Stage)
	}
}

func TestUnresponsiveTCPListenerReturnsTLSStage(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	ctx := context.Background()
	res := Probe(ctx, ProbeOptions{
		IP:      "127.0.0.1",
		Port:    port,
		Timeout: 500 * time.Millisecond,
	})
	if res.Stage != "tls" {
		t.Fatalf("expected stage 'tls' on unresponsive listener, got %q", res.Stage)
	}
}

func TestLocalTLSServerHTTP11ReturnsTLSStage(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"}, // Only HTTP/1.1, not h2
	})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err == nil {
			_ = conn.(*tls.Conn).Handshake()
			_ = conn.Close()
		}
	}()

	_, portStr, _ := net.SplitHostPort(listener.Addr().String())
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	ctx := context.Background()
	res := Probe(ctx, ProbeOptions{
		IP:      "127.0.0.1",
		Port:    port,
		Timeout: 2 * time.Second,
	})
	if res.Stage != "tls" {
		t.Fatalf("expected stage 'tls' due to non-h2 ALPN, got %q (alpn=%q)", res.Stage, res.NegotiatedALPN)
	}
}
