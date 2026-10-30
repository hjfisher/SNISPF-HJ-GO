package pool

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// dataCheckTestCert generates a throwaway self-signed certificate for the
// in-memory TLS server used by the tests.
//
// The tests deliberately avoid real sockets: net.Pipe gives an in-memory
// net.Conn, so the suite never touches the network stack and runs the same
// way on a locked-down machine.
func dataCheckTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
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
		t.Fatalf("create certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// pipeTLSDialer returns a dial hook that hands out in-memory pipes wired to
// a TLS server running handler. It is used in place of a real TCP dial.
func pipeTLSDialer(t *testing.T, handler func(c net.Conn)) func(addr string) (net.Conn, error) {
	t.Helper()
	cert := dataCheckTestCert(t)
	return func(addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			ts := tls.Server(server, &tls.Config{Certificates: []tls.Certificate{cert}})
			if err := ts.Handshake(); err != nil {
				_ = server.Close()
				return
			}
			handler(ts)
			// Close the raw transport rather than the TLS conn: a TLS close
			// would write a close_notify alert that blocks forever on the
			// unbuffered pipe because the peer is not reading any more.
			_ = server.Close()
		}()
		return client, nil
	}
}

// pipeDialer returns a dial hook that hands out plain (non-TLS) pipes.
func pipeDialer(handler func(c net.Conn)) func(addr string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			handler(server)
			_ = server.Close()
		}()
		return client, nil
	}
}

// readRequest consumes the HTTP request headers from c.
func readRequest(c net.Conn) string {
	buf := make([]byte, 2048)
	n, _ := c.Read(buf)
	return string(buf[:n])
}

func TestDataCheckSuccess(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		readRequest(server)
		_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"))
	}()
	ok, stage := dataCheck(client, "example.com", "/cdn-cgi/trace", 2*time.Second, false)
	if !ok || stage != dataStageOK {
		t.Fatalf("expected ok/stage=ok, got ok=%v stage=%q", ok, stage)
	}
}

func TestDataCheckNon200IsOKWhenNotStrict(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		readRequest(server)
		_, _ = server.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	}()
	ok, stage := dataCheck(client, "example.com", "/cdn-cgi/trace", 2*time.Second, false)
	if !ok || stage != dataStageOK {
		t.Fatalf("expected ok for non-200 when not strict, got ok=%v stage=%q", ok, stage)
	}
}

func TestDataCheckStrictRejectsNon200(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		readRequest(server)
		_, _ = server.Write([]byte("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"))
	}()
	ok, stage := dataCheck(client, "example.com", "/cdn-cgi/trace", 2*time.Second, true)
	if ok || stage != dataStageStatus {
		t.Fatalf("expected strict rejection at status stage, got ok=%v stage=%q", ok, stage)
	}
}

func TestDataCheckNonHTTPResponseFailsAtStatus(t *testing.T) {
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		readRequest(server)
		_, _ = server.Write([]byte("this is not http\r\n"))
	}()
	ok, stage := dataCheck(client, "example.com", "/cdn-cgi/trace", 2*time.Second, false)
	if ok || stage != dataStageStatus {
		t.Fatalf("expected status stage failure, got ok=%v stage=%q", ok, stage)
	}
}

func TestDataCheckHandshakeOnlyServerFailsAtRead(t *testing.T) {
	// The peer reads the request but never answers with data.
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		readRequest(server)
		// never write a response
	}()
	ok, stage := dataCheck(client, "example.com", "/cdn-cgi/trace", 300*time.Millisecond, false)
	if ok || stage != dataStageRead {
		t.Fatalf("expected read-stage failure, got ok=%v stage=%q", ok, stage)
	}
}

func TestDataCheckClosedServerFailsAtRead(t *testing.T) {
	// The peer reads the request and then hangs up without answering.
	client, server := net.Pipe()
	go func() {
		readRequest(server)
		_ = server.Close()
	}()
	ok, stage := dataCheck(client, "example.com", "/cdn-cgi/trace", time.Second, false)
	if ok || stage != dataStageRead {
		t.Fatalf("expected read-stage failure, got ok=%v stage=%q", ok, stage)
	}
}

func TestDataCheckWriteStageFailure(t *testing.T) {
	// A closed peer makes the write fail immediately.
	client, server := net.Pipe()
	_ = server.Close()
	ok, stage := dataCheck(client, "example.com", "/", time.Second, false)
	if ok || stage != dataStageWrite {
		t.Fatalf("expected write-stage failure, got ok=%v stage=%q", ok, stage)
	}
}

func TestDataCheckSendsExpectedRequest(t *testing.T) {
	received := make(chan string, 1)
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		received <- readRequest(server)
		_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}()
	if ok, stage := dataCheck(client, "example.com", "/probe", 2*time.Second, false); !ok {
		t.Fatalf("expected success, got stage=%q", stage)
	}
	req := <-received
	if !strings.HasPrefix(req, "GET /probe HTTP/1.1\r\n") {
		t.Fatalf("unexpected request line: %q", req)
	}
	if !strings.Contains(req, "Host: example.com\r\n") {
		t.Fatalf("missing Host header: %q", req)
	}
}

func TestDataCheckEmptyPathFallsBackToDefault(t *testing.T) {
	received := make(chan string, 1)
	client, server := net.Pipe()
	go func() {
		defer server.Close()
		received <- readRequest(server)
		_, _ = server.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	}()
	if ok, _ := dataCheck(client, "example.com", "", 2*time.Second, false); !ok {
		t.Fatalf("expected success")
	}
	req := <-received
	if !strings.HasPrefix(req, "GET /cdn-cgi/trace HTTP/1.1\r\n") {
		t.Fatalf("unexpected request line: %q", req)
	}
}

func TestParseHTTPStatus(t *testing.T) {
	cases := []struct {
		line string
		code int
		ok   bool
	}{
		{"HTTP/1.1 200 OK\r\n", 200, true},
		{"HTTP/1.0 404 Not Found\r\n", 404, true},
		{"HTTP/1.1 204 No Content\n", 204, true},
		{"HTTP/2 200 OK\r\n", 0, false},
		{"garbage\r\n", 0, false},
		{"HTTP/1.1 abc OK\r\n", 0, false},
		{"HTTP/1.1 999 Weird\r\n", 0, false},
		{"\r\n", 0, false},
	}
	for _, c := range cases {
		code, ok := parseHTTPStatus(c.line)
		if ok != c.ok || (ok && code != c.code) {
			t.Fatalf("parseHTTPStatus(%q) = (%d,%v), want (%d,%v)", c.line, code, ok, c.code, c.ok)
		}
	}
}

// newDataCheckExplorer builds an explorer wired to an in-memory peer.
func newDataCheckExplorer(enabled bool, timeout time.Duration, dial func(addr string) (net.Conn, error)) (*CombinationExplorer, *PairStats) {
	key := PairKey{IP: "127.0.0.1", SNI: "example.com"}
	ps := NewPairStats(key.IP, key.SNI, "static", "static")
	e := &CombinationExplorer{
		Port:            443,
		Timeout:         2 * time.Second,
		ProbeCount:      0,
		LossThreshold:   0.2,
		DeadThreshold:   0.8,
		DataCheck:       DataCheckConfig{Enabled: enabled, Path: "/cdn-cgi/trace", Timeout: timeout},
		Stats:           map[PairKey]*PairStats{},
		dataCheckStages: newDataCheckCounters(),
		dial:            dial,
	}
	e.Stats[key] = ps
	return e, ps
}

// TestProbeOneDataCheckDisabledStillSucceeds asserts that with the check off
// a handshake-only peer still yields a healthy pair.
func TestProbeOneDataCheckDisabledStillSucceeds(t *testing.T) {
	dial := pipeTLSDialer(t, func(c net.Conn) {
		readRequest(c)
		// handshake succeeds, but no HTTP response is ever sent
	})
	e, ps := newDataCheckExplorer(false, time.Second, dial)
	e.ProbeOne(ps)

	if ps.probesSent == 0 {
		t.Fatalf("expected probes to be recorded")
	}
	if ps.DataCheckFailed() {
		t.Fatalf("data check must not fail when disabled")
	}
	if len(e.StableStats()) == 0 {
		t.Fatalf("expected the pair to remain a stable candidate")
	}
	stages := e.dataCheckStages.snapshot()
	if stages[dataStageOK] != 0 || stages[dataStageRead] != 0 {
		t.Fatalf("expected no data-check counters when disabled, got %v", stages)
	}
}

// TestProbeOneDataCheckFailureKeepsPairOutOfActivePool asserts that a pair
// which only completes the handshake never becomes a pool candidate.
func TestProbeOneDataCheckFailureKeepsPairOutOfActivePool(t *testing.T) {
	dial := pipeTLSDialer(t, func(c net.Conn) {
		readRequest(c)
		// handshake completes, no HTTP response
	})
	e, ps := newDataCheckExplorer(true, 300*time.Millisecond, dial)
	e.ProbeOne(ps)

	if !ps.DataCheckFailed() {
		t.Fatalf("expected data check failure to be recorded")
	}
	if got := e.StableStats(); len(got) != 0 {
		t.Fatalf("expected no stable candidates, got %d", len(got))
	}
	if got := e.KnownStats(); len(got) != 0 {
		t.Fatalf("expected no known candidates, got %d", len(got))
	}
	stages := e.dataCheckStages.snapshot()
	if stages[dataStageOK] != 0 {
		t.Fatalf("expected no successful data checks, got %d", stages[dataStageOK])
	}
	if stages[dataStageRead] == 0 {
		t.Fatalf("expected read-stage failures to be counted")
	}
}

// TestProbeOneDataCheckSuccessMarksPairHealthy asserts the positive case.
func TestProbeOneDataCheckSuccessMarksPairHealthy(t *testing.T) {
	dial := pipeTLSDialer(t, func(c net.Conn) {
		readRequest(c)
		_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	})
	e, ps := newDataCheckExplorer(true, 2*time.Second, dial)
	e.ProbeOne(ps)

	if ps.DataCheckFailed() {
		t.Fatalf("expected data check to succeed")
	}
	if len(e.StableStats()) == 0 {
		t.Fatalf("expected the pair to be a stable candidate")
	}
	stages := e.dataCheckStages.snapshot()
	if stages[dataStageOK] == 0 {
		t.Fatalf("expected successful data checks to be counted")
	}
}

// TestProbeOnePlainTCPIsUnaffected asserts the non-TLS fallback path keeps
// working exactly as before: no data check, no counters.
func TestProbeOnePlainTCPIsUnaffected(t *testing.T) {
	dial := pipeDialer(func(c net.Conn) {
		buf := make([]byte, 256)
		_, _ = c.Read(buf)
	})
	e, ps := newDataCheckExplorer(true, time.Second, dial)
	e.ClientSniProvider = func() (string, bool) {
		return "example.com", false
	}
	e.ProbeOne(ps)

	if ps.DataCheckFailed() {
		t.Fatalf("plain TCP mode must not run the data check")
	}
	stages := e.dataCheckStages.snapshot()
	if stages[dataStageOK] != 0 || stages[dataStageRead] != 0 || stages[dataStageWrite] != 0 || stages[dataStageStatus] != 0 {
		t.Fatalf("expected no data-check counters in plain TCP mode, got %v", stages)
	}
	if len(e.StableStats()) == 0 {
		t.Fatalf("expected the pair to remain a stable candidate")
	}
}

// TestProbeOneDataCheckFailureIsSticky asserts that a pair which failed the
// data check stays out of the pool until a later probe succeeds.
func TestProbeOneDataCheckFailureIsSticky(t *testing.T) {
	var respond atomic.Bool
	dial := pipeTLSDialer(t, func(c net.Conn) {
		readRequest(c)
		if respond.Load() {
			_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		}
	})
	e, ps := newDataCheckExplorer(true, 300*time.Millisecond, dial)
	e.ProbeOne(ps)
	if !ps.DataCheckFailed() {
		t.Fatalf("expected the first probe to fail the data check")
	}
	if len(e.StableStats()) != 0 {
		t.Fatalf("expected the pair to be excluded after a failed data check")
	}

	respond.Store(true)
	e.ProbeOne(ps)
	if ps.DataCheckFailed() {
		t.Fatalf("expected a later successful probe to clear the failure")
	}
	if len(e.StableStats()) == 0 {
		t.Fatalf("expected the pair to become a candidate again")
	}
}

// TestProbeOneDialFailureIsNotADataCheckFailure asserts that a dead TCP
// endpoint is reported through the normal probe-loss path, not the data
// check counters.
func TestProbeOneDialFailureIsNotADataCheckFailure(t *testing.T) {
	dial := func(addr string) (net.Conn, error) {
		return nil, io.EOF
	}
	e, ps := newDataCheckExplorer(true, time.Second, dial)
	e.ProbeOne(ps)

	if ps.DataCheckFailed() {
		t.Fatalf("a failed dial must not be recorded as a data check failure")
	}
	stages := e.dataCheckStages.snapshot()
	if stages[dataStageOK] != 0 || stages[dataStageRead] != 0 || stages[dataStageWrite] != 0 || stages[dataStageStatus] != 0 {
		t.Fatalf("expected no data-check counters when the dial fails, got %v", stages)
	}
	if ps.probesSent == 0 {
		t.Fatalf("expected probes to be recorded")
	}
}
