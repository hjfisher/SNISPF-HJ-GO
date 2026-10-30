package pool

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DebugLogging enables verbose debug output for the pool package. It is off
// by default so that a failing data-plane probe never spams the log — the
// per-stage counters in the STATS line carry the signal instead.
var DebugLogging atomic.Bool

// Data-check failure stages, reported by dataCheck.
const (
	dataStageOK     = "ok"
	dataStageWrite  = "write"
	dataStageRead   = "read"
	dataStageStatus = "status"
)

// dataCheckStages is the ordered set of stages tracked by the counters.
var dataCheckStages = []string{dataStageOK, dataStageWrite, dataStageRead, dataStageStatus}

// DataCheckConfig holds the knobs for the data-plane probe.
type DataCheckConfig struct {
	// Enabled turns the check on. It only applies to TLS probes.
	Enabled bool
	// Path is the HTTP path requested during the check.
	Path string
	// Strict requires a 200 status; otherwise any valid HTTP/1.x status line
	// counts as success.
	Strict bool
	// Timeout bounds the whole request/response exchange.
	Timeout time.Duration
}

// dataCheck performs a minimal HTTP/1.1 GET on an already-established
// connection and reports whether the peer actually carries data.
//
// The request deliberately advertises no ALPN so the server answers with
// HTTP/1.1 instead of negotiating h2, which keeps the response parseable
// with a plain bufio.Reader.
//
// stage is one of "ok", "write", "read" or "status".
func dataCheck(conn net.Conn, host, path string, timeout time.Duration, strict bool) (ok bool, stage string) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	if path == "" {
		path = "/cdn-cgi/trace"
	}
	if host == "" {
		host = "localhost"
	}

	// The connection may carry a deadline from the handshake phase; replace it
	// with one that covers this exchange only.
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, host)
	if _, err := conn.Write([]byte(req)); err != nil {
		return false, dataStageWrite
	}

	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	line, err := reader.ReadString('\n')
	if err != nil {
		// A clean EOF with no bytes at all is still "read" — the peer closed
		// without carrying data.
		return false, dataStageRead
	}

	code, ok := parseHTTPStatus(line)
	if !ok {
		return false, dataStageStatus
	}
	if strict && code != 200 {
		return false, dataStageStatus
	}
	return true, dataStageOK
}

// parseHTTPStatus extracts the status code from an HTTP/1.x status line.
// It returns ok=false when the line is not a valid HTTP/1.x status line.
func parseHTTPStatus(line string) (int, bool) {
	line = strings.TrimRight(line, "\r\n")
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return 0, false
	}
	proto := parts[0]
	if !strings.HasPrefix(proto, "HTTP/1.") {
		return 0, false
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, false
	}
	if code < 100 || code > 599 {
		return 0, false
	}
	return code, true
}

// DataCheckCounters tracks how many probes ended in each stage. The counters
// are surfaced in the STATS snapshot line so a systematic failure (e.g. every
// pair handshook but returned no data) is visible without debug logging.
type DataCheckCounters struct {
	mu     sync.Mutex
	counts map[string]int64
}

func newDataCheckCounters() *DataCheckCounters {
	return &DataCheckCounters{counts: make(map[string]int64, len(dataCheckStages))}
}

// record increments the counter for a stage.
func (c *DataCheckCounters) record(stage string) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.counts[stage]++
	c.mu.Unlock()
}

// snapshot returns a copy of the counters.
func (c *DataCheckCounters) snapshot() map[string]int64 {
	out := make(map[string]int64, len(dataCheckStages))
	if c == nil {
		return out
	}
	c.mu.Lock()
	for _, s := range dataCheckStages {
		out[s] = c.counts[s]
	}
	c.mu.Unlock()
	return out
}
