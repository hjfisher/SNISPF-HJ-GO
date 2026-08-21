package scanner

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// CloudflareASNs are the known Cloudflare AS numbers.
var CloudflareASNs = map[int]bool{13335: true, 209242: true}

// cloudflareIPv4Ranges mirrors the official Cloudflare /ips-v4 list.
var cloudflareIPv4Ranges = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var cfNetworks = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, cidr := range cloudflareIPv4Ranges {
		if _, n, err := net.ParseCIDR(cidr); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// IsCloudflareIP reports whether an IPv4 address belongs to a Cloudflare range.
func IsCloudflareIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return false
	}
	for _, n := range cfNetworks {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// DomainResult holds the outcome of checking a single domain.
type DomainResult struct {
	Domain       string
	IP           string
	IsCloudflare bool
	TCPOk        bool
	TLSOk        bool
	HTTPOk       bool
	HTTPStatus   int
	TLSMs        float64
	Error        string
}

// UsableAsSNI reports whether the domain can be used as a fake SNI.
func (r *DomainResult) UsableAsSNI() bool {
	return r.IsCloudflare && r.TCPOk && r.TLSOk
}

func (r *DomainResult) Summary() string {
	parts := []string{r.Domain}
	if r.IP != "" {
		parts = append(parts, r.IP)
	}
	if r.IsCloudflare {
		parts = append(parts, "CF")
	}
	if r.TCPOk {
		parts = append(parts, "TCP:OK")
	} else {
		parts = append(parts, "TCP:FAIL")
	}
	if r.TLSOk {
		parts = append(parts, "TLS:OK")
	} else {
		parts = append(parts, "TLS:FAIL")
	}
	if r.HTTPOk {
		parts = append(parts, "HTTP:"+strconv.Itoa(r.HTTPStatus))
	}
	if r.Error != "" {
		parts = append(parts, "ERR:"+r.Error)
	}
	return strings.Join(parts, " | ")
}

// DomainChecker verifies domains against Cloudflare for SNI spoofing.
type DomainChecker struct {
	Concurrency int
	Timeout     time.Duration
	VerifyTLS   bool
	VerifyHTTP  bool
}

func NewDomainChecker(concurrency int, timeout time.Duration, verifyTLS, verifyHTTP bool) *DomainChecker {
	return &DomainChecker{Concurrency: concurrency, Timeout: timeout, VerifyTLS: verifyTLS, VerifyHTTP: verifyHTTP}
}

// CheckDomains checks domains in parallel, sorted CF/usable-first by latency.
func (c *DomainChecker) CheckDomains(domains []string, progressCb func(done, total int)) []*DomainResult {
	log.Printf("Checking %d domains (workers=%d, timeout=%.1fs, tls=%v, http=%v)",
		len(domains), c.Concurrency, c.Timeout.Seconds(), c.VerifyTLS, c.VerifyHTTP)

	start := time.Now()
	results := make([]*DomainResult, len(domains))
	sem := make(chan struct{}, c.Concurrency)
	var wg sync.WaitGroup
	var doneCount int
	var mu sync.Mutex

	for i, domain := range domains {
		wg.Add(1)
		go func(idx int, d string) {
			defer wg.Done()
			sem <- struct{}{}
			res := c.checkOne(d)
			<-sem
			mu.Lock()
			results[idx] = res
			doneCount++
			if progressCb != nil {
				progressCb(doneCount, len(domains))
			}
			mu.Unlock()
		}(i, domain)
	}
	wg.Wait()

	elapsed := time.Since(start)
	var cf, usable int
	for _, r := range results {
		if r.IsCloudflare {
			cf++
		}
		if r.UsableAsSNI() {
			usable++
		}
	}
	log.Printf("Domain check complete: %d/%d Cloudflare, %d usable (%.1fs)", cf, len(domains), usable, elapsed.Seconds())

	sort.SliceStable(results, func(a, b int) bool {
		ra, rb := results[a], results[b]
		if ra.UsableAsSNI() != rb.UsableAsSNI() {
			return ra.UsableAsSNI()
		}
		if ra.IsCloudflare != rb.IsCloudflare {
			return ra.IsCloudflare
		}
		la, lb := ra.TLSMs, rb.TLSMs
		if la <= 0 {
			la = 9999
		}
		if lb <= 0 {
			lb = 9999
		}
		return la < lb
	})
	return results
}

func (c *DomainChecker) checkOne(domain string) *DomainResult {
	res := &DomainResult{Domain: domain}

	ips, err := net.LookupIP(domain)
	if err != nil || len(ips) == 0 {
		res.Error = "dns_fail"
		return res
	}
	var ip4 net.IP
	for _, ip := range ips {
		if ip4 = ip.To4(); ip4 != nil {
			break
		}
	}
	if ip4 == nil {
		res.Error = "dns_fail"
		return res
	}
	res.IP = ip4.String()
	res.IsCloudflare = IsCloudflareIP(res.IP)

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(res.IP, "443"), c.Timeout)
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			res.Error = "tcp_timeout"
		} else {
			res.Error = "tcp_error"
		}
		return res
	}
	defer conn.Close()
	res.TCPOk = true

	if !c.VerifyTLS {
		return res
	}

	tconn := tls.Client(conn, &tls.Config{ServerName: domain, InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}})
	_ = tconn.SetDeadline(time.Now().Add(c.Timeout))
	t0 := time.Now()
	if err := tconn.Handshake(); err != nil {
		res.Error = "tls_error"
		return res
	}
	res.TLSMs = time.Since(t0).Seconds() * 1000
	res.TLSOk = true

	if c.VerifyHTTP {
		c.httpCheck(tconn, domain, res)
	}
	return res
}

func (c *DomainChecker) httpCheck(tconn *tls.Conn, domain string, res *DomainResult) {
	req := fmt.Sprintf("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", domain)
	_ = tconn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err := tconn.Write([]byte(req)); err != nil {
		return
	}
	response := make([]byte, 0, 4096)
	buf := make([]byte, 4096)
	for len(response) < 4096 {
		n, err := tconn.Read(buf)
		if n > 0 {
			response = append(response, buf[:n]...)
			if strings.Contains(string(response), "\r\n\r\n") {
				break
			}
		}
		if err != nil {
			break
		}
	}
	if len(response) == 0 {
		return
	}
	firstLine := strings.SplitN(string(response), "\r\n", 2)[0]
	parts := strings.Split(firstLine, " ")
	if len(parts) >= 2 {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			res.HTTPStatus = code
			if code >= 200 && code < 400 {
				res.HTTPOk = true
			}
		}
	}
}

// LoadDomainsFromFile reads one domain per line (comments and prefixes ok).
func LoadDomainsFromFile(filepath string) ([]string, error) {
	f, err := os.Open(filepath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var domains []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimPrefix(line, "https://")
		line = strings.SplitN(line, "/", 2)[0]
		line = strings.SplitN(line, ":", 2)[0]
		if line != "" {
			domains = append(domains, line)
		}
	}
	return domains, scanner.Err()
}

// ResultsTable formats results as a human-readable table.
func ResultsTable(results []*DomainResult, cloudflareOnly bool) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%4s  %-40s %-16s %4s %4s %4s %7s %-6s\n",
		"#", "Domain", "IP", "CDN", "TCP", "TLS", "TLS ms", "Status")
	b.WriteString(strings.Repeat("-", 90) + "\n")

	filtered := results
	if cloudflareOnly {
		var cf []*DomainResult
		for _, r := range results {
			if r.IsCloudflare {
				cf = append(cf, r)
			}
		}
		filtered = cf
	}
	for i, r := range filtered {
		cdn := "-"
		if r.IsCloudflare {
			cdn = "CF"
		}
		tcp := "-"
		if r.TCPOk {
			tcp = "OK"
		}
		tls := "-"
		if r.TLSOk {
			tls = "OK"
		}
		tlsMs := "-"
		if r.TLSMs > 0 {
			tlsMs = fmt.Sprintf("%.0fms", r.TLSMs)
		}
		status := "skip"
		if r.UsableAsSNI() {
			status = "SNI"
		} else if r.IsCloudflare {
			status = "CF"
		}
		fmt.Fprintf(&b, "%4d  %-40s %-16s %4s %4s %4s %7s %-6s\n",
			i+1, r.Domain, r.IP, cdn, tcp, tls, tlsMs, status)
	}
	return b.String()
}

// ExportSNIList writes verified domains to a file (usable only by default).
func ExportSNIList(results []*DomainResult, filepath string, usableOnly bool) (int, error) {
	var domains []string
	for _, r := range results {
		if usableOnly && !r.UsableAsSNI() {
			continue
		}
		if !usableOnly && !r.IsCloudflare {
			continue
		}
		domains = append(domains, r.Domain)
	}

	var b strings.Builder
	b.WriteString("# Verified Cloudflare-backed SNI domains\n")
	b.WriteString("# Generated by SNISPF domain checker\n")
	fmt.Fprintf(&b, "# Total: %d domains\n\n", len(domains))
	for _, d := range domains {
		b.WriteString(d + "\n")
	}
	if err := os.WriteFile(filepath, []byte(b.String()), 0o644); err != nil {
		return 0, err
	}
	return len(domains), nil
}
