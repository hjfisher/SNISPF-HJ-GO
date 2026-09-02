package discovery

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"snispf-hj-go/internal/config"
	"snispf-hj-go/internal/pool"
)

// CuratedSeeds is a small hand-picked baseline that works even offline.
var CuratedSeeds = strings.Fields(`
discord.com discordapp.com canva.com notion.so medium.com dev.to hashnode.com
fly.io cloudflare.com workers.dev pages.dev trycloudflare.com cdnjs.cloudflare.com
cdnjs.com cdn.jsdelivr.net vercel.com vercel.app railway.app render.com netlify.com
netlify.app surge.sh gitbook.io gitbook.com readme.io readme.com stoplight.io
swagger.io postman.com rapidapi.com replit.com codesandbox.io stackblitz.com
glitch.com codepen.io jsfiddle.net jsbin.com observablehq.com npmjs.com npmjs.org
registry.npmjs.org unpkg.com skypack.dev esm.sh esm.run jspm.io hub.docker.com
golang.org go.dev rust-lang.org crates.io lib.rs docs.rs pypi.org rubygems.org
packagist.org nuget.org gradle.org dart.dev pub.dev sourceforge.net gitlab.com
bitbucket.org codeberg.org huggingface.co arxiv.org researchgate.net zenodo.org
biorxiv.org medrxiv.org stackoverflow.com stackexchange.com superuser.com
serverfault.com askubuntu.com reddit.com substack.com ghost.org wordpress.com
squarespace.com webflow.com framer.com bubble.io airtable.com coda.io obsidian.md
logseq.com linear.app monday.com clickup.com toggl.com clockify.me freshdesk.com
crisp.chat tawk.to sentry.io grafana.com prometheus.io elastic.co stripe.com
paddle.com twilio.com sendgrid.com mailchimp.com mailgun.com klaviyo.com
hubspot.com pipedrive.com auth0.com okta.com yarnpkg.com pnpm.io bun.sh deno.land
deno.com standardnotes.com philarchive.org rollbar.com logrocket.com
`)

var extraSources = map[string]string{
	"majestic": "https://downloads.majestic.com/majestic_million.csv",
	"umbrella": "https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip",
	"tranco":   "https://tranco-list.eu/top-1m.csv.zip",
}

func cleanDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(strings.SplitN(d, "#", 2)[0]))
	for _, p := range []string{"https://", "http://", "ftp://"} {
		if strings.HasPrefix(d, p) {
			d = d[len(p):]
		}
	}
	d = strings.SplitN(d, "/", 2)[0]
	d = strings.SplitN(d, ":", 2)[0]
	d = strings.SplitN(d, "?", 2)[0]
	return d
}

func fetchZipCSV(url string, limit int, timeout time.Duration) []string {
	client := &http.Client{Timeout: timeout}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(zr.File) == 0 {
		return nil
	}
	rc, err := zr.File[0].Open()
	if err != nil {
		return nil
	}
	defer rc.Close()
	body, err := io.ReadAll(rc)
	if err != nil {
		return nil
	}
	var domains []string
	for _, line := range strings.Split(string(body), "\n") {
		if len(domains) >= limit {
			break
		}
		parts := strings.Split(strings.TrimSpace(line), ",")
		if len(parts) > 1 {
			d := cleanDomain(parts[1])
			if d != "" && strings.Contains(d, ".") {
				domains = append(domains, d)
			}
		}
	}
	return domains
}

func fetchPlainCSV(url string, limit int, timeout time.Duration) []string {
	client := &http.Client{Timeout: timeout}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64)")
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	var domains []string
	for i, line := range strings.Split(string(body), "\n") {
		if i == 0 {
			continue
		}
		if len(domains) >= limit {
			break
		}
		parts := strings.Split(strings.TrimSpace(line), ",")
		if len(parts) > 1 {
			d := cleanDomain(parts[1])
			if d != "" && strings.Contains(d, ".") {
				domains = append(domains, d)
			}
		}
	}
	return domains
}

// FetchDomainPool downloads and merges domains from all public sources + seeds.
func FetchDomainPool(limitPerSource int) map[string]bool {
	domains := map[string]bool{}
	for _, d := range CuratedSeeds {
		if d = cleanDomain(d); d != "" {
			domains[d] = true
		}
	}
	log.Printf("SNI source refresh: %d curated seeds", len(domains))

	for name, url := range extraSources {
		var found []string
		if name == "majestic" {
			found = fetchPlainCSV(url, limitPerSource, 60*time.Second)
		} else {
			found = fetchZipCSV(url, limitPerSource, 90*time.Second)
		}
		for _, d := range found {
			domains[d] = true
		}
		label := fmt.Sprintf("%d domains", len(found))
		if len(found) == 0 {
			label = "failed/unreachable"
		}
		log.Printf("SNI source refresh: %s -> %s", name, label)
	}

	for d := range domains {
		if d == "" || !strings.Contains(d, ".") || len(d) >= 100 || strings.Contains(d, " ") {
			delete(domains, d)
		}
	}
	log.Printf("SNI source refresh: %d unique candidate domains total", len(domains))
	return domains
}

func resolveDomain(ctx context.Context, domain string, timeout time.Duration) string {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain)
	if err != nil || len(addrs) == 0 {
		return ""
	}
	return addrs[0].String()
}

// tlsProbeSNI returns the fraction of successful TLS handshakes for (ip, sni).
func tlsProbeSNI(ip, sni string, port int, timeout time.Duration, attempts int) float64 {
	dialer := &net.Dialer{Timeout: timeout}
	successes := 0
	for i := 0; i < attempts; i++ {
		raw, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err == nil {
			tconn := tls.Client(raw, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
			_ = tconn.SetDeadline(time.Now().Add(timeout))
			if tconn.Handshake() == nil {
				successes++
			}
			_ = tconn.Close()
		}
		time.Sleep(time.Duration(randFloat(20, 80)) * time.Millisecond)
	}
	if attempts == 0 {
		return 0
	}
	return float64(successes) / float64(attempts)
}

// SNIDiscovery samples Cloudflare-hosted domains and injects fresh SNIs.
type SNIDiscovery struct {
	manager *pool.ConnectionManager

	ScanBatch             int
	ScanInterval          time.Duration
	SourceRefreshInterval time.Duration
	ProbeAttempts         int
	ProbeTimeout          time.Duration
	MinSuccessRate        float64
	MaxDynamicSNIs        int
	DomainsPerSource      int
	Port                  int

	domainPool map[string]bool
	domainMu   sync.Mutex

	knownSNIs   map[string]bool
	dynamicSNIs []string
	mu          sync.Mutex
}

func NewSNIDiscovery(manager *pool.ConnectionManager, scanBatch int, scanInterval, sourceRefreshInterval time.Duration, probeAttempts int, probeTimeout time.Duration, minSuccessRate float64, maxDynamicSNIs, domainsPerSource, port int) *SNIDiscovery {
	d := &SNIDiscovery{
		manager:               manager,
		ScanBatch:             scanBatch,
		ScanInterval:          scanInterval,
		SourceRefreshInterval: sourceRefreshInterval,
		ProbeAttempts:         probeAttempts,
		ProbeTimeout:          probeTimeout,
		MinSuccessRate:        minSuccessRate,
		MaxDynamicSNIs:        maxDynamicSNIs,
		DomainsPerSource:      domainsPerSource,
		Port:                  port,
		domainPool:            map[string]bool{},
		knownSNIs:             manager.Explorer.SnapshotKnownSNIs(),
	}
	for _, s := range CuratedSeeds {
		d.domainPool[cleanDomain(s)] = true
	}
	return d
}

// Start launches both background loops (source refresh + discovery).
func (d *SNIDiscovery) Start() {
	go d.sourceRefreshLoop()
	go d.discoveryLoop()
	log.Printf("SNI discovery started — batch=%d  interval=%ds  source_refresh=%ds",
		d.ScanBatch, int(d.ScanInterval.Seconds()), int(d.SourceRefreshInterval.Seconds()))
}

// DynamicSNICount reports the number of currently-active dynamic SNIs.
func (d *SNIDiscovery) DynamicSNICount() int {
	d.syncWithExplorer()
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.dynamicSNIs)
}

func (d *SNIDiscovery) syncWithExplorer() {
	activeSNIs := d.manager.Explorer.SnapshotAllSNIs()
	active := map[string]bool{}
	for _, sni := range activeSNIs {
		active[sni] = true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var dyn []string
	for _, sni := range d.dynamicSNIs {
		origin := d.manager.Explorer.LookupSNIOrigin(sni)
		if active[sni] && origin == "dynamic" {
			dyn = append(dyn, sni)
		}
	}
	d.dynamicSNIs = dyn
	for sni := range d.knownSNIs {
		if !active[sni] && !d.manager.Explorer.HasSNIOrigin(sni) {
			delete(d.knownSNIs, sni)
		}
	}
}

func (d *SNIDiscovery) sourceRefreshLoop() {
	time.Sleep(20*time.Second + time.Duration(randFloat(0, 10))*time.Second)
	for {
		fresh := FetchDomainPool(d.DomainsPerSource)
		d.domainMu.Lock()
		d.domainPool = fresh
		d.domainMu.Unlock()
		log.Printf("SNI source refresh complete: %d candidate domains cached.", len(fresh))
		sleepFor := d.SourceRefreshInterval.Seconds()
		if sleepFor < 300 {
			sleepFor = 300
		}
		time.Sleep(time.Duration(sleepFor) * time.Second)
	}
}

func (d *SNIDiscovery) discoveryLoop() {
	time.Sleep(15*time.Second + time.Duration(randFloat(0, 10))*time.Second)
	for {
		d.scanRound()
		jitter := randFloat(-15, 15)
		sleepFor := d.ScanInterval.Seconds() + jitter
		if sleepFor < 30 {
			sleepFor = 30
		}
		time.Sleep(time.Duration(sleepFor) * time.Second)
	}
}

func (d *SNIDiscovery) scanRound() {
	d.syncWithExplorer()
	d.mu.Lock()
	currentCount := len(d.dynamicSNIs)
	d.mu.Unlock()
	if currentCount >= d.MaxDynamicSNIs {
		log.Printf("SNI discovery: dynamic SNI cap reached (%d/%d) — skipping scan round.", currentCount, d.MaxDynamicSNIs)
		return
	}

	d.domainMu.Lock()
	var poolSnapshot []string
	for s := range d.domainPool {
		poolSnapshot = append(poolSnapshot, s)
	}
	d.domainMu.Unlock()
	if len(poolSnapshot) == 0 {
		log.Printf("SNI discovery: domain pool empty — skipping round.")
		return
	}

	d.mu.Lock()
	known := map[string]bool{}
	for s := range d.knownSNIs {
		known[s] = true
	}
	d.mu.Unlock()
	var candidatePool []string
	for _, dom := range poolSnapshot {
		if !known[dom] {
			candidatePool = append(candidatePool, dom)
		}
	}
	if len(candidatePool) == 0 {
		log.Printf("SNI discovery: all sampled domains already known — skipping.")
		return
	}
	rand.Shuffle(len(candidatePool), func(i, j int) { candidatePool[i], candidatePool[j] = candidatePool[j], candidatePool[i] })
	candidates := candidatePool
	if len(candidates) > d.ScanBatch {
		candidates = candidates[:d.ScanBatch]
	}
	log.Printf("SNI discovery: checking %d candidate domain(s) ...", len(candidates))

	// Step 1: resolve + Cloudflare filter. Concurrency is bounded so DNS
	// resolution does not fan out one goroutine per domain.
	const probeConcurrency = 8
	var cfCandidates []string
	var cfMu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, probeConcurrency)
	for _, dom := range candidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }()
			ip := resolveDomain(context.Background(), domain, 5*time.Second)
			if ip != "" && IsCloudflareIP(ip) {
				cfMu.Lock()
				cfCandidates = append(cfCandidates, domain)
				cfMu.Unlock()
			}
		}(dom)
	}
	wg.Wait()
	log.Printf("SNI discovery: %d / %d candidates are Cloudflare-hosted", len(cfCandidates), len(candidates))
	if len(cfCandidates) == 0 {
		return
	}

	// Step 2: TLS probe against an active pool IP.
	probeIP := d.pickProbeIP()
	if probeIP == "" {
		log.Printf("SNI discovery: no active IP available to probe against.")
		return
	}
	var accepted []string
	var accMu sync.Mutex
	for _, dom := range cfCandidates {
		wg.Add(1)
		sem <- struct{}{}
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }()
			rate := tlsProbeSNI(probeIP, domain, d.Port, d.ProbeTimeout, d.ProbeAttempts)
			if rate >= d.MinSuccessRate {
				accMu.Lock()
				accepted = append(accepted, domain)
				accMu.Unlock()
			}
		}(dom)
	}
	wg.Wait()
	log.Printf("SNI discovery: %d / %d Cloudflare domains passed TLS probe (>=%.0f%%)",
		len(accepted), len(cfCandidates), d.MinSuccessRate*100)
	if len(accepted) == 0 {
		return
	}

	injected := 0
	for _, sni := range accepted {
		injected += d.injectSNI(sni)
	}
	log.Printf("SNI discovery: injected %d new (IP, SNI) pairs into the pool.", injected)
	if injected > 0 {
		d.manager.Pool.Refresh()
	}
}

func (d *SNIDiscovery) pickProbeIP() string {
	ips := d.manager.Explorer.SnapshotAllIPs()
	if len(ips) == 0 {
		return ""
	}
	return ips[rand.Intn(len(ips))]
}

// injectSNI adds one new SNI × all active (non-quarantined) IPs.
func (d *SNIDiscovery) injectSNI(sni string) int {
	d.syncWithExplorer()

	d.mu.Lock()
	if d.knownSNIs[sni] {
		d.mu.Unlock()
		return 0
	}
	if len(d.dynamicSNIs) >= d.MaxDynamicSNIs {
		evicted := d.dynamicSNIs[0]
		d.dynamicSNIs = d.dynamicSNIs[1:]
		delete(d.knownSNIs, evicted)
		d.manager.Explorer.RemoveAllPairsForSNI(evicted)
		d.manager.Explorer.RemoveSNIBookkeeping(evicted)
		log.Printf("SNI discovery: evicted old SNI %s from pool.", evicted)
	}
	d.knownSNIs[sni] = true
	d.dynamicSNIs = append(d.dynamicSNIs, sni)
	d.manager.Explorer.SetSNIOrigin(sni, "dynamic")
	d.mu.Unlock()

	added := 0
	for _, ip := range d.manager.Explorer.SnapshotAllIPs() {
		if d.manager.Explorer.IsIPQuarantined(ip) {
			continue
		}
		ipOrigin := d.manager.Explorer.LookupIPOrigin(ip)
		d.manager.Explorer.AddUnexploredPair(ip, sni, ipOrigin, "dynamic")
		added++
	}
	return added
}

// LogStatus prints diagnostics.
func (d *SNIDiscovery) LogStatus() {
	d.syncWithExplorer()
	d.mu.Lock()
	dynamic := len(d.dynamicSNIs)
	known := len(d.knownSNIs)
	d.mu.Unlock()
	d.domainMu.Lock()
	poolSize := len(d.domainPool)
	d.domainMu.Unlock()
	log.Printf("SNI discovery status — dynamic SNIs: %d / %d  total known: %d  candidate pool: %d",
		dynamic, d.MaxDynamicSNIs, known, poolSize)
}

// BuildSNIDiscovery builds an SNIDiscovery from config, or nil when disabled.
func BuildSNIDiscovery(manager *pool.ConnectionManager, cfg *config.Config) *SNIDiscovery {
	if !cfg.GetBool("DYNAMIC_SNI_DISCOVERY", false) {
		return nil
	}
	return NewSNIDiscovery(
		manager,
		cfg.GetInt("SNI_DISCOVERY_BATCH", 50),
		time.Duration(cfg.GetFloat("SNI_DISCOVERY_INTERVAL", 120.0))*time.Second,
		time.Duration(cfg.GetFloat("SNI_SOURCE_REFRESH_INTERVAL", 21600.0))*time.Second,
		cfg.GetInt("SNI_DISCOVERY_PROBE_TRIES", 3),
		time.Duration(cfg.GetFloat("SNI_DISCOVERY_TIMEOUT", 2.0))*time.Second,
		cfg.GetFloat("SNI_DISCOVERY_MIN_SUCCESS", 0.50),
		cfg.GetInt("MAX_DYNAMIC_SNIS", 100),
		cfg.GetInt("SNI_DISCOVERY_DOMAINS_PER_SOURCE", 5000),
		cfg.GetInt("CONNECT_PORT", 443),
	)
}
