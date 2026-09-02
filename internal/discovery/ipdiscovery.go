package discovery

import (
	"crypto/tls"
	"log"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"snispf-hj-go/internal/config"
	"snispf-hj-go/internal/pool"
)

// tlsProbe returns the fraction of successful TLS handshakes (0.0–1.0) for an
// IP. Uses SNI cloudflare.com (always-valid) with verification disabled.
func tlsProbe(ip string, port int, timeout time.Duration, attempts int) float64 {
	dialer := &net.Dialer{Timeout: timeout}
	successes := 0
	for i := 0; i < attempts; i++ {
		raw, err := dialer.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
		if err == nil {
			tconn := tls.Client(raw, &tls.Config{ServerName: "cloudflare.com", InsecureSkipVerify: true})
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

// IPDiscovery continuously samples Cloudflare IPs, probes them, and injects
// the survivors into the connection pool. Port of ip_discovery.py.
type IPDiscovery struct {
	manager *pool.ConnectionManager
	snis    []string

	ScanBatch      int
	ScanInterval   time.Duration
	ProbeAttempts  int
	ProbeTimeout   time.Duration
	MinSuccessRate float64
	MaxDynamicIPs  int
	Port           int
	CIDRs          []string

	knownIPs   map[string]bool
	dynamicIPs []string
	mu         sync.Mutex
}

func NewIPDiscovery(manager *pool.ConnectionManager, snis []string, scanBatch int, scanInterval time.Duration, probeAttempts int, probeTimeout time.Duration, minSuccessRate float64, maxDynamicIPs, port int, cidrs []string) *IPDiscovery {
	if cidrs == nil {
		cidrs = CloudflareCIDRs
	}
	return &IPDiscovery{
		manager:        manager,
		snis:           snis,
		ScanBatch:      scanBatch,
		ScanInterval:   scanInterval,
		ProbeAttempts:  probeAttempts,
		ProbeTimeout:   probeTimeout,
		MinSuccessRate: minSuccessRate,
		MaxDynamicIPs:  maxDynamicIPs,
		Port:           port,
		CIDRs:          cidrs,
		knownIPs:       manager.Explorer.SnapshotKnownIPs(),
	}
}

// Start launches the discovery loop in a background goroutine.
func (d *IPDiscovery) Start() {
	go d.loop()
	log.Printf("IP discovery started — batch=%d  interval=%ds  CIDRs=%d",
		d.ScanBatch, int(d.ScanInterval.Seconds()), len(d.CIDRs))
}

// DynamicIPCount reports the number of currently-active dynamic IPs.
func (d *IPDiscovery) DynamicIPCount() int {
	d.syncWithExplorer()
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.dynamicIPs)
}

// syncWithExplorer reconciles local bookkeeping with the explorer's evictions.
func (d *IPDiscovery) syncWithExplorer() {
	activeIPs := d.manager.Explorer.SnapshotAllIPs()
	active := map[string]bool{}
	for _, ip := range activeIPs {
		active[ip] = true
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var dyn []string
	for _, ip := range d.dynamicIPs {
		origin := d.manager.Explorer.LookupIPOrigin(ip)
		if active[ip] && origin == "dynamic" {
			dyn = append(dyn, ip)
		}
	}
	d.dynamicIPs = dyn
	for ip := range d.knownIPs {
		if !active[ip] && !d.manager.Explorer.HasIPOrigin(ip) {
			delete(d.knownIPs, ip)
		}
	}
}

// snisLive always reads the current SNI list from the explorer.
func (d *IPDiscovery) snisLive() []string {
	if live := d.manager.Explorer.SnapshotAllSNIs(); len(live) > 0 {
		return live
	}
	return d.snis
}

func (d *IPDiscovery) loop() {
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

func (d *IPDiscovery) scanRound() {
	d.syncWithExplorer()
	d.mu.Lock()
	currentCount := len(d.dynamicIPs)
	d.mu.Unlock()
	if currentCount >= d.MaxDynamicIPs {
		log.Printf("IP discovery: dynamic IP cap reached (%d/%d) — skipping scan round.", currentCount, d.MaxDynamicIPs)
		return
	}

	candidates := SampleCloudflareIPs(d.ScanBatch, d.CIDRs)
	d.mu.Lock()
	known := map[string]bool{}
	for ip := range d.knownIPs {
		known[ip] = true
	}
	d.mu.Unlock()
	var fresh []string
	for _, ip := range candidates {
		if !known[ip] {
			fresh = append(fresh, ip)
		}
	}
	if len(fresh) == 0 {
		log.Printf("IP discovery: all sampled IPs already known — skipping.")
		return
	}
	log.Printf("IP discovery: probing %d candidates (batch=%d, %d new) ...", len(fresh), d.ScanBatch, len(fresh))

	// Bound concurrent probes: one goroutine per IP with no limit opened
	// ScanBatch × ProbeAttempts TLS handshakes in a single burst.
	const probeConcurrency = 8
	var accepted []string
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, probeConcurrency)
	for _, ip := range fresh {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()
			defer func() { <-sem }()
			rate := tlsProbe(ip, d.Port, d.ProbeTimeout, d.ProbeAttempts)
			if rate >= d.MinSuccessRate {
				mu.Lock()
				accepted = append(accepted, ip)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()

	log.Printf("IP discovery: %d / %d candidates accepted (>=%.0f%% success)",
		len(accepted), len(fresh), d.MinSuccessRate*100)
	if len(accepted) == 0 {
		return
	}

	injected := 0
	for _, ip := range accepted {
		injected += d.injectIP(ip)
	}
	log.Printf("IP discovery: injected %d new (IP, SNI) pairs into the pool.", injected)
	if injected > 0 {
		d.manager.Pool.Refresh()
	}
}

// injectIP adds one new IP × all active SNIs into the explorer.
func (d *IPDiscovery) injectIP(ip string) int {
	d.syncWithExplorer()

	d.mu.Lock()
	if d.knownIPs[ip] {
		d.mu.Unlock()
		return 0
	}
	if len(d.dynamicIPs) >= d.MaxDynamicIPs {
		evicted := d.dynamicIPs[0]
		d.dynamicIPs = d.dynamicIPs[1:]
		delete(d.knownIPs, evicted)
		d.manager.Explorer.RemoveAllPairsForIP(evicted)
		d.manager.Explorer.RemoveIPBookkeeping(evicted)
		log.Printf("Discovery: evicted old IP %s from pool.", evicted)
	}
	d.knownIPs[ip] = true
	d.dynamicIPs = append(d.dynamicIPs, ip)
	d.manager.Explorer.SetIPOrigin(ip, "dynamic")
	d.mu.Unlock()

	added := 0
	for _, sni := range d.snisLive() {
		if d.manager.Explorer.IsSNIQuarantined(sni) {
			continue
		}
		sniOrigin := d.manager.Explorer.LookupSNIOrigin(sni)
		d.manager.Explorer.AddUnexploredPair(ip, sni, "dynamic", sniOrigin)
		added++
	}
	return added
}

// LogStatus prints diagnostics.
func (d *IPDiscovery) LogStatus() {
	d.syncWithExplorer()
	d.mu.Lock()
	dynamic := len(d.dynamicIPs)
	known := len(d.knownIPs)
	d.mu.Unlock()
	log.Printf("IP discovery status — dynamic IPs: %d / %d  total known: %d", dynamic, d.MaxDynamicIPs, known)
}

// BuildIPDiscovery builds an IPDiscovery from config, or nil when disabled.
func BuildIPDiscovery(manager *pool.ConnectionManager, cfg *config.Config) *IPDiscovery {
	if !cfg.GetBool("DYNAMIC_IP_DISCOVERY", false) {
		return nil
	}
	snis := cfg.GetStringList("FAKE_SNIS")
	if len(snis) == 0 && cfg.Get("FAKE_SNI", nil) != nil {
		snis = []string{cfg.GetString("FAKE_SNI", "")}
	}
	if len(snis) == 0 {
		log.Printf("IP discovery enabled but no FAKE_SNIS — disabled.")
		return nil
	}
	return NewIPDiscovery(
		manager,
		snis,
		cfg.GetInt("DISCOVERY_BATCH", 100),
		time.Duration(cfg.GetFloat("DISCOVERY_INTERVAL", 120.0))*time.Second,
		cfg.GetInt("DISCOVERY_PROBE_TRIES", 3),
		time.Duration(cfg.GetFloat("DISCOVERY_TIMEOUT", 2.0))*time.Second,
		cfg.GetFloat("DISCOVERY_MIN_SUCCESS", 0.50),
		cfg.GetInt("DISCOVERY_MAX_IPS", 200),
		cfg.GetInt("CONNECT_PORT", 443),
		nil,
	)
}

func randFloat(min, max float64) float64 {
	return min + rand.Float64()*(max-min)
}
