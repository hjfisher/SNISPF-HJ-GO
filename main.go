package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"snispf-hj-go/internal/certs"
	"snispf-hj-go/internal/config"
	"snispf-hj-go/internal/discovery"
	"snispf-hj-go/internal/finalmask"
	"snispf-hj-go/internal/forward"
	"snispf-hj-go/internal/mitm"
	"snispf-hj-go/internal/pool"
	"snispf-hj-go/internal/scanner"
	"snispf-hj-go/internal/tlsutil"
	"snispf-hj-go/internal/utils"
)

const version = "1.0.0"

const banner = `
███████╗███╗   ██╗██╗███████╗██████╗ ███████╗    ██╗  ██╗     ██╗       ██████╗  ██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔══██╗██╔════╝    ██║  ██║     ██║      ██╔════╝ ██╔═══██╗
███████╗██╔██╗ ██║██║███████╗██████╔╝█████╗█████╗███████║     ██║█████╗██║  ███╗██║   ██║
╚════██║██║╚██╗██║██║╚════██║██╔═══╝ ██╔══╝╚════╝██╔══██║██   ██║╚════╝██║   ██║██║   ██║
███████║██║ ╚████║██║███████║██║     ██║         ██║  ██║╚█████╔╝      ╚██████╔╝╚██████╔╝
╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝     ╚═╝         ╚═╝  ╚═╝ ╚════╝        ╚═════╝  ╚═════╝ 

     SNISPF-HJ-GO - Cross-Platform DPI Bypass Tool (Go port)         
     Works on Windows / macOS / Linux                               
`

// ─── Config helpers ─────────────────────────────────────────────────────────

func alpnList(cfg *config.Config) []string {
	var alpn []string
	for _, x := range cfg.GetStringList("MITM_ALPN") {
		alpn = append(alpn, strings.TrimSpace(x))
	}
	if len(alpn) == 1 && strings.Contains(alpn[0], ",") {
		var out []string
		for _, part := range strings.Split(alpn[0], ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
		alpn = out
	}
	return alpn
}

func parseHostPort(addr string, defaultHost string, defaultPort int) (string, int) {
	if addr == "" {
		return defaultHost, defaultPort
	}
	if strings.HasPrefix(addr, ":") {
		p, err := strconv.Atoi(addr[1:])
		if err != nil {
			fmt.Printf("Error: Invalid port in '%s'\n", addr)
			os.Exit(1)
		}
		return defaultHost, p
	}
	parts := strings.Split(addr, ":")
	host := parts[0]
	if host == "" {
		host = defaultHost
	}
	port := defaultPort
	if len(parts) == 2 {
		p, err := strconv.Atoi(parts[1])
		if err != nil {
			fmt.Printf("Error: Invalid port in '%s'\n", addr)
			os.Exit(1)
		}
		port = p
	}
	return host, port
}

func generateConfig(path string) {
	cfg := config.DefaultConfig()
	cfg.Set("BYPASS_METHOD", "fragment")
	cfg.Set("FINALMASK_TCP", nil)
	cfg.Set("MITM_CERT_FILE", nil)
	cfg.Set("MITM_KEY_FILE", nil)
	cfg.Set("FINGERPRINT", nil)
	cfg.Set("FINGERPRINT_TLS_BIN", nil)
	raw := map[string]interface{}{}
	for k, v := range cfg.Raw {
		raw[k] = v
	}
	raw["_comment_method"] = "Bypass mode: 'direct', 'fragment', 'fake_sni', 'combined', or 'mitm'"
	raw["_comment_fingerprint"] = "Browser TLS fingerprint for the upstream ClientHello in MITM mode: presets chrome/firefox/safari/ios/android/edge/360/qq/random/randomized/randomizednoalpn/unsafe, plus pinned versions like hellochrome_120 (handled in-process by uTLS)."
	data, err := marshalJSON(raw)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Generated default config: %s\n", path)
}

func marshalJSON(v interface{}) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}

// ─── Platform info ──────────────────────────────────────────────────────────

func showPlatformInfo() {
	fmt.Printf("\nPlatform: %s %s\n", runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Version:  %s\n", version)
	fmt.Printf("Raw injection (Linux seq_id trick): %v\n", forward.IsRawAvailable())
	fmt.Printf("Recommended: combined (fragment + raw fake-SNI when root)\n")
}

// ─── Domain checker command ────────────────────────────────────────────────

func runDomainCheck(domainsFile, output string, workers int, timeout float64, verifyHTTP bool) {
	domains, err := scanner.LoadDomainsFromFile(domainsFile)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if len(domains) == 0 {
		fmt.Println("No domains found in file.")
		return
	}
	fmt.Printf("\n  Checking %d domains...\n\n", len(domains))

	checker := scanner.NewDomainChecker(workers, time.Duration(timeout*float64(time.Second)), true, verifyHTTP)
	results := checker.CheckDomains(domains, nil)

	var cf, usable int
	for _, r := range results {
		if r.IsCloudflare {
			cf++
		}
		if r.UsableAsSNI() {
			usable++
		}
	}
	fmt.Printf("\n%s\n", strings.Repeat("=", 90))
	fmt.Printf("  Domain Check Results\n")
	fmt.Printf("%s\n", strings.Repeat("=", 90))
	fmt.Printf("  Total domains:     %d\n", len(results))
	fmt.Printf("  Behind Cloudflare: %d\n", cf)
	fmt.Printf("  Usable as SNI:     %d\n", usable)
	fmt.Printf("%s\n\n", strings.Repeat("=", 90))

	fmt.Println(scanner.ResultsTable(results, true))

	if output != "" {
		count, err := scanner.ExportSNIList(results, output, true)
		if err != nil {
			fmt.Printf("\n  Export failed: %v\n", err)
		} else {
			fmt.Printf("\n  Exported %d verified domains to %s\n", count, output)
		}
	}
	var nonCF int
	for _, r := range results {
		if !r.IsCloudflare && r.IP != "" {
			nonCF++
		}
	}
	if nonCF > 0 {
		fmt.Printf("\n  Note: %d domains are NOT behind Cloudflare\n", nonCF)
	}
	fmt.Println()
}

// ─── Main ───────────────────────────────────────────────────────────────────

func main() {
	var (
		configPath       string
		genConfig        string
		listen           string
		connect          string
		sni              string
		method           string
		cipherSuites     string
		fingerprint      string
		fingerprintBin   string
		finalmaskFile    string
		fragmentStrategy string
		fragmentDelay    float64
		noRaw            bool
		checkDomains     string
		checkWorkers     int
		checkTimeout     float64
		output           string
		checkHTTP        bool
		verbose          bool
		quiet            bool
		showInfo         bool
	)

	flag.StringVar(&configPath, "config", "", "Path to JSON config file")
	flag.StringVar(&configPath, "C", "", "Path to JSON config file")
	flag.StringVar(&genConfig, "generate-config", "", "Generate a default config file and exit")
	flag.StringVar(&listen, "listen", "", "Listen address HOST:PORT (default 0.0.0.0:40443)")
	flag.StringVar(&listen, "l", "", "Listen address HOST:PORT")
	flag.StringVar(&connect, "connect", "", "Target server address IP:PORT")
	flag.StringVar(&connect, "c", "", "Target server address IP:PORT")
	flag.StringVar(&sni, "sni", "", "Fake SNI hostname")
	flag.StringVar(&sni, "s", "", "Fake SNI hostname")
	flag.StringVar(&method, "method", "", "Bypass mode: direct|fragment|fake_sni|combined|mitm")
	flag.StringVar(&method, "m", "", "Bypass mode")
	flag.StringVar(&cipherSuites, "cipher-suites", "", "Custom upstream TLS cipher suites (colon-separated)")
	flag.StringVar(&fingerprint, "fingerprint", "", "Browser TLS fingerprint for the upstream ClientHello")
	flag.StringVar(&fingerprintBin, "fingerprint-tls-bin", "", "Path to snispf-tls sidecar (legacy, unused in Go)")
	flag.StringVar(&finalmaskFile, "finalmask", "", "Path to a JSON file with finalmask TCP fragment rules")
	flag.StringVar(&fragmentStrategy, "fragment-strategy", "", "Fragment strategy: sni_split|half|multi|tls_record_frag")
	flag.Float64Var(&fragmentDelay, "fragment-delay", -1, "Delay between fragments in seconds")
	flag.BoolVar(&noRaw, "no-raw", false, "Disable raw socket injection even if available")
	flag.StringVar(&checkDomains, "check-domains", "", "Check domains from a file to find Cloudflare-backed ones")
	flag.IntVar(&checkWorkers, "check-workers", 50, "Parallel workers for domain checking")
	flag.Float64Var(&checkTimeout, "check-timeout", 3.0, "Per-domain timeout for checking")
	flag.StringVar(&output, "output", "", "Export verified Cloudflare domains to a file")
	flag.BoolVar(&checkHTTP, "check-http", false, "Also verify HTTP connectivity during domain check")
	flag.BoolVar(&verbose, "verbose", false, "Verbose output (debug logging)")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.BoolVar(&quiet, "quiet", false, "Quiet output (warnings only)")
	flag.BoolVar(&quiet, "q", false, "Quiet output")
	flag.BoolVar(&showInfo, "info", false, "Show platform capabilities and exit")
	showVersion := flag.Bool("version", false, "Show version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SNISPF %s\n", version)
		return
	}

	if genConfig != "" {
		generateConfig(genConfig)
		return
	}

	fmt.Print(banner)

	switch {
	case quiet:
		log.SetFlags(log.LstdFlags)
	case verbose:
		log.SetFlags(log.LstdFlags)
	default:
		log.SetFlags(log.LstdFlags)
	}
	_ = verbose
	_ = quiet

	if showInfo {
		showPlatformInfo()
		return
	}

	// Load configuration.
	var cfg *config.Config
	if configPath != "" {
		loaded, err := config.LoadConfig(configPath)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
		cfg = loaded
	} else {
		cfg = config.DefaultConfig()
	}

	// Override with CLI arguments.
	if listen != "" {
		host, port := parseHostPort(listen, "0.0.0.0", 40443)
		cfg.Set("LISTEN_HOST", host)
		cfg.Set("LISTEN_PORT", port)
	}
	if connect != "" {
		host, port := parseHostPort(connect, "104.18.38.202", 443)
		cfg.Set("CONNECT_IP", host)
		cfg.Set("CONNECT_PORT", port)
	}
	if sni != "" {
		cfg.Set("FAKE_SNI", sni)
	}
	if method != "" {
		cfg.Set("BYPASS_METHOD", method)
	}
	if fragmentStrategy != "" {
		cfg.Set("FRAGMENT_STRATEGY", fragmentStrategy)
	}
	if fragmentDelay >= 0 {
		cfg.Set("FRAGMENT_DELAY", fragmentDelay)
	}
	if cipherSuites != "" {
		cfg.Set("CIPHER_SUITES", cipherSuites)
	}
	if fingerprint != "" {
		cfg.Set("FINGERPRINT", fingerprint)
	}
	if fingerprintBin != "" {
		cfg.Set("FINGERPRINT_TLS_BIN", fingerprintBin)
	}
	if finalmaskFile != "" {
		cfg.Set("FINALMASK_TCP", finalmaskFile)
	}

	// Auto-load config.json when present and no --config was given.
	if configPath == "" {
		for _, candidate := range []string{"config.json", "snispf.json"} {
			if _, err := os.Stat(candidate); err == nil {
				log.Printf("Auto-loading config from %s", candidate)
				userCfg, err := config.LoadConfig(candidate)
				if err == nil {
					for k, v := range userCfg.Raw {
						cfg.Raw[k] = v
					}
				}
				break
			}
		}
	}

	// Domain checker mode
	if checkDomains != "" {
		runDomainCheck(checkDomains, output, checkWorkers, checkTimeout, checkHTTP)
		return
	}

	// Validate
	if !utils.IsValidPort(cfg.GetInt("LISTEN_PORT", 40443)) {
		fmt.Printf("Error: Invalid listen port: %v\n", cfg.Get("LISTEN_PORT", nil))
		os.Exit(1)
	}
	if !utils.IsValidPort(cfg.GetInt("CONNECT_PORT", 443)) {
		fmt.Printf("Error: Invalid connect port: %v\n", cfg.Get("CONNECT_PORT", nil))
		os.Exit(1)
	}
	if cfg.Get("CONNECT_IP", nil) != nil {
		cfg.Set("CONNECT_IP", utils.ResolveHost(cfg.GetString("CONNECT_IP", "")))
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// MITM relay mode
	if isMITMMethod(cfg) {
		runMITM(ctx, cfg)
		return
	}

	runForward(ctx, cfg, noRaw)
}

func isMITMMethod(cfg *config.Config) bool {
	m := strings.ToLower(cfg.GetString("BYPASS_METHOD", "fragment"))
	if m == "mitm" {
		return true
	}
	return strings.ToLower(cfg.GetString("MODE", "standard")) == "mitm"
}

func runMITM(ctx context.Context, cfg *config.Config) {
	maskerRules := config.LoadFinalmaskRules(cfg.Get("FINALMASK_TCP", nil))
	cipherSuiteIDs := tlsutil.ParseCipherSuiteIDs(cfg.Get("CIPHER_SUITES", nil))
	alpn := alpnList(cfg)

	certPath, keyPath, fp, err := certs.LoadOrCreate(
		cfg.GetString("MITM_CERT_FILE", ""),
		cfg.GetString("MITM_KEY_FILE", ""),
		cfg.GetString("MITM_CERT_CN", "SNISPF-HJ"),
	)
	if err != nil {
		fmt.Printf("Error generating MITM certificate: %v\n", err)
		os.Exit(1)
	}
	log.Printf("MITM TLS certificate: %s", certPath)
	log.Printf("MITM cert SHA-256 (pin this): %s", fp)
	fmt.Printf("\n  MITM mode - pin this SHA-256 certificate in your app:\n  %s\n\n", fp)
	if dir := os.Getenv("USERPROFILE"); dir != "" {
		_ = os.MkdirAll(dir+string(os.PathSeparator)+".snispf", 0o755)
		_ = os.WriteFile(dir+string(os.PathSeparator)+".snispf"+string(os.PathSeparator)+"fingerprint.txt", []byte(fp+"\n"), 0o644)
	}

	// Validate fingerprint early so a typo fails fast.
	fingerprintVal := cfg.GetString("FINGERPRINT", "")
	if resolved := tlsutil.ResolveFingerprint(fingerprintVal); resolved != "" {
		if _, err := tlsutil.ClientHelloID(resolved); err != nil {
			fmt.Printf("\n  Error: %v\n", err)
			os.Exit(1)
		}
	}

	// Backfill singular upstream keys from the list forms so single-target
	// fallbacks (pool disabled) and MITM defaults use what's configured.
	if cfg.Get("CONNECT_IP", nil) == nil {
		if ips := cfg.GetStringList("CONNECT_IPS"); len(ips) > 0 {
			cfg.Set("CONNECT_IP", ips[0])
		}
	}
	if cfg.Get("FAKE_SNI", nil) == nil {
		if snis := cfg.GetStringList("FAKE_SNIS"); len(snis) > 0 {
			cfg.Set("FAKE_SNI", snis[0])
		}
	}

	// Connection pool + dynamic discovery. Full (IP x SNI) pool when the
	// upstream handshake sends the pool's fake SNI (default); collapses to
	// IP-only when MITM_USE_CLIENT_SNI=true makes the SNI axis meaningless.
	useClientSNI := cfg.GetBool("MITM_USE_CLIENT_SNI", false)
	sniAxis := !useClientSNI
	var connManager *pool.ConnectionManager
	connManager = pool.BuildConnectionManager(cfg, sniAxis)
	if connManager != nil {
		connManager.StartHealthLoop()
		connManager.StartStatsTicker(ctx, 5*time.Second)
		if sniAxis {
			log.Printf("Connection pool active -- %d pair(s), %d active slot(s)",
				len(connManager.Explorer.Stats), connManager.Pool.Slots)
		} else {
			log.Printf("Connection pool active (IP-only) -- %d IP(s), %d active slot(s)",
				len(uniqueIPs(connManager)), connManager.Pool.Slots)
		}
		ipDisc := discovery.BuildIPDiscovery(connManager, cfg)
		if ipDisc != nil {
			ipDisc.Start()
			log.Printf("Dynamic IP discovery active -- batch=%d  interval=%ds", ipDisc.ScanBatch, int(ipDisc.ScanInterval.Seconds()))
		} else {
			log.Printf("Dynamic IP discovery: disabled (set DYNAMIC_IP_DISCOVERY=true in config to enable)")
		}
		if sniAxis {
			sniDisc := discovery.BuildSNIDiscovery(connManager, cfg)
			if sniDisc != nil {
				sniDisc.Start()
				log.Printf("Dynamic SNI discovery active -- batch=%d  interval=%ds  source_refresh=%ds",
					sniDisc.ScanBatch, int(sniDisc.ScanInterval.Seconds()), int(sniDisc.SourceRefreshInterval.Seconds()))
			} else {
				log.Printf("Dynamic SNI discovery: disabled (set DYNAMIC_SNI_DISCOVERY=true in config to enable)")
			}
		} else {
			log.Printf("Dynamic SNI discovery: skipped (IP-only pool; MITM_USE_CLIENT_SNI=true)")
		}
	}

	opts := &mitm.Options{
		ListenHost:   cfg.GetString("LISTEN_HOST", "0.0.0.0"),
		ListenPort:   cfg.GetInt("LISTEN_PORT", 40443),
		ConnectIP:    cfg.GetString("CONNECT_IP", "104.18.38.202"),
		ConnectPort:  cfg.GetInt("CONNECT_PORT", 443),
		FakeSNI:      cfg.GetString("FAKE_SNI", "cdnjs.cloudflare.com"),
		CipherSuites: cipherSuiteIDs,
		ALPN:         alpn,
		MaskerRules:  maskerRules,
		CertFile:     certPath,
		KeyFile:      keyPath,
		UseClientSNI: useClientSNI,
		ConnManager:  connManager,
		Fingerprint:  fingerprintVal,
	}
	if err := mitm.Start(ctx, opts); err != nil {
		fmt.Printf("\nError: %v\n", err)
		os.Exit(1)
	}
}

func uniqueIPs(m *pool.ConnectionManager) map[string]bool {
	set := map[string]bool{}
	for k := range m.Explorer.Stats {
		set[k.IP] = true
	}
	return set
}

func runForward(ctx context.Context, cfg *config.Config, noRaw bool) {
	method := strings.ToLower(cfg.GetString("BYPASS_METHOD", "fragment"))
	sniAxis := method != "direct" && method != "mitm"

	connManager := pool.BuildConnectionManager(cfg, sniAxis)
	if connManager != nil {
		firstKey := firstPairKey(connManager)
		if cfg.Get("CONNECT_IP", nil) == nil {
			cfg.Set("CONNECT_IP", firstKey.IP)
		}
		if cfg.Get("FAKE_SNI", nil) == nil {
			cfg.Set("FAKE_SNI", firstKey.SNI)
		}
	}

	connectIP := cfg.GetString("CONNECT_IP", "104.18.38.202")
	interfaceIP := utils.GetDefaultInterfaceIPv4(connectIP)
	log.Printf("Default interface: %s", interfaceLabel(interfaceIP))

	// Raw injector
	var rawInjector forward.RawInjector
	if !noRaw && (method == "fake_sni" || method == "combined") && interfaceIP != "" {
		rawInjector = forward.NewRawInjector(interfaceIP, connectIP, cfg.GetInt("CONNECT_PORT", 443))
		if rawInjector == nil {
			if method == "fake_sni" {
				log.Printf("Raw sockets not available (need root/CAP_NET_RAW). fake_sni will fragment the real ClientHello.")
			} else {
				log.Printf("Raw sockets not available. Using fragmentation bypass.")
			}
		} else if !rawInjector.Start() {
			log.Printf("Raw injector failed to start.")
			rawInjector = nil
		}
	}
	if rawInjector != nil {
		defer rawInjector.Stop()
	}

	// Build the bypass strategy
	strategy := buildStrategy(cfg, rawInjector)

	// Pool health loop + discovery
	if connManager != nil {
		connManager.StartHealthLoop()
		connManager.StartStatsTicker(ctx, 5*time.Second)
		log.Printf("Connection pool active -- %d pair(s), %d active slot(s)",
			len(connManager.Explorer.Stats), connManager.Pool.Slots)

		ipDisc := discovery.BuildIPDiscovery(connManager, cfg)
		if ipDisc != nil {
			ipDisc.Start()
			log.Printf("Dynamic IP discovery active -- batch=%d  interval=%ds", ipDisc.ScanBatch, int(ipDisc.ScanInterval.Seconds()))
		} else {
			log.Printf("Dynamic IP discovery: disabled (set DYNAMIC_IP_DISCOVERY=true in config to enable)")
		}

		if sniAxis {
			sniDisc := discovery.BuildSNIDiscovery(connManager, cfg)
			if sniDisc != nil {
				sniDisc.Start()
				log.Printf("Dynamic SNI discovery active -- batch=%d  interval=%ds  source_refresh=%ds",
					sniDisc.ScanBatch, int(sniDisc.ScanInterval.Seconds()), int(sniDisc.SourceRefreshInterval.Seconds()))
			} else {
				log.Printf("Dynamic SNI discovery: disabled (set DYNAMIC_SNI_DISCOVERY=true in config to enable)")
			}
		} else {
			log.Printf("Dynamic SNI discovery: skipped (IP-only pool for %s)", method)
		}
	}

	masker := finalmask.NewFinalMasker(config.LoadFinalmaskRules(cfg.Get("FINALMASK_TCP", nil)))
	if masker != nil {
		log.Printf("FinalMask TCP active -- initial ClientHello and C->S traffic go through %d fragment layer(s)",
			masker.LayerCount())
	}

	cipherSuites := tlsutil.ParseCipherSuiteIDs(cfg.Get("CIPHER_SUITES", nil))

	opts := &forward.ForwardOptions{
		ListenHost:   cfg.GetString("LISTEN_HOST", "0.0.0.0"),
		ListenPort:   cfg.GetInt("LISTEN_PORT", 40443),
		ConnectIP:    connectIP,
		ConnectPort:  cfg.GetInt("CONNECT_PORT", 443),
		FakeSNI:      cfg.GetString("FAKE_SNI", "cdnjs.cloudflare.com"),
		Strategy:     strategy,
		InterfaceIP:  interfaceIP,
		RawInjector:  rawInjector,
		ConnManager:  connManager,
		Masker:       masker,
		CipherSuites: cipherSuites,
	}
	if err := forward.StartServer(ctx, opts); err != nil {
		fmt.Printf("\nError: %v\n", err)
		os.Exit(1)
	}
}

func firstPairKey(m *pool.ConnectionManager) pool.PairKey {
	for k := range m.Explorer.Stats {
		return k
	}
	return pool.PairKey{}
}

func interfaceLabel(ip string) string {
	if ip == "" {
		return "auto"
	}
	return ip
}

func buildStrategy(cfg *config.Config, rawInjector forward.RawInjector) forward.BypassStrategy {
	method := strings.ToLower(cfg.GetString("BYPASS_METHOD", "fragment"))
	switch method {
	case "direct":
		return forward.DirectBypass{}
	case "fragment":
		return &forward.FragmentBypass{
			Strategy:      cfg.GetString("FRAGMENT_STRATEGY", "sni_split"),
			FragmentDelay: time.Duration(cfg.GetFloat("FRAGMENT_DELAY", 0.1) * float64(time.Second)),
			TCPNoDelay:    true,
		}
	case "fake_sni":
		return &forward.FakeSNIBypass{
			RawInjector:   rawInjector,
			FragmentReal:  cfg.GetBool("FAKE_SNI_FRAGMENT_REAL", true),
			FragmentStrat: cfg.GetString("FRAGMENT_STRATEGY", "sni_split"),
			RealFragDelay: 100 * time.Millisecond,
		}
	case "combined":
		return &forward.CombinedBypass{
			FragmentStrat: cfg.GetString("FRAGMENT_STRATEGY", "sni_split"),
			FragmentDelay: time.Duration(cfg.GetFloat("FRAGMENT_DELAY", 0.1) * float64(time.Second)),
			RawInjector:   rawInjector,
		}
	default:
		fmt.Printf("Warning: Unknown bypass method '%s', using 'fragment'\n", method)
		return &forward.FragmentBypass{
			Strategy:      "sni_split",
			FragmentDelay: 100 * time.Millisecond,
			TCPNoDelay:    true,
		}
	}
}
