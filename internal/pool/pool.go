package pool

import (
	"crypto/tls"
	"log"
	"math"
	"math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"snispf-hj-go/internal/config"
)

const (
	minProbes       = 3
	latencyCapMs    = 1500.0
	emaAlphaProbe   = 0.01
	emaAlphaReal    = 0.01
	initialSample   = 20
	exploreBatch    = 10
	verifyTop       = 15
	probeSleepMinMS = 50
	probeSleepMaxMS = 200
)

// PairKey identifies an (IP, SNI) pair.
type PairKey struct {
	IP  string
	SNI string
}

// PairStats tracks per-(IP, SNI) statistics used to rank and health-check
// upstream pairs. Port of pool.py PairStats.
type PairStats struct {
	IP        string
	SNI       string
	IPOrigin  string
	SNIOrigin string

	probesSent      int
	probesRecv      int
	realPacketsSent int
	realPacketsLost int

	emaProbeLoss float64
	emaRealLoss  float64

	latencySumMs float64
	latencyCount int

	ActiveConnections int
	TotalConnections  int
	Alive             bool
	Probed            bool
	InActivePool      bool

	forceClose     chan struct{}
	forceClosed    bool
	drainStartedAt *time.Time

	mu sync.Mutex
}

func NewPairStats(ip, sni, ipOrigin, sniOrigin string) *PairStats {
	return &PairStats{
		IP: ip, SNI: sni,
		IPOrigin: ipOrigin, SNIOrigin: sniOrigin,
		Alive:      true,
		forceClose: make(chan struct{}),
	}
}

// Lock/Unlock expose the per-pair mutex to the relay (mirrors pair.lock).
func (p *PairStats) Lock()   { p.mu.Lock() }
func (p *PairStats) Unlock() { p.mu.Unlock() }

// ForceCloseEvent returns a channel closed once the pair is force-closed.
func (p *PairStats) ForceCloseEvent() <-chan struct{} { return p.forceClose }

// IsForceClosed reports whether the drain timeout has expired for this pair.
func (p *PairStats) IsForceClosed() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.forceClosed
}

func (p *PairStats) ProbeLossRate() float64 {
	if p.probesSent < minProbes {
		return 0.0
	}
	return p.emaProbeLoss
}

func (p *PairStats) RealLossRate() float64 {
	if p.realPacketsSent == 0 {
		return 0.0
	}
	return p.emaRealLoss
}

// CombinedLossRate blends 70% real + 30% probe once real data exist.
func (p *PairStats) CombinedLossRate() float64 {
	if p.realPacketsSent > 10 {
		return 0.7*p.RealLossRate() + 0.3*p.ProbeLossRate()
	}
	return p.ProbeLossRate()
}

func (p *PairStats) AvgLatencyMs() float64 {
	if p.latencyCount == 0 {
		return latencyCapMs
	}
	return p.latencySumMs / float64(p.latencyCount)
}

func (p *PairStats) LatencyScore() float64 {
	return math.Min(p.AvgLatencyMs(), latencyCapMs) / latencyCapMs
}

// Score is the composite score — lower is better. Dead -> +inf, unknown -> 0.5.
func (p *PairStats) Score() float64 {
	if !p.Alive {
		return math.Inf(1)
	}
	if !p.Probed {
		return 0.5
	}
	return 0.60*p.CombinedLossRate() + 0.20*p.LatencyScore() + 0.20*p.ProbeLossRate()
}

func (p *PairStats) IsStable() bool {
	return p.Alive && p.Probed
}

func (p *PairStats) RecordProbe(success bool, deadThreshold, latencyMs float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probesSent++
	p.Probed = true
	lossThis := 0.0
	if !success {
		lossThis = 1.0
	}
	p.emaProbeLoss = emaAlphaProbe*lossThis + (1-emaAlphaProbe)*p.emaProbeLoss
	if success {
		p.probesRecv++
		p.latencySumMs += latencyMs
		p.latencyCount++
	}
	if p.probesSent >= minProbes {
		if p.emaProbeLoss >= deadThreshold {
			p.Alive = false
		} else if p.probesRecv > 0 {
			p.Alive = true
		}
	}
}

func (p *PairStats) RecordRealPacket(lost bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.realPacketsSent++
	if lost {
		p.realPacketsLost++
	}
	lossThis := 0.0
	if lost {
		lossThis = 1.0
	}
	p.emaRealLoss = emaAlphaReal*lossThis + (1-emaAlphaReal)*p.emaRealLoss
}

func (p *PairStats) StartDraining() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.drainStartedAt == nil {
		now := time.Now()
		p.drainStartedAt = &now
	}
}

func (p *PairStats) ForceClose() {
	p.mu.Lock()
	p.InActivePool = false
	p.mu.Unlock()
	p.mu.Lock()
	if !p.forceClosed {
		p.forceClosed = true
		close(p.forceClose)
	}
	p.mu.Unlock()
	log.Printf("Force-closing pair %s / %s (%d active connection(s))", p.IP, p.SNI, p.ActiveConnections)
}

func (p *PairStats) DrainAge() float64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.drainStartedAt == nil {
		return 0.0
	}
	return time.Since(*p.drainStartedAt).Seconds()
}

// QuarantineInfo tracks an evicted IP or SNI for potential recycling.
type QuarantineInfo struct {
	Partners    []string
	Origin      string
	EvictedAt   time.Time
	LastAttempt time.Time
	Attempts    int
}

// CombinationExplorer gradually discovers and health-checks the full
// cartesian product of IPs × SNIs. Port of pool.py CombinationExplorer.
type CombinationExplorer struct {
	Port          int
	Timeout       time.Duration
	ProbeCount    int
	LossThreshold float64
	DeadThreshold float64
	// ClientSniProvider returns the last observed client SNI + whether to use
	// TLS probing (false = plain TCP connect fallback).
	ClientSniProvider func() (string, bool)

	Stats           map[PairKey]*PairStats
	IPOriginLedger  map[string]string
	SNIOriginLedger map[string]string
	IPQuarantine    map[string]*QuarantineInfo
	SNIQuarantine   map[string]*QuarantineInfo
	unexplored      []PairKey
	AllIPs          []string
	AllSNIs         []string

	mu sync.Mutex
}

func NewCombinationExplorer(combinations []PairKey, port int, timeout time.Duration, probeCount int, lossThreshold, deadThreshold float64, sniProvider func() (string, bool)) *CombinationExplorer {
	e := &CombinationExplorer{
		Port:              port,
		Timeout:           timeout,
		ProbeCount:        probeCount,
		LossThreshold:     lossThreshold,
		DeadThreshold:     deadThreshold,
		ClientSniProvider: sniProvider,
		Stats:             make(map[PairKey]*PairStats),
		IPOriginLedger:    make(map[string]string),
		SNIOriginLedger:   make(map[string]string),
		IPQuarantine:      make(map[string]*QuarantineInfo),
		SNIQuarantine:     make(map[string]*QuarantineInfo),
	}
	seenIPs := map[string]bool{}
	seenSNIs := map[string]bool{}
	for _, c := range combinations {
		e.Stats[c] = NewPairStats(c.IP, c.SNI, "static", "static")
		e.IPOriginLedger[c.IP] = "static"
		e.SNIOriginLedger[c.SNI] = "static"
		seenIPs[c.IP] = true
		seenSNIs[c.SNI] = true
		e.unexplored = append(e.unexplored, c)
	}
	rand.Shuffle(len(e.unexplored), func(i, j int) {
		e.unexplored[i], e.unexplored[j] = e.unexplored[j], e.unexplored[i]
	})
	for ip := range seenIPs {
		e.AllIPs = append(e.AllIPs, ip)
	}
	for sni := range seenSNIs {
		e.AllSNIs = append(e.AllSNIs, sni)
	}
	sortStrings(e.AllIPs)
	sortStrings(e.AllSNIs)
	return e
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

func (e *CombinationExplorer) AllStats() []*PairStats {
	out := make([]*PairStats, 0, len(e.Stats))
	for _, ps := range e.Stats {
		out = append(out, ps)
	}
	return out
}

func (e *CombinationExplorer) KnownStats() []*PairStats {
	var out []*PairStats
	for _, ps := range e.Stats {
		if ps.Probed {
			out = append(out, ps)
		}
	}
	return out
}

func (e *CombinationExplorer) StableStats() []*PairStats {
	var out []*PairStats
	for _, ps := range e.KnownStats() {
		if ps.Alive && ps.CombinedLossRate() < e.LossThreshold {
			out = append(out, ps)
		}
	}
	return out
}

// LookupSNIOrigin is the authoritative SNI origin lookup.
func (e *CombinationExplorer) LookupSNIOrigin(sni string) string {
	if o, ok := e.SNIOriginLedger[sni]; ok {
		return o
	}
	for key, ps := range e.Stats {
		if key.SNI == sni {
			return ps.SNIOrigin
		}
	}
	if qi, ok := e.SNIQuarantine[sni]; ok {
		return qi.Origin
	}
	return "dynamic"
}

// LookupIPOrigin is the authoritative IP origin lookup.
func (e *CombinationExplorer) LookupIPOrigin(ip string) string {
	if o, ok := e.IPOriginLedger[ip]; ok {
		return o
	}
	for key, ps := range e.Stats {
		if key.IP == ip {
			return ps.IPOrigin
		}
	}
	if qi, ok := e.IPQuarantine[ip]; ok {
		return qi.Origin
	}
	return "dynamic"
}

// ── Bookkeeping helpers used by dynamic IP/SNI discovery ────────────────────

// SnapshotAllIPs returns a copy of the currently active IP list.
func (e *CombinationExplorer) SnapshotAllIPs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.AllIPs...)
}

// SnapshotAllSNIs returns a copy of the currently active SNI list.
func (e *CombinationExplorer) SnapshotAllSNIs() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return append([]string{}, e.AllSNIs...)
}

// SnapshotKnownIPs returns the set of IPs with at least one live pair.
func (e *CombinationExplorer) SnapshotKnownIPs() map[string]bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := map[string]bool{}
	for k := range e.Stats {
		seen[k.IP] = true
	}
	return seen
}

// SnapshotKnownSNIs returns the set of SNIs with at least one live pair.
func (e *CombinationExplorer) SnapshotKnownSNIs() map[string]bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	seen := map[string]bool{}
	for k := range e.Stats {
		seen[k.SNI] = true
	}
	return seen
}

// AddUnexploredPair registers a new (ip, sni) pair (with origins) and queues
// it for probing. Used by dynamic discovery to inject fresh pairs.
func (e *CombinationExplorer) AddUnexploredPair(ip, sni, ipOrigin, sniOrigin string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	key := PairKey{IP: ip, SNI: sni}
	if _, ok := e.Stats[key]; ok {
		return
	}
	e.Stats[key] = NewPairStats(ip, sni, ipOrigin, sniOrigin)
	e.unexplored = append(e.unexplored, key)
	if !containsStr(e.AllIPs, ip) {
		e.AllIPs = append(e.AllIPs, ip)
	}
	if !containsStr(e.AllSNIs, sni) {
		e.AllSNIs = append(e.AllSNIs, sni)
	}
}

// RemoveAllPairsForIP drops every live pair carrying the IP.
func (e *CombinationExplorer) RemoveAllPairsForIP(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.Stats {
		if k.IP == ip {
			delete(e.Stats, k)
		}
	}
	var un []PairKey
	for _, k := range e.unexplored {
		if k.IP != ip {
			un = append(un, k)
		}
	}
	e.unexplored = un
}

// RemoveAllPairsForSNI drops every live pair carrying the SNI.
func (e *CombinationExplorer) RemoveAllPairsForSNI(sni string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k := range e.Stats {
		if k.SNI == sni {
			delete(e.Stats, k)
		}
	}
	var un []PairKey
	for _, k := range e.unexplored {
		if k.SNI != sni {
			un = append(un, k)
		}
	}
	e.unexplored = un
}

// RemoveIPBookkeeping forgets an IP entirely (drops from active list + ledger).
func (e *CombinationExplorer) RemoveIPBookkeeping(ip string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, x := range e.AllIPs {
		if x == ip {
			e.AllIPs = append(e.AllIPs[:i], e.AllIPs[i+1:]...)
			break
		}
	}
	delete(e.IPOriginLedger, ip)
}

// RemoveSNIBookkeeping forgets an SNI entirely (drops from active list + ledger).
func (e *CombinationExplorer) RemoveSNIBookkeeping(sni string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, x := range e.AllSNIs {
		if x == sni {
			e.AllSNIs = append(e.AllSNIs[:i], e.AllSNIs[i+1:]...)
			break
		}
	}
	delete(e.SNIOriginLedger, sni)
}

// SetIPOrigin permanently records an IP's origin (static/dynamic).
func (e *CombinationExplorer) SetIPOrigin(ip, origin string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.IPOriginLedger[ip] = origin
}

// HasIPOrigin reports whether the IP exists in the origin ledger (ever seen).
func (e *CombinationExplorer) HasIPOrigin(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.IPOriginLedger[ip]
	return ok
}

// SetSNIOrigin permanently records an SNI's origin (static/dynamic).
func (e *CombinationExplorer) SetSNIOrigin(sni, origin string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.SNIOriginLedger[sni] = origin
}

// HasSNIOrigin reports whether the SNI exists in the origin ledger (ever seen).
func (e *CombinationExplorer) HasSNIOrigin(sni string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.SNIOriginLedger[sni]
	return ok
}

// IsIPQuarantined reports whether the IP currently sits in quarantine.
func (e *CombinationExplorer) IsIPQuarantined(ip string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.IPQuarantine[ip]
	return ok
}

// IsSNIQuarantined reports whether the SNI currently sits in quarantine.
func (e *CombinationExplorer) IsSNIQuarantined(sni string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, ok := e.SNIQuarantine[sni]
	return ok
}

func (e *CombinationExplorer) ProbeOne(ps *PairStats) {
	probeSNI := ps.SNI
	useTLS := true
	if e.ClientSniProvider != nil {
		probeSNI, useTLS = e.ClientSniProvider()
	}
	count := max(2, e.ProbeCount+randInt(-1, 1))
	for i := 0; i < count; i++ {
		success := false
		latencyMs := 0.0
		start := time.Now()
		addr := net.JoinHostPort(ps.IP, strconv.Itoa(e.Port))
		dialer := &net.Dialer{Timeout: e.Timeout}
		conn, err := dialer.Dial("tcp", addr)
		if err == nil {
			if useTLS {
				_ = conn.SetDeadline(time.Now().Add(e.Timeout))
				tconn := tls.Client(conn, &tls.Config{ServerName: probeSNI, InsecureSkipVerify: true})
				if tconn.Handshake() == nil {
					latencyMs = time.Since(start).Seconds() * 1000
					success = true
				}
				_ = tconn.Close()
			} else {
				latencyMs = time.Since(start).Seconds() * 1000
				success = true
				_ = conn.Close()
			}
		}
		ps.RecordProbe(success, e.DeadThreshold, latencyMs)
		sleepMs := randFloat(probeSleepMinMS, probeSleepMaxMS)
		time.Sleep(time.Duration(sleepMs) * time.Millisecond)
	}
}

func (e *CombinationExplorer) runProbesParallel(pairs []*PairStats) {
	rand.Shuffle(len(pairs), func(i, j int) { pairs[i], pairs[j] = pairs[j], pairs[i] })
	var wg sync.WaitGroup
	for _, ps := range pairs {
		wg.Add(1)
		go func(p *PairStats) {
			defer wg.Done()
			e.ProbeOne(p)
		}(ps)
		time.Sleep(time.Duration(randFloat(0, 30)) * time.Millisecond)
	}
	wg.Wait()
}

// InitialExplore probes a random sample of INITIAL_SAMPLE pairs.
func (e *CombinationExplorer) InitialExplore() {
	e.mu.Lock()
	batchKeys := e.unexplored[:minInt(initialSample, len(e.unexplored))]
	e.unexplored = e.unexplored[minInt(initialSample, len(e.unexplored)):]
	e.mu.Unlock()
	var batch []*PairStats
	for _, k := range batchKeys {
		if ps, ok := e.Stats[k]; ok {
			batch = append(batch, ps)
		}
	}
	log.Printf("Initial probe: %d combinations ...", len(batch))
	e.runProbesParallel(batch)
}

// PeriodicExplore re-verifies top pairs and explores a fresh batch.
func (e *CombinationExplorer) PeriodicExplore() {
	known := e.KnownStats()
	sortByScore(known)
	toVerify := known[:minInt(verifyTop, len(known))]
	if len(toVerify) > 0 {
		log.Printf("Verifying top %d known pairs ...", len(toVerify))
		e.runProbesParallel(toVerify)
	}

	e.mu.Lock()
	batchKeys := e.unexplored[:minInt(exploreBatch, len(e.unexplored))]
	e.unexplored = e.unexplored[minInt(exploreBatch, len(e.unexplored)):]
	remaining := len(e.unexplored)
	e.mu.Unlock()

	var batch []*PairStats
	for _, k := range batchKeys {
		if ps, ok := e.Stats[k]; ok {
			batch = append(batch, ps)
		}
	}
	if len(batch) > 0 {
		log.Printf("Exploring %d new combinations (%d remaining) ...", len(batch), remaining)
		e.runProbesParallel(batch)
	} else {
		log.Printf("All combinations explored — reshuffling for next cycle.")
		e.mu.Lock()
		allKeys := make([]PairKey, 0, len(e.Stats))
		for k := range e.Stats {
			allKeys = append(allKeys, k)
		}
		rand.Shuffle(len(allKeys), func(i, j int) { allKeys[i], allKeys[j] = allKeys[j], allKeys[i] })
		e.unexplored = allKeys
		e.mu.Unlock()
	}
}

// EvictWeakestIP moves the weakest IP's pairs into quarantine.
func (e *CombinationExplorer) EvictWeakestIP(protectedIPs map[string]bool, scope string) string {
	ipLoss := map[string][]float64{}
	for key, ps := range e.Stats {
		if protectedIPs[key.IP] {
			continue
		}
		if scope != "both" && ps.IPOrigin != scope {
			continue
		}
		if ps.Probed {
			ipLoss[key.IP] = append(ipLoss[key.IP], ps.CombinedLossRate())
		}
	}
	if len(ipLoss) == 0 {
		return ""
	}
	var worstIP string
	worstAvg := -1.0
	for ip, losses := range ipLoss {
		avg := avgF64(losses)
		if avg > worstAvg {
			worstAvg = avg
			worstIP = ip
		}
	}
	if worstAvg < e.LossThreshold {
		return ""
	}

	var keysToRemove []PairKey
	var snisForIP []string
	ipOrigin := "static"
	for k := range e.Stats {
		if k.IP == worstIP {
			keysToRemove = append(keysToRemove, k)
			snisForIP = append(snisForIP, k.SNI)
		}
	}
	if len(keysToRemove) > 0 {
		ipOrigin = e.Stats[keysToRemove[0]].IPOrigin
	}
	for _, k := range keysToRemove {
		delete(e.Stats, k)
	}
	e.mu.Lock()
	var un []PairKey
	for _, k := range e.unexplored {
		if k.IP != worstIP {
			un = append(un, k)
		}
	}
	e.unexplored = un
	var ips []string
	for _, ip := range e.AllIPs {
		if ip != worstIP {
			ips = append(ips, ip)
		}
	}
	e.AllIPs = ips
	e.IPQuarantine[worstIP] = &QuarantineInfo{
		Partners: snisForIP, Origin: ipOrigin,
		EvictedAt: time.Now(), LastAttempt: time.Now(),
	}
	e.mu.Unlock()

	log.Printf("Evicted IP %s to quarantine (avg loss %.1f%%, %d pair(s) removed)", worstIP, worstAvg*100, len(keysToRemove))
	e.quarantineOrphanedSNIs()
	return worstIP
}

// EvictWeakestSNI mirrors EvictWeakestIP on the SNI axis.
func (e *CombinationExplorer) EvictWeakestSNI(protectedSNIs map[string]bool, scope string) string {
	sniLoss := map[string][]float64{}
	for key, ps := range e.Stats {
		if protectedSNIs[key.SNI] {
			continue
		}
		if scope != "both" && ps.SNIOrigin != scope {
			continue
		}
		if ps.Probed {
			sniLoss[key.SNI] = append(sniLoss[key.SNI], ps.CombinedLossRate())
		}
	}
	if len(sniLoss) == 0 {
		return ""
	}
	var worstSNI string
	worstAvg := -1.0
	for sni, losses := range sniLoss {
		avg := avgF64(losses)
		if avg > worstAvg {
			worstAvg = avg
			worstSNI = sni
		}
	}
	if worstAvg < e.LossThreshold {
		return ""
	}

	var keysToRemove []PairKey
	var ipsForSNI []string
	sniOrigin := "static"
	for k := range e.Stats {
		if k.SNI == worstSNI {
			keysToRemove = append(keysToRemove, k)
			ipsForSNI = append(ipsForSNI, k.IP)
		}
	}
	if len(keysToRemove) > 0 {
		sniOrigin = e.Stats[keysToRemove[0]].SNIOrigin
	}
	for _, k := range keysToRemove {
		delete(e.Stats, k)
	}
	e.mu.Lock()
	var un []PairKey
	for _, k := range e.unexplored {
		if k.SNI != worstSNI {
			un = append(un, k)
		}
	}
	e.unexplored = un
	var snis []string
	for _, s := range e.AllSNIs {
		if s != worstSNI {
			snis = append(snis, s)
		}
	}
	e.AllSNIs = snis
	e.SNIQuarantine[worstSNI] = &QuarantineInfo{
		Partners: ipsForSNI, Origin: sniOrigin,
		EvictedAt: time.Now(), LastAttempt: time.Now(),
	}
	e.mu.Unlock()

	log.Printf("Evicted SNI %s to quarantine (avg loss %.1f%%, %d pair(s) removed)", worstSNI, worstAvg*100, len(keysToRemove))
	e.quarantineOrphanedIPs()
	return worstSNI
}

func (e *CombinationExplorer) quarantineOrphanedIPs() int {
	e.mu.Lock()
	activeIPs := map[string]bool{}
	for k := range e.Stats {
		activeIPs[k.IP] = true
	}
	var orphans []string
	for _, ip := range e.AllIPs {
		if !activeIPs[ip] {
			if _, ok := e.IPQuarantine[ip]; !ok {
				orphans = append(orphans, ip)
			}
		}
	}
	for _, ip := range orphans {
		origin := e.IPOriginLedger[ip]
		if origin == "" {
			origin = "static"
		}
		e.IPQuarantine[ip] = &QuarantineInfo{
			Origin: origin, EvictedAt: time.Now(), LastAttempt: time.Now(),
		}
	}
	var ips []string
	for _, ip := range e.AllIPs {
		skip := false
		for _, o := range orphans {
			if o == ip {
				skip = true
				break
			}
		}
		if !skip {
			ips = append(ips, ip)
		}
	}
	e.AllIPs = ips
	var un []PairKey
	for _, k := range e.unexplored {
		skip := false
		for _, o := range orphans {
			if o == k.IP {
				skip = true
				break
			}
		}
		if !skip {
			un = append(un, k)
		}
	}
	e.unexplored = un
	e.mu.Unlock()
	if len(orphans) > 0 {
		log.Printf("Quarantined %d orphaned IP(s) with zero active pairs: %v", len(orphans), orphans)
	}
	return len(orphans)
}

func (e *CombinationExplorer) quarantineOrphanedSNIs() int {
	e.mu.Lock()
	activeSNIs := map[string]bool{}
	for k := range e.Stats {
		activeSNIs[k.SNI] = true
	}
	var orphans []string
	for _, sni := range e.AllSNIs {
		if !activeSNIs[sni] {
			if _, ok := e.SNIQuarantine[sni]; !ok {
				orphans = append(orphans, sni)
			}
		}
	}
	for _, sni := range orphans {
		origin := e.SNIOriginLedger[sni]
		if origin == "" {
			origin = "static"
		}
		e.SNIQuarantine[sni] = &QuarantineInfo{
			Origin: origin, EvictedAt: time.Now(), LastAttempt: time.Now(),
		}
	}
	var snis []string
	for _, s := range e.AllSNIs {
		skip := false
		for _, o := range orphans {
			if o == s {
				skip = true
				break
			}
		}
		if !skip {
			snis = append(snis, s)
		}
	}
	e.AllSNIs = snis
	var un []PairKey
	for _, k := range e.unexplored {
		skip := false
		for _, o := range orphans {
			if o == k.SNI {
				skip = true
				break
			}
		}
		if !skip {
			un = append(un, k)
		}
	}
	e.unexplored = un
	e.mu.Unlock()
	if len(orphans) > 0 {
		log.Printf("Quarantined %d orphaned SNI(s) with zero active pairs: %v", len(orphans), orphans)
	}
	return len(orphans)
}

// RecycleIPAttempt randomly re-probes quarantined IPs and recovers healthy ones.
func (e *CombinationExplorer) RecycleIPAttempt(batch int, minCooldown float64, maxQuarantine int, scope string) int {
	e.mu.Lock()
	if len(e.IPQuarantine) > maxQuarantine {
		overflow := len(e.IPQuarantine) - maxQuarantine
		// drop oldest
		var ages []struct {
			ip  string
			age time.Time
		}
		for ip, info := range e.IPQuarantine {
			ages = append(ages, struct {
				ip  string
				age time.Time
			}{ip, info.EvictedAt})
		}
		sortIPAgeKeys(ages)
		for i := 0; i < overflow && i < len(ages); i++ {
			delete(e.IPQuarantine, ages[i].ip)
		}
	}
	now := time.Now()
	var eligible []string
	for ip, info := range e.IPQuarantine {
		if now.Sub(info.LastAttempt).Seconds() >= minCooldown &&
			(scope == "both" || info.Origin == scope) {
			eligible = append(eligible, ip)
		}
	}
	if len(eligible) == 0 {
		e.mu.Unlock()
		return 0
	}
	rand.Shuffle(len(eligible), func(i, j int) { eligible[i], eligible[j] = eligible[j], eligible[i] })
	candidates := eligible[:minInt(batch, len(eligible))]
	e.mu.Unlock()

	recovered := 0
	for _, ip := range candidates {
		if e.tryRecycleIPOne(ip) {
			recovered++
		}
	}
	return recovered
}

func (e *CombinationExplorer) tryRecycleIPOne(ip string) bool {
	e.mu.Lock()
	info := e.IPQuarantine[ip]
	if info == nil {
		e.mu.Unlock()
		return false
	}
	info.LastAttempt = time.Now()
	info.Attempts++
	snis := append([]string{}, info.Partners...)
	ipOrigin := info.Origin
	if ipOrigin == "" {
		ipOrigin = "static"
	}
	e.mu.Unlock()

	probeSNI := ""
	if len(snis) > 0 {
		probeSNI = snis[0]
	} else if len(e.AllSNIs) > 0 {
		probeSNI = e.AllSNIs[rand.Intn(len(e.AllSNIs))]
	} else {
		return false
	}

	trial := NewPairStats(ip, probeSNI, ipOrigin, "static")
	e.ProbeOne(trial)
	if !trial.Alive || trial.CombinedLossRate() >= e.LossThreshold {
		return false
	}

	restoreSNIs := snis
	if len(restoreSNIs) == 0 {
		restoreSNIs = []string{probeSNI}
	}
	e.mu.Lock()
	delete(e.IPQuarantine, ip)
	for _, sni := range restoreSNIs {
		if _, ok := e.SNIQuarantine[sni]; ok {
			continue
		}
		key := PairKey{IP: ip, SNI: sni}
		if _, ok := e.Stats[key]; !ok {
			sniOrigin := e.LookupSNIOrigin(sni)
			e.Stats[key] = NewPairStats(ip, sni, ipOrigin, sniOrigin)
			e.unexplored = append(e.unexplored, key)
		}
	}
	if !containsStr(e.AllIPs, ip) {
		e.AllIPs = append(e.AllIPs, ip)
	}
	e.mu.Unlock()
	log.Printf("Recycled IP %s back into the pool (probe loss=%.1f%%, %d pair(s) restored)", ip, trial.CombinedLossRate()*100, len(restoreSNIs))
	return true
}

// RecycleSNIAttempt mirrors RecycleIPAttempt on the SNI axis.
func (e *CombinationExplorer) RecycleSNIAttempt(batch int, minCooldown float64, maxQuarantine int, scope string) int {
	e.mu.Lock()
	if len(e.SNIQuarantine) > maxQuarantine {
		overflow := len(e.SNIQuarantine) - maxQuarantine
		var ages []struct {
			sni string
			age time.Time
		}
		for sni, info := range e.SNIQuarantine {
			ages = append(ages, struct {
				sni string
				age time.Time
			}{sni, info.EvictedAt})
		}
		sortAgeKeysSNI(ages)
		for i := 0; i < overflow && i < len(ages); i++ {
			delete(e.SNIQuarantine, ages[i].sni)
		}
	}
	now := time.Now()
	var eligible []string
	for sni, info := range e.SNIQuarantine {
		if now.Sub(info.LastAttempt).Seconds() >= minCooldown &&
			(scope == "both" || info.Origin == scope) {
			eligible = append(eligible, sni)
		}
	}
	if len(eligible) == 0 {
		e.mu.Unlock()
		return 0
	}
	rand.Shuffle(len(eligible), func(i, j int) { eligible[i], eligible[j] = eligible[j], eligible[i] })
	candidates := eligible[:minInt(batch, len(eligible))]
	e.mu.Unlock()

	recovered := 0
	for _, sni := range candidates {
		if e.tryRecycleSNIOne(sni) {
			recovered++
		}
	}
	return recovered
}

func (e *CombinationExplorer) tryRecycleSNIOne(sni string) bool {
	e.mu.Lock()
	info := e.SNIQuarantine[sni]
	if info == nil {
		e.mu.Unlock()
		return false
	}
	info.LastAttempt = time.Now()
	info.Attempts++
	ips := append([]string{}, info.Partners...)
	sniOrigin := info.Origin
	if sniOrigin == "" {
		sniOrigin = "static"
	}
	e.mu.Unlock()

	probeIP := ""
	if len(ips) > 0 {
		probeIP = ips[0]
	} else if len(e.AllIPs) > 0 {
		probeIP = e.AllIPs[rand.Intn(len(e.AllIPs))]
	} else {
		return false
	}

	trial := NewPairStats(probeIP, sni, "static", sniOrigin)
	e.ProbeOne(trial)
	if !trial.Alive || trial.CombinedLossRate() >= e.LossThreshold {
		return false
	}

	restoreIPs := ips
	if len(restoreIPs) == 0 {
		restoreIPs = []string{probeIP}
	}
	e.mu.Lock()
	delete(e.SNIQuarantine, sni)
	for _, ip := range restoreIPs {
		if _, ok := e.IPQuarantine[ip]; ok {
			continue
		}
		key := PairKey{IP: ip, SNI: sni}
		if _, ok := e.Stats[key]; !ok {
			ipOrigin := e.LookupIPOrigin(ip)
			e.Stats[key] = NewPairStats(ip, sni, ipOrigin, sniOrigin)
			e.unexplored = append(e.unexplored, key)
		}
	}
	if !containsStr(e.AllSNIs, sni) {
		e.AllSNIs = append(e.AllSNIs, sni)
	}
	e.mu.Unlock()
	log.Printf("Recycled SNI %s back into the pool (probe loss=%.1f%%, %d pair(s) restored)", sni, trial.CombinedLossRate()*100, len(restoreIPs))
	return true
}

// PrintSummary logs a pool summary.
func (e *CombinationExplorer) PrintSummary() {
	known := e.KnownStats()
	var stable, weak, dead []*PairStats
	for _, ps := range known {
		switch {
		case !ps.Alive:
			dead = append(dead, ps)
		case ps.CombinedLossRate() >= e.LossThreshold:
			weak = append(weak, ps)
		default:
			stable = append(stable, ps)
		}
	}
	unknownCount := len(e.Stats) - len(known)
	log.Printf("Pool summary — known=%d  stable=%d  weak=%d  dead=%d  unexplored=%d",
		len(known), len(stable), len(weak), len(dead), unknownCount)
	sortByScore(stable)
	for _, ps := range stable[:minInt(8, len(stable))] {
		marker := " "
		if ps.InActivePool {
			marker = "*"
		}
		log.Printf("  %s %-20s %-25s  loss=%.1f%%  latency=%dms  score=%.3f  active=%d",
			marker, ps.IP, ps.SNI, ps.CombinedLossRate()*100, int(ps.AvgLatencyMs()), ps.Score(), ps.ActiveConnections)
	}
}

// ActivePool maintains ACTIVE_SLOTS stable pairs. Port of pool.py ActivePool.
type ActivePool struct {
	Explorer *CombinationExplorer
	Slots    int

	LossThreshold        float64
	DrainTimeout         float64
	MaxDraining          int
	EvictEvery           int
	EvictCount           int
	RecycleEnabled       bool
	RecycleEvery         int
	RecycleBatch         int
	RecycleMinCooldown   float64
	RecycleMaxQuarantine int
	QuarantineScope      string

	SNIEvictEvery           int
	SNIEvictCount           int
	SNIRecycleEnabled       bool
	SNIRecycleEvery         int
	SNIRecycleBatch         int
	SNIRecycleMinCooldown   float64
	SNIRecycleMaxQuarantine int
	SNIQuarantineScope      string

	pool         []*PairStats
	draining     []*PairStats
	mu           sync.Mutex
	refreshCount int
}

func NewActivePool(e *CombinationExplorer, slots int, lossThreshold, drainTimeout float64, maxDraining, evictEvery, evictCount int, recycleEnabled bool, recycleEvery, recycleBatch int, recycleMinCooldown, recycleMaxQuarantine float64, quarantineScope string, sniEvictEvery, sniEvictCount int, sniRecycleEnabled bool, sniRecycleEvery, sniRecycleBatch int, sniRecycleMinCooldown, sniRecycleMaxQuarantine float64, sniQuarantineScope string) *ActivePool {
	return &ActivePool{
		Explorer: e, Slots: slots,
		LossThreshold: lossThreshold, DrainTimeout: drainTimeout, MaxDraining: maxDraining,
		EvictEvery: evictEvery, EvictCount: evictCount,
		RecycleEnabled: recycleEnabled, RecycleEvery: recycleEvery, RecycleBatch: recycleBatch,
		RecycleMinCooldown: recycleMinCooldown, RecycleMaxQuarantine: int(recycleMaxQuarantine),
		QuarantineScope: quarantineScope,
		SNIEvictEvery:   sniEvictEvery, SNIEvictCount: sniEvictCount,
		SNIRecycleEnabled: sniRecycleEnabled, SNIRecycleEvery: sniRecycleEvery, SNIRecycleBatch: sniRecycleBatch,
		SNIRecycleMinCooldown: sniRecycleMinCooldown, SNIRecycleMaxQuarantine: int(sniRecycleMaxQuarantine),
		SNIQuarantineScope: sniQuarantineScope,
	}
}

func (p *ActivePool) Initialize() {
	p.mu.Lock()
	candidates := p.Explorer.StableStats()
	if len(candidates) == 0 {
		candidates = p.Explorer.KnownStats()
	}
	rand.Shuffle(len(candidates), func(i, j int) { candidates[i], candidates[j] = candidates[j], candidates[i] })
	p.pool = candidates[:minInt(p.Slots, len(candidates))]
	for _, ps := range p.pool {
		ps.InActivePool = true
	}
	p.mu.Unlock()
	p.logPool("INIT")
}

func (p *ActivePool) Refresh() {
	p.mu.Lock()
	p.refreshCount++

	// 1. Enforce drain timeout
	for _, ps := range p.draining {
		if ps.DrainAge() >= p.DrainTimeout {
			ps.ForceClose()
		}
	}

	// 2. Clean up fully-drained pairs
	var still []*PairStats
	for _, ps := range p.draining {
		if ps.ActiveConnections > 0 {
			still = append(still, ps)
		} else {
			ps.InActivePool = false
		}
	}
	p.draining = still

	// 3. Move weak pairs to draining
	var weak []*PairStats
	var remainingPool []*PairStats
	for _, ps := range p.pool {
		if !ps.Alive || ps.CombinedLossRate() >= p.LossThreshold {
			weak = append(weak, ps)
		} else {
			remainingPool = append(remainingPool, ps)
		}
	}
	p.pool = remainingPool
	for _, ps := range weak {
		p.startDraining(ps)
	}

	// 4. Fill empty slots
	inUse := map[*PairStats]bool{}
	for _, ps := range p.pool {
		inUse[ps] = true
	}
	for _, ps := range p.draining {
		inUse[ps] = true
	}
	candidates := p.Explorer.StableStats()
	if len(candidates) == 0 {
		candidates = p.Explorer.KnownStats()
	}
	var free []*PairStats
	for _, ps := range candidates {
		if !inUse[ps] {
			free = append(free, ps)
		}
	}
	needed := p.Slots - len(p.pool)
	if needed > 0 && len(free) > 0 {
		chosen := weightedChoices(free, needed)
		for _, ps := range chosen {
			ps.InActivePool = true
			p.pool = append(p.pool, ps)
		}
	}

	shouldEvictIP := p.refreshCount%p.EvictEvery == 0
	shouldEvictSNI := p.SNIEvictEvery > 0 && p.refreshCount%p.SNIEvictEvery == 0
	p.mu.Unlock()

	// 5. Periodic IP eviction (outside lock)
	if shouldEvictIP {
		protected := p.ProtectedIPs()
		evictedCount := 0
		for i := 0; i < p.EvictCount; i++ {
			evicted := p.Explorer.EvictWeakestIP(protected, p.QuarantineScope)
			if evicted == "" {
				break
			}
			evictedCount++
			delete(protected, evicted)
		}
		if evictedCount > 0 {
			log.Printf("Eviction cycle %d: removed %d IP(s) (scope=%s)", p.refreshCount, evictedCount, p.QuarantineScope)
		}
	}

	// 5b. Periodic SNI eviction
	if shouldEvictSNI {
		protected := p.ProtectedSNIs()
		evictedCount := 0
		for i := 0; i < p.SNIEvictCount; i++ {
			evicted := p.Explorer.EvictWeakestSNI(protected, p.SNIQuarantineScope)
			if evicted == "" {
				break
			}
			evictedCount++
			delete(protected, evicted)
		}
		if evictedCount > 0 {
			log.Printf("SNI eviction cycle %d: removed %d SNI(s) (scope=%s)", p.refreshCount, evictedCount, p.SNIQuarantineScope)
		}
	}

	// 6. Periodic recycling
	if p.RecycleEnabled && p.refreshCount%p.RecycleEvery == 0 {
		recovered := p.Explorer.RecycleIPAttempt(p.RecycleBatch, p.RecycleMinCooldown, p.RecycleMaxQuarantine, p.QuarantineScope)
		if recovered > 0 {
			log.Printf("Recycle cycle %d: restored %d IP(s) from quarantine (scope=%s)", p.refreshCount, recovered, p.QuarantineScope)
		}
	}
	if p.SNIRecycleEnabled && p.refreshCount%p.SNIRecycleEvery == 0 {
		recovered := p.Explorer.RecycleSNIAttempt(p.SNIRecycleBatch, p.SNIRecycleMinCooldown, p.SNIRecycleMaxQuarantine, p.SNIQuarantineScope)
		if recovered > 0 {
			log.Printf("SNI recycle cycle %d: restored %d SNI(s) from quarantine (scope=%s)", p.refreshCount, recovered, p.SNIQuarantineScope)
		}
	}

	// 7. Independent orphan sweep
	ipOrphans := p.Explorer.quarantineOrphanedIPs()
	sniOrphans := p.Explorer.quarantineOrphanedSNIs()
	if ipOrphans > 0 || sniOrphans > 0 {
		log.Printf("Orphan sweep: quarantined %d IP(s) and %d SNI(s) with zero active pairs", ipOrphans, sniOrphans)
	}

	p.logPool("REFRESH")
}

func (p *ActivePool) startDraining(ps *PairStats) {
	ps.StartDraining()
	if len(p.draining) >= p.MaxDraining {
		var oldest *PairStats
		maxAge := -1.0
		for _, d := range p.draining {
			a := d.DrainAge()
			if a > maxAge {
				maxAge = a
				oldest = d
			}
		}
		if oldest != nil {
			log.Printf("Drain cap (%d) reached — force-closing oldest pair %s/%s (age=%.0fs, active=%d)",
				p.MaxDraining, oldest.IP, oldest.SNI, oldest.DrainAge(), oldest.ActiveConnections)
			oldest.ForceClose()
		}
	}
	p.draining = append(p.draining, ps)
}

func (p *ActivePool) ProtectedIPs() map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	set := map[string]bool{}
	for _, ps := range append(append([]*PairStats{}, p.pool...), p.draining...) {
		set[ps.IP] = true
	}
	return set
}

func (p *ActivePool) ProtectedSNIs() map[string]bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	set := map[string]bool{}
	for _, ps := range append(append([]*PairStats{}, p.pool...), p.draining...) {
		set[ps.SNI] = true
	}
	return set
}

// Pick returns the best pair for the next connection (weighted-random).
func (p *ActivePool) Pick() *PairStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	pool := p.pool
	if len(pool) == 0 {
		pool = p.Explorer.KnownStats()
	}
	if len(pool) == 0 {
		pool = p.Explorer.AllStats()
	}
	return weightedChoices(pool, 1)[0]
}

func (p *ActivePool) ReportFailure(ps *PairStats) {
	ps.RecordProbe(false, p.Explorer.DeadThreshold, 0)
	if !ps.Alive || ps.CombinedLossRate() >= p.LossThreshold {
		p.Refresh()
	}
}

func (p *ActivePool) logPool(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	log.Printf("[Pool/%s] active=%d  draining=%d  (evict_cycle=%d/%d)",
		reason, len(p.pool), len(p.draining), p.refreshCount%p.EvictEvery, p.EvictEvery)
	for _, ps := range p.pool {
		log.Printf("  * %-18s %-25s  loss=%.1f%%  conns=%d", ps.IP, ps.SNI, ps.CombinedLossRate()*100, ps.ActiveConnections)
	}
	for _, ps := range p.draining {
		fc := ""
		if ps.IsForceClosed() {
			fc = " FORCE-CLOSE"
		}
		log.Printf("  ~ %-18s  draining %.0fs/%.0fs  conns=%d%s", ps.IP, ps.DrainAge(), p.DrainTimeout, ps.ActiveConnections, fc)
	}
}

// ConnectionManager wires CombinationExplorer and ActivePool together.
type ConnectionManager struct {
	Interval time.Duration

	ClientSNI     string
	clientSNILock sync.Mutex

	Explorer *CombinationExplorer
	Pool     *ActivePool

	UseClientSNIProbes bool
}

func NewConnectionManager(combinations []PairKey, port int, healthCheckInterval, healthCheckTimeout time.Duration, probeCount, activeSlots int, lossThreshold, deadThreshold, drainTimeout float64, maxDraining, evictEvery, evictCount int, recycleEnabled bool, recycleEvery, recycleBatch int, recycleMinCooldown, recycleMaxQuarantine float64, quarantineScope string, sniEvictEvery, sniEvictCount int, sniRecycleEnabled bool, sniRecycleEvery, sniRecycleBatch int, sniRecycleMinCooldown, sniRecycleMaxQuarantine float64, sniQuarantineScope string, useClientSNIProbes bool) *ConnectionManager {
	m := &ConnectionManager{
		Interval:           healthCheckInterval,
		UseClientSNIProbes: useClientSNIProbes,
	}
	var sniProvider func() (string, bool)
	if useClientSNIProbes {
		sniProvider = func() (string, bool) {
			sni := m.getClientSNI()
			if sni == "" {
				return "", false
			}
			return sni, true
		}
	}
	m.Explorer = NewCombinationExplorer(combinations, port, healthCheckTimeout, probeCount, lossThreshold, deadThreshold, sniProvider)
	m.Pool = NewActivePool(m.Explorer, activeSlots, lossThreshold, drainTimeout, maxDraining, evictEvery, evictCount, recycleEnabled, recycleEvery, recycleBatch, recycleMinCooldown, recycleMaxQuarantine, quarantineScope, sniEvictEvery, sniEvictCount, sniRecycleEnabled, sniRecycleEvery, sniRecycleBatch, sniRecycleMinCooldown, sniRecycleMaxQuarantine, sniQuarantineScope)
	return m
}

// RunHealthLoop is the blocking health loop.
func (m *ConnectionManager) RunHealthLoop() {
	m.Explorer.InitialExplore()
	m.Pool.Initialize()
	m.Explorer.PrintSummary()
	for {
		jitter := randFloat(-5, 5)
		sleepFor := math.Max(10, m.Interval.Seconds()+jitter)
		time.Sleep(time.Duration(sleepFor) * time.Second)
		m.Explorer.PeriodicExplore()
		m.Pool.Refresh()
		m.Explorer.PrintSummary()
	}
}

// StartHealthLoop runs the health loop in a goroutine.
func (m *ConnectionManager) StartHealthLoop() {
	go m.RunHealthLoop()
	log.Printf("Connection manager health loop started.")
}

func (m *ConnectionManager) PickPair() *PairStats { return m.Pool.Pick() }

func (m *ConnectionManager) ReportFailure(ps *PairStats) { m.Pool.ReportFailure(ps) }

func (m *ConnectionManager) NoteClientSNI(sni string) {
	if sni == "" || sni == "unknown" {
		return
	}
	m.clientSNILock.Lock()
	m.ClientSNI = sni
	m.clientSNILock.Unlock()
}

func (m *ConnectionManager) getClientSNI() string {
	m.clientSNILock.Lock()
	defer m.clientSNILock.Unlock()
	return m.ClientSNI
}

// BuildConnectionManager builds a manager from config, or returns nil (pool
// disabled when only a single IP+SNI is configured).
func BuildConnectionManager(cfg *config.Config, sniAxis bool) *ConnectionManager {
	ips := cfg.GetStringList("CONNECT_IPS")
	snis := cfg.GetStringList("FAKE_SNIS")
	if len(ips) == 0 && cfg.Get("CONNECT_IP", nil) != nil {
		ips = []string{cfg.GetString("CONNECT_IP", "")}
	}
	if len(snis) == 0 && cfg.Get("FAKE_SNI", nil) != nil {
		snis = []string{cfg.GetString("FAKE_SNI", "")}
	}
	if len(ips) == 0 || len(snis) == 0 {
		log.Printf("No IPs or SNIs found in config — pool disabled.")
		return nil
	}
	if !sniAxis {
		snis = snis[:1]
		cfg.Set("SNI_EVICT_EVERY", 0)
		cfg.Set("SNI_EVICT_COUNT", 0)
		cfg.Set("SNI_RECYCLE_ENABLED", false)
	}
	if len(ips) == 1 && len(snis) == 1 {
		log.Printf("Single IP+SNI detected — pool disabled (using direct mode).")
		return nil
	}
	var combinations []PairKey
	for _, ip := range ips {
		for _, sni := range snis {
			combinations = append(combinations, PairKey{IP: ip, SNI: sni})
		}
	}
	log.Printf("Building connection pool: %d IP(s) x %d SNI(s) = %d pairs", len(ips), len(snis), len(combinations))

	quarantineScope := validateScope(cfg.GetString("QUARANTINE_SCOPE", "both"), "QUARANTINE_SCOPE")
	sniQuarantineScope := validateScope(cfg.GetString("SNI_QUARANTINE_SCOPE", "both"), "SNI_QUARANTINE_SCOPE")

	return NewConnectionManager(
		combinations,
		cfg.GetInt("CONNECT_PORT", 443),
		time.Duration(cfg.GetFloat("HEALTH_CHECK_INTERVAL", 30))*time.Second,
		time.Duration(cfg.GetFloat("HEALTH_CHECK_TIMEOUT", 3))*time.Second,
		cfg.GetInt("PROBE_COUNT", 5),
		cfg.GetInt("ACTIVE_SLOTS", 3),
		cfg.GetFloat("LOSS_THRESHOLD", 0.20),
		cfg.GetFloat("DEAD_THRESHOLD", 0.80),
		cfg.GetFloat("DRAIN_TIMEOUT", 30.0),
		cfg.GetInt("MAX_DRAINING", 5),
		cfg.GetInt("EVICT_EVERY", 3),
		cfg.GetInt("EVICT_COUNT", 2),
		cfg.GetBool("RECYCLE_ENABLED", true),
		cfg.GetInt("RECYCLE_EVERY", 6),
		cfg.GetInt("RECYCLE_BATCH", 2),
		cfg.GetFloat("RECYCLE_MIN_COOLDOWN", 180.0),
		cfg.GetFloat("RECYCLE_MAX_QUARANTINE", 100),
		quarantineScope,
		cfg.GetInt("SNI_EVICT_EVERY", 3),
		cfg.GetInt("SNI_EVICT_COUNT", 1),
		cfg.GetBool("SNI_RECYCLE_ENABLED", true),
		cfg.GetInt("SNI_RECYCLE_EVERY", 6),
		cfg.GetInt("SNI_RECYCLE_BATCH", 2),
		cfg.GetFloat("SNI_RECYCLE_MIN_COOLDOWN", 180.0),
		cfg.GetFloat("SNI_RECYCLE_MAX_QUARANTINE", 100),
		sniQuarantineScope,
		!sniAxis,
	)
}

func validateScope(value, key string) string {
	if value != "static" && value != "dynamic" && value != "both" {
		log.Printf("Invalid %s %q — falling back to 'both'.", key, value)
		return "both"
	}
	return value
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func sortByScore(pairs []*PairStats) {
	for i := 1; i < len(pairs); i++ {
		for j := i; j > 0 && pairs[j].Score() < pairs[j-1].Score(); j-- {
			pairs[j], pairs[j-1] = pairs[j-1], pairs[j]
		}
	}
}

func sortIPAgeKeys(keys []struct {
	ip  string
	age time.Time
}) {
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j].age.Before(keys[j-1].age); j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
}

func sortAgeKeysSNI(keys []struct {
	sni string
	age time.Time
}) {
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j].age.Before(keys[j-1].age); j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
}

func avgF64(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	var s float64
	for _, v := range values {
		s += v
	}
	return s / float64(len(values))
}

func randInt(min, max int) int {
	if max <= min {
		return min
	}
	return min + rand.Intn(max-min+1)
}

func randFloat(min, max float64) float64 {
	return min + rand.Float64()*(max-min)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func weightedChoices(pairs []*PairStats, n int) []*PairStats {
	if len(pairs) == 0 {
		return nil
	}
	var weights []float64
	for _, ps := range pairs {
		weights = append(weights, 1.0/(ps.CombinedLossRate()+0.01))
	}
	total := 0.0
	for _, w := range weights {
		total += w
	}
	if total <= 0 {
		total = 1
	}
	var chosen []*PairStats
	tc := append([]*PairStats{}, pairs...)
	tw := append([]float64{}, weights...)
	for k := 0; k < minInt(n, len(tc)); k++ {
		r := rand.Float64() * total
		idx := 0
		cum := 0.0
		for i, w := range tw {
			cum += w
			if r < cum {
				idx = i
				break
			}
		}
		chosen = append(chosen, tc[idx])
		total -= tw[idx]
		tc = append(tc[:idx], tc[idx+1:]...)
		tw = append(tw[:idx], tw[idx+1:]...)
	}
	return chosen
}
