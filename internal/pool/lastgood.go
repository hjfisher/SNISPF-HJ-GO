package pool

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"snispf-hj-go/internal/config"
)

const lastGoodVersionV2 = 2

type PairStatsSnapshot struct {
	EMAProbeLoss float64 `json:"ema_probe_loss"`
	EMARealLoss  float64 `json:"ema_real_loss"`
	LatencySumMs float64 `json:"latency_sum_ms"`
	LatencyCount int     `json:"latency_count"`
	Probed       bool    `json:"probed"`
	Alive        bool    `json:"alive"`
}

type IPState struct {
	IP            string             `json:"ip"`
	Origin        string             `json:"origin"`
	State         string             `json:"state"` // "live", "quarantined", "dead", "active"
	LastOK        int64              `json:"last_ok"`
	QuarantinedAt int64              `json:"quarantined_at,omitempty"`
	Stats         *PairStatsSnapshot `json:"stats,omitempty"`
}

type SNIState struct {
	SNI           string             `json:"sni"`
	Origin        string             `json:"origin"`
	State         string             `json:"state"`
	LastOK        int64              `json:"last_ok"`
	QuarantinedAt int64              `json:"quarantined_at,omitempty"`
	Stats         *PairStatsSnapshot `json:"stats,omitempty"`
}

type PairState struct {
	IP     string             `json:"ip"`
	SNI    string             `json:"sni"`
	State  string             `json:"state"` // "active", "live", "dead"
	LastOK int64              `json:"last_ok"`
	Stats  *PairStatsSnapshot `json:"stats"`
}

type SnapshotDoc struct {
	Version int         `json:"version"`
	SavedAt int64       `json:"saved_at"`
	IPs     []IPState   `json:"ips"`
	SNIs    []SNIState  `json:"snis"`
	Pairs   []PairState `json:"pairs"`
}

// LoadSnapshotV2 reads the v2 snapshot at path using the robust config reader (handling BOM, UTF-16, CRLF).
// A missing file returns nil, nil. A corrupt file or version mismatch logs a warning, moves aside to .bak, and returns nil, nil.
func LoadSnapshotV2(path string, ttl time.Duration, now time.Time) (*SnapshotDoc, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}

	data, _, err := config.ReadConfigBytes(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		moveAsideBak(path)
		log.Printf("Last-good state: unreadable %s, moved aside to .bak: %v", path, err)
		return nil, nil
	}

	var doc SnapshotDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		moveAsideBak(path)
		log.Printf("Last-good state: parse error in %s, moved aside to .bak: %v", path, err)
		return nil, nil
	}

	if doc.Version != lastGoodVersionV2 {
		moveAsideBak(path)
		log.Printf("Last-good state: unsupported version %d in %s (expected %d), moved aside to .bak", doc.Version, path, lastGoodVersionV2)
		return nil, nil
	}

	// Filter by TTL if needed
	if ttl > 0 {
		filteredIPs := make([]IPState, 0, len(doc.IPs))
		for _, ip := range doc.IPs {
			lastOK := ip.LastOK
			if lastOK <= 0 {
				lastOK = doc.SavedAt
			}
			if now.Sub(time.Unix(lastOK, 0)) <= ttl {
				filteredIPs = append(filteredIPs, ip)
			}
		}
		doc.IPs = filteredIPs

		filteredSNIs := make([]SNIState, 0, len(doc.SNIs))
		for _, sni := range doc.SNIs {
			lastOK := sni.LastOK
			if lastOK <= 0 {
				lastOK = doc.SavedAt
			}
			if now.Sub(time.Unix(lastOK, 0)) <= ttl {
				filteredSNIs = append(filteredSNIs, sni)
			}
		}
		doc.SNIs = filteredSNIs

		filteredPairs := make([]PairState, 0, len(doc.Pairs))
		for _, p := range doc.Pairs {
			lastOK := p.LastOK
			if lastOK <= 0 {
				lastOK = doc.SavedAt
			}
			if now.Sub(time.Unix(lastOK, 0)) <= ttl {
				filteredPairs = append(filteredPairs, p)
			}
		}
		doc.Pairs = filteredPairs
	}

	return &doc, nil
}

func moveAsideBak(path string) {
	bakPath := path + ".bak"
	_ = os.Remove(bakPath)
	_ = os.Rename(path, bakPath)
}

// SaveSnapshotV2 atomically writes the snapshot doc to path.
func SaveSnapshotV2(path string, doc SnapshotDoc) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("last-good encode: %w", err)
	}
	data = append(data, '\n')
	return atomicWriteFile(path, data)
}

func atomicWriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("last-good mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".lastgood-*.tmp")
	if err != nil {
		return fmt.Errorf("last-good temp: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return fmt.Errorf("last-good write: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("last-good sync: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("last-good close: %w", err)
	}

	if err := atomicRename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("last-good rename: %w", err)
	}
	return nil
}

// ComputeSnapshotHash computes SHA-256 hash of snapshot JSON excluding saved_at.
func ComputeSnapshotHash(doc SnapshotDoc) string {
	doc.SavedAt = 0
	data, _ := json.Marshal(doc)
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// Snapshot generates a v2 snapshot of the explorer state.
func (e *CombinationExplorer) Snapshot() SnapshotDoc {
	e.mu.Lock()
	defer e.mu.Unlock()

	var ips []IPState
	for _, ip := range e.AllIPs {
		origin := e.IPOriginLedger[ip]
		if origin == "" {
			origin = "static"
		}
		state := "live"
		var quarantinedAt int64
		if qi, ok := e.IPQuarantine[ip]; ok {
			state = "quarantined"
			quarantinedAt = qi.EvictedAt.Unix()
		}
		ips = append(ips, IPState{
			IP:            ip,
			Origin:        origin,
			State:         state,
			QuarantinedAt: quarantinedAt,
		})
	}

	var snis []SNIState
	for _, sni := range e.AllSNIs {
		origin := e.SNIOriginLedger[sni]
		if origin == "" {
			origin = "static"
		}
		state := "live"
		var quarantinedAt int64
		if qi, ok := e.SNIQuarantine[sni]; ok {
			state = "quarantined"
			quarantinedAt = qi.EvictedAt.Unix()
		}
		snis = append(snis, SNIState{
			SNI:           sni,
			Origin:        origin,
			State:         state,
			QuarantinedAt: quarantinedAt,
		})
	}

	var pairs []PairState
	for k, ps := range e.Stats {
		ps.Lock()
		state := "live"
		if !ps.Alive {
			state = "dead"
		} else if ps.InActivePool {
			state = "active"
		}
		statsSnap := &PairStatsSnapshot{
			EMAProbeLoss: ps.emaProbeLoss,
			EMARealLoss:  ps.emaRealLoss,
			LatencySumMs: ps.latencySumMs,
			LatencyCount: ps.latencyCount,
			Probed:       ps.Probed,
			Alive:        ps.Alive,
		}
		ps.Unlock()

		pairs = append(pairs, PairState{
			IP:    k.IP,
			SNI:   k.SNI,
			State: state,
			Stats: statsSnap,
		})
	}

	return SnapshotDoc{
		Version: lastGoodVersionV2,
		SavedAt: time.Now().Unix(),
		IPs:     ips,
		SNIs:    snis,
		Pairs:   pairs,
	}
}

// Restore populates the explorer state from a v2 snapshot.
func (e *CombinationExplorer) Restore(doc *SnapshotDoc, now time.Time) int {
	if doc == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()

	restoredPairs := 0
	seenIPs := map[string]bool{}
	seenSNIs := map[string]bool{}

	for _, ipState := range doc.IPs {
		e.AllIPs = append(e.AllIPs, ipState.IP)
		e.IPOriginLedger[ipState.IP] = ipState.Origin
		seenIPs[ipState.IP] = true
		if ipState.State == "quarantined" {
			evictedAt := time.Unix(ipState.QuarantinedAt, 0)
			if evictedAt.IsZero() {
				evictedAt = now
			}
			e.IPQuarantine[ipState.IP] = &QuarantineInfo{
				EvictedAt: evictedAt,
				Origin:    ipState.Origin,
			}
		}
	}

	for _, sniState := range doc.SNIs {
		e.AllSNIs = append(e.AllSNIs, sniState.SNI)
		e.SNIOriginLedger[sniState.SNI] = sniState.Origin
		seenSNIs[sniState.SNI] = true
		if sniState.State == "quarantined" {
			evictedAt := time.Unix(sniState.QuarantinedAt, 0)
			if evictedAt.IsZero() {
				evictedAt = now
			}
			e.SNIQuarantine[sniState.SNI] = &QuarantineInfo{
				EvictedAt: evictedAt,
				Origin:    sniState.Origin,
			}
		}
	}

	for _, pState := range doc.Pairs {
		key := PairKey{IP: pState.IP, SNI: pState.SNI}
		ps := NewPairStats(pState.IP, pState.SNI, e.LookupIPOrigin(pState.IP), e.LookupSNIOrigin(pState.SNI))
		if pState.Stats != nil {
			ps.emaProbeLoss = pState.Stats.EMAProbeLoss
			ps.emaRealLoss = pState.Stats.EMARealLoss
			ps.latencySumMs = pState.Stats.LatencySumMs
			ps.latencyCount = pState.Stats.LatencyCount
			ps.Probed = pState.Stats.Probed
			ps.Alive = pState.Stats.Alive
		}
		// Mark unverified until dataCheck passes
		ps.InActivePool = false
		e.Stats[key] = ps
		restoredPairs++

		if !seenIPs[pState.IP] {
			seenIPs[pState.IP] = true
			e.AllIPs = append(e.AllIPs, pState.IP)
		}
		if !seenSNIs[pState.SNI] {
			seenSNIs[pState.SNI] = true
			e.AllSNIs = append(e.AllSNIs, pState.SNI)
		}
	}

	sortStrings(e.AllIPs)
	sortStrings(e.AllSNIs)

	var front []PairKey
	for _, pState := range doc.Pairs {
		front = append(front, PairKey{IP: pState.IP, SNI: pState.SNI})
	}
	if len(front) > 0 {
		seen := map[PairKey]bool{}
		for _, k := range front {
			seen[k] = true
		}
		rest := make([]PairKey, 0, len(e.unexplored))
		for _, k := range e.unexplored {
			if !seen[k] {
				rest = append(rest, k)
			}
		}
		e.unexplored = append(front, rest...)
	}

	return restoredPairs
}
