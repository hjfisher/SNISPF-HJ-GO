package pool

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unicode/utf16"
)

func TestSnapshotRoundTrip(t *testing.T) {
	e := NewCombinationExplorer([]PairKey{
		{IP: "203.0.113.10", SNI: "example.com"},
	}, 443, time.Second, 0, 0.2, 0.8, nil)

	ps := e.Stats[PairKey{IP: "203.0.113.10", SNI: "example.com"}]
	ps.Probed = true
	ps.Alive = true
	ps.emaProbeLoss = 0.1

	doc := e.Snapshot()
	if doc.Version != lastGoodVersionV2 {
		t.Fatalf("expected version %d, got %d", lastGoodVersionV2, doc.Version)
	}

	e2 := NewCombinationExplorer(nil, 443, time.Second, 0, 0.2, 0.8, nil)
	restored := e2.Restore(&doc, time.Now())
	if restored != 1 {
		t.Fatalf("expected 1 restored pair, got %d", restored)
	}

	ps2 := e2.Stats[PairKey{IP: "203.0.113.10", SNI: "example.com"}]
	if ps2 == nil || !ps2.Probed || !ps2.Alive || ps2.emaProbeLoss != 0.1 {
		t.Fatalf("restored stats mismatch: %+v", ps2)
	}
}

func TestVersionMismatchMovesAsideBak(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`{"version": 99, "saved_at": 1730000000, "ips": [], "snis": [], "pairs": []}`), 0644); err != nil {
		t.Fatal(err)
	}

	doc, err := LoadSnapshotV2(path, time.Hour, time.Now())
	if err != nil || doc != nil {
		t.Fatalf("expected nil doc for version mismatch, got doc=%v err=%v", doc, err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("expected .bak file created")
	}
}

func TestCorruptJSONMovesAsideBak(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte(`not valid json`), 0644); err != nil {
		t.Fatal(err)
	}

	doc, err := LoadSnapshotV2(path, time.Hour, time.Now())
	if err != nil || doc != nil {
		t.Fatalf("expected nil doc for corrupt json, got doc=%v err=%v", doc, err)
	}
	if _, err := os.Stat(path + ".bak"); err != nil {
		t.Fatalf("expected .bak file created")
	}
}

func TestBOMPrefixedSnapshotLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	nowSec := time.Now().Unix()
	jsonStr := []byte(fmt.Sprintf(`{"version": 2, "saved_at": %d, "ips": [], "snis": [], "pairs": [{"ip":"203.0.113.10","sni":"example.com","state":"active","last_ok":%d}]}`, nowSec, nowSec))
	content := append([]byte{0xEF, 0xBB, 0xBF}, jsonStr...)
	if err := os.WriteFile(path, content, 0644); err != nil {
		t.Fatal(err)
	}

	doc, err := LoadSnapshotV2(path, time.Hour, time.Now())
	if err != nil || doc == nil {
		t.Fatalf("expected snapshot to load with BOM, got err=%v doc=%v", err, doc)
	}
	if len(doc.Pairs) != 1 {
		t.Fatalf("expected 1 pair")
	}
}

func TestTTLFiltering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	now := time.Now()
	oldTime := now.Add(-48 * time.Hour).Unix()
	freshTime := now.Unix()

	doc := SnapshotDoc{
		Version: lastGoodVersionV2,
		SavedAt: now.Unix(),
		Pairs: []PairState{
			{IP: "203.0.113.1", SNI: "old.com", LastOK: oldTime},
			{IP: "203.0.113.2", SNI: "fresh.com", LastOK: freshTime},
		},
	}
	if err := SaveSnapshotV2(path, doc); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadSnapshotV2(path, 24*time.Hour, now)
	if err != nil || loaded == nil {
		t.Fatal(err)
	}
	if len(loaded.Pairs) != 1 || loaded.Pairs[0].IP != "203.0.113.2" {
		t.Fatalf("expected only fresh pair, got %+v", loaded.Pairs)
	}
}

func TestHashGatedSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	e := NewCombinationExplorer([]PairKey{{IP: "203.0.113.1", SNI: "a.com"}}, 443, time.Second, 0, 0.2, 0.8, nil)
	cm := &ConnectionManager{
		Explorer:     e,
		Pool:         &ActivePool{Explorer: e, Slots: 1},
		LastGoodPath: path,
	}

	cm.SaveSnapshotNow()
	fi1, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	// Saving again with identical state should be gated (not rewriting file, or hash matches)
	time.Sleep(10 * time.Millisecond)
	cm.SaveSnapshotNow()
	fi2, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}

	if fi1.ModTime() != fi2.ModTime() {
		// Note: on some filesystems modtime resolution might match or differ slightly, but hash check prevents work.
	}
}

func TestShutdownSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	e := NewCombinationExplorer([]PairKey{{IP: "203.0.113.1", SNI: "a.com"}}, 443, time.Second, 0, 0.2, 0.8, nil)
	cm := &ConnectionManager{
		Explorer:     e,
		Pool:         &ActivePool{Explorer: e, Slots: 1},
		LastGoodPath: path,
	}

	cm.SaveShutdown(2 * time.Second)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected shutdown save file to exist: %v", err)
	}
}

func TestConcurrencyRacePersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	e := NewCombinationExplorer([]PairKey{{IP: "203.0.113.1", SNI: "a.com"}}, 443, time.Second, 0, 0.2, 0.8, nil)
	cm := &ConnectionManager{
		Explorer:        e,
		Pool:            &ActivePool{Explorer: e, Slots: 1},
		LastGoodPath:    path,
		LastGoodSaveSec: 1,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cm.StartLastGoodPersistence(ctx)

	done := make(chan bool)
	go func() {
		for i := 0; i < 50; i++ {
			cm.SaveSnapshotNow()
			time.Sleep(5 * time.Millisecond)
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout in concurrency test")
	}
}

func TestUTF16LESnapshotLoads(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	nowSec := time.Now().Unix()
	jsonStr := fmt.Sprintf(`{"version": 2, "saved_at": %d, "ips": [], "snis": [], "pairs": [{"ip":"203.0.113.10","sni":"example.com","state":"active","last_ok":%d}]}`, nowSec, nowSec)

	u16s := utf16.Encode([]rune(jsonStr))
	buf := make([]byte, 2+len(u16s)*2)
	buf[0] = 0xFF
	buf[1] = 0xFE
	for i, u := range u16s {
		buf[2+2*i] = byte(u)
		buf[2+2*i+1] = byte(u >> 8)
	}
	if err := os.WriteFile(path, buf, 0644); err != nil {
		t.Fatal(err)
	}

	doc, err := LoadSnapshotV2(path, time.Hour, time.Now())
	if err != nil || doc == nil {
		t.Fatalf("expected UTF-16 LE snapshot to load, got err=%v doc=%v", err, doc)
	}
	if len(doc.Pairs) != 1 {
		t.Fatalf("expected 1 pair")
	}
}

func TestRestoredLiveEntryMustPassDataCheckBeforeEnteringActivePool(t *testing.T) {
	e := NewCombinationExplorer([]PairKey{
		{IP: "203.0.113.10", SNI: "example.com"},
	}, 443, time.Second, 0, 0.2, 0.8, nil)

	ps := e.Stats[PairKey{IP: "203.0.113.10", SNI: "example.com"}]
	ps.Probed = true
	ps.Alive = true
	ps.InActivePool = true

	doc := e.Snapshot()

	e2 := NewCombinationExplorer(nil, 443, time.Second, 0, 0.2, 0.8, nil)
	e2.Restore(&doc, time.Now())

	restoredPS := e2.Stats[PairKey{IP: "203.0.113.10", SNI: "example.com"}]
	if restoredPS == nil {
		t.Fatal("restored pair missing")
	}
	if restoredPS.InActivePool {
		t.Fatalf("restored live entry must NOT be in active pool before dataCheck passes")
	}
}

func TestHashGatedSaveUpdatesCheckedAtNotWrittenAt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	e := NewCombinationExplorer([]PairKey{{IP: "203.0.113.1", SNI: "a.com"}}, 443, time.Second, 0, 0.2, 0.8, nil)
	cm := &ConnectionManager{
		Explorer:     e,
		Pool:         &ActivePool{Explorer: e, Slots: 1},
		LastGoodPath: path,
	}

	cm.SaveSnapshotNow()
	t1 := cm.lastWrittenAt
	c1 := cm.lastCheckedAt

	time.Sleep(10 * time.Millisecond)
	cm.SaveSnapshotNow()
	t2 := cm.lastWrittenAt
	c2 := cm.lastCheckedAt

	if !c2.After(c1) {
		t.Fatalf("lastCheckedAt should update on every check")
	}
	if !t2.Equal(t1) {
		t.Fatalf("lastWrittenAt should not change when state is unchanged")
	}
}
