package config

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadConfigBytesBOMAndComments(t *testing.T) {
	dir := t.TempDir()

	// 1. UTF-8 with BOM
	p1 := filepath.Join(dir, "utf8_bom.json")
	content1 := append([]byte{0xEF, 0xBB, 0xBF}, []byte("{\n  \"LISTEN_PORT\": 40443,\n  \"URL\": \"https://example.com\" // comment\n}")...)
	if err := os.WriteFile(p1, content1, 0644); err != nil {
		t.Fatal(err)
	}
	data, note, err := ReadConfigBytes(p1)
	if err != nil {
		t.Fatalf("utf8_bom error: %v", err)
	}
	if note == "" {
		t.Fatalf("expected info note for BOM")
	}
	cfg, err := DecodeConfig(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cfg["LISTEN_PORT"] != float64(40443) && cfg["LISTEN_PORT"] != 40443 {
		t.Fatalf("expected LISTEN_PORT 40443, got %v", cfg["LISTEN_PORT"])
	}
	if cfg["URL"] != "https://example.com" {
		t.Fatalf("expected URL https://example.com, got %v", cfg["URL"])
	}
}

func TestTrailingCommasAndCommentsInString(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "trailing.json")
	jsonStr := []byte(`{
		"LISTEN_PORT": 8080,
		"DESC": "test \"quoted\" // not a comment",
		"LIST": [1, 2, 3,],
	}`)
	if err := os.WriteFile(p, jsonStr, 0644); err != nil {
		t.Fatal(err)
	}
	data, _, err := ReadConfigBytes(p)
	if err != nil {
		t.Fatalf("read error: %v", err)
	}
	cfg, err := DecodeConfig(data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if cfg["LISTEN_PORT"] != float64(8080) && cfg["LISTEN_PORT"] != 8080 {
		t.Fatalf("expected 8080")
	}
}

func TestValidationErrorsAndCheckConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "invalid.json")
	// Multiple validation errors: invalid port (>65535), invalid bypass method
	jsonStr := []byte(`{
		"LISTEN_PORT": 99999,
		"BYPASS_METHOD": "invalid_method"
	}`)
	if err := os.WriteFile(p, jsonStr, 0644); err != nil {
		t.Fatal(err)
	}
	_, err := CheckConfig(p)
	if err == nil {
		t.Fatalf("expected validation errors")
	}
}

func TestWatchConfigReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "reload.json")
	if err := os.WriteFile(p, []byte(`{"FRAGMENT_DELAY": 0.1}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(p)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reloaded := make(chan bool, 1)
	go WatchConfig(ctx, p, cfg, func(newCfg *Config, restart []string) {
		reloaded <- true
	})

	// Wait briefly then update file with reloadable change
	time.Sleep(100 * time.Millisecond)
	if err := os.WriteFile(p, []byte(`{"FRAGMENT_DELAY": 0.5}`), 0644); err != nil {
		t.Fatal(err)
	}

	select {
	case <-reloaded:
		if cfg.GetFloat("FRAGMENT_DELAY", 0) != 0.5 {
			t.Fatalf("expected FRAGMENT_DELAY 0.5, got %v", cfg.GetFloat("FRAGMENT_DELAY", 0))
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timeout waiting for config reload")
	}
}
