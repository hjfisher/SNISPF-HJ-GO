package masque

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"
)

func TestLiveProbe(t *testing.T) {
	if os.Getenv("SNISPF_LIVE_PROBE") != "1" {
		t.Skip("Skipping live probe (set SNISPF_LIVE_PROBE=1 to run)")
	}

	ip := os.Getenv("SNISPF_PROBE_IP")
	if ip == "" {
		t.Skip("SNISPF_PROBE_IP not set; skipping live probe")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	res := Probe(ctx, ProbeOptions{
		IP:      ip,
		Timeout: 10 * time.Second,
	})

	b, _ := json.MarshalIndent(res, "", "  ")
	t.Logf("Live Probe Result:\n%s", string(b))
}
