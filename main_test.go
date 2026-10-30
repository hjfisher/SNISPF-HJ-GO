package main

import (
	"strings"
	"testing"
)

func TestBanner(t *testing.T) {
	expectedLines := []string{
		"███████╗███╗   ██╗██╗███████╗██████╗ ███████╗    ██╗  ██╗     ██╗       ██████╗  ██████╗ ",
		"██╔════╝████╗  ██║██║██╔════╝██╔══██╗██╔════╝    ██║  ██║     ██║      ██╔════╝ ██╔═══██╗",
		"███████╗██╔██╗ ██║██║███████╗██████╔╝█████╗█████╗███████║     ██║█████╗██║  ███╗██║   ██║",
		"╚════██║██║╚██╗██║██║╚════██║██╔═══╝ ██╔══╝╚════╝██╔══██║██   ██║╚════╝██║   ██║██║   ██║",
		"███████║██║ ╚████║██║███████║██║     ██║         ██║  ██║╚█████╔╝      ╚██████╔╝╚██████╔╝",
		"╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝     ╚═╝         ╚═╝  ╚═╝ ╚════╝        ╚═════╝  ╚═════╝",
	}

	lines := strings.Split(banner, "\n")
	for i, exp := range expectedLines {
		idx := i + 1
		if idx >= len(lines) {
			t.Fatalf("banner missing line %d", i+1)
		}
		if lines[idx] != exp {
			t.Errorf("Line %d mismatch:\ngot:  %q\nwant: %q", i+1, lines[idx], exp)
		}
	}
}
