//go:build windows

package main

import (
	"log"
	"os"

	"golang.org/x/sys/windows"
)

func init() {
	if err := windows.SetConsoleOutputCP(65001); err != nil {
		if os.Getenv("DEBUG") != "" {
			log.Printf("DEBUG: SetConsoleOutputCP(65001) failed: %v", err)
		}
	}
}
