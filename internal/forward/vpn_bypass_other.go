//go:build !linux && !android

// vpn_bypass_other.go - No-op VPN bypass for platforms without SO_BINDTODEVICE
// handling (Windows, macOS, etc.). The raw bypass only applies to the root
// Linux/Android backend, so on other platforms the existing control passes
// through unchanged.

package forward

import (
	"net"
	"syscall"
)

// VPNBypassControl is a no-op on non-Linux/Android platforms: it returns the
// inner control unchanged so outbound dials behave exactly as before.
func VPNBypassControl(localIP net.IP, inner func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	return inner
}
