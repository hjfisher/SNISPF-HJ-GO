//go:build !linux && !android && !windows

// vpn_bypass_other.go - No-op VPN bypass for platforms without an outbound
// interface-selection socket option (macOS, BSD, etc.).

package forward

import (
	"net"
	"syscall"
)

// VPNBypassControl is a no-op on unsupported platforms: it returns the
// inner control unchanged so outbound dials behave exactly as before.
func VPNBypassControl(localIP net.IP, inner func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	return inner
}

// PhysicalInterfaceIPv4 is unsupported here.
func PhysicalInterfaceIPv4() (string, bool) {
	return "", false
}
