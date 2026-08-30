//go:build linux || android

// vpn_bypass.go - Route the backend's outbound sockets through the physical
// network interface, bypassing any upstream VPN (e.g. v2rayNG) tun device.
//
// When the backend runs as root (su), Android's per-UID network policy and
// VPN routing can capture the backend's own outbound traffic and loop it back
// through the VPN, breaking connectivity even in direct mode. As root we can
// bind each outbound socket to the real (non-virtual) interface and clear the
// socket mark so the kernel routes it directly to the wire instead of into a
// VPN tun0. Non-root builds simply no-op.

package forward

import (
	"log"
	"net"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// vpnInterfaceNames returns true for interfaces that are VPN/virtual tunnels
// or otherwise not the physical link, so we never bind to them.
func isVirtualIface(name string) bool {
	n := strings.ToLower(name)
	if n == "lo" {
		return true
	}
	for _, p := range []string{"tun", "tap", "ppp", "pppoe", "ipsec", "ip6tnl", "gre", "gretap", "vpn", "svpn", "tun0", "nl0", "teql", "dummy", "ifb", "wg", "utun", "tunl"} {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// physicalLinkIPv4 returns the (interface name) whose address equals the given
// IPv4, skipping virtual interfaces. It favours real Wi-Fi / cellular links.
func findPhysicalIfaceForIP(ip net.IP) (string, bool) {
	if ip == nil {
		return "", false
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		if isVirtualIface(ifc.Name) {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipn.IP.To4(); ip4 != nil && ip4.Equal(ip) {
				return ifc.Name, true
			}
		}
	}
	return "", false
}

// VPNBypassControl returns a net.Dialer.Control that binds the socket to the
// physical interface for the given local IP and clears its mark so it is not
// routed through an upstream VPN. inner (e.g. raw-injector registration) runs
// first. Returns inner (or nil) if no physical interface can be determined, so
// normal operation is never broken.
var vpnBypassLogged sync.Once

func VPNBypassControl(localIP net.IP, inner func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	iface, ok := findPhysicalIfaceForIP(localIP)
	if !ok {
		return inner
	}
	vpnBypassLogged.Do(func() {
		log.Printf("VPN bypass: binding outbound sockets to physical interface %q (isolating backend from upstream VPNs)", iface)
	})
	return func(network, address string, c syscall.RawConn) error {
		var outerErr error
		bindErr := c.Control(func(fd uintptr) {
			if err := unix.BindToDevice(int(fd), iface); err != nil {
				outerErr = err
				return
			}
			// Clear the socket mark so VPN fwmark routing rules are bypassed.
			_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, 0)
		})
		if bindErr != nil {
			return bindErr
		}
		if outerErr != nil {
			return outerErr
		}
		if inner != nil {
			return inner(network, address, c)
		}
		return nil
	}
}
