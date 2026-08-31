//go:build windows

// vpn_bypass_windows.go - Windows equivalent of the Linux/Android VPN bypass.
//
// Windows has no SO_BINDTODEVICE; the per-socket equivalent is IP_UNICAST_IF
// (IPPROTO_IP, 31) for IPv4 sockets and IPV6_UNICAST_IF (IPPROTO_IPV6, 31)
// for IPv6 sockets. Setting it forces all unicast traffic of that socket out
// of the given interface, so an upstream VPN TUN adapter (Wintun, TAP,
// WireGuard, Clash/Mihomo, ...) cannot capture and loop the backend's own
// outbound connections. The physical adapter is resolved from the local IP
// (or the first non-virtual IPv4 adapter) and virtual adapters are excluded
// by name.

package forward

import (
	"encoding/binary"
	"log"
	"net"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
)

// Socket options not exported by x/sys/windows (ws2ipdef.h / in6.h).
const (
	ipUnicastIf   = 31 // IP_UNICAST_IF   (level IPPROTO_IP)   - ifindex in NETWORK byte order
	ipv6UnicastIf = 31 // IPV6_UNICAST_IF (level IPPROTO_IPV6) - ifindex in HOST byte order
)

// isVirtualIface reports whether an adapter is a VPN/virtual tunnel or
// otherwise not the physical link, so we never bind to it.
func isVirtualIface(name string) bool {
	n := strings.ToLower(name)
	keywords := []string{
		"wintun", "tun", "tap", "wireguard", "openvpn", "clash", "mihomo",
		"meta", "sing-box", "tailscale", "zerotier", "nordlynx", "nordvirt",
		"proton", "hamachi", "teamviewer", "vmware", "virtualbox", "virtual",
		"hyper-v", "vethernet", "vbox", "loopback", "bluetooth", "wan miniport",
		"ras", "ppp", "6to4", "isatap", "teredo", "iphttps", "wi-fi direct",
		"hosted network", "km-test", "pseudo",
	}
	for _, k := range keywords {
		if strings.Contains(n, k) {
			return true
		}
	}
	return false
}

// PhysicalInterfaceIPv4 returns the IPv4 of the first up, non-virtual
// adapter (the physical link), or false if none can be determined.
func PhysicalInterfaceIPv4() (net.IP, bool) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, false
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
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
			if ip4 := ipn.IP.To4(); ip4 != nil {
				return ip4, true
			}
		}
	}
	return nil, false
}

// findPhysicalIface returns the adapter whose IPv4 equals localIP, skipping
// virtual adapters. Falls back to the first physical adapter when localIP is
// nil or unmatched (e.g. it resolved through a VPN tunnel).
func findPhysicalIface(localIP net.IP) (*net.Interface, bool) {
	var matched *net.Interface
	if localIP != nil {
		ifaces, err := net.Interfaces()
		if err == nil {
			for i := range ifaces {
				ifc := &ifaces[i]
				if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
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
					if ip4 := ipn.IP.To4(); ip4 != nil && ip4.Equal(localIP) {
						matched = ifc
						break
					}
				}
				if matched != nil {
					break
				}
			}
		}
	}
	if matched != nil {
		return matched, true
	}
	// Fallback: first non-virtual adapter with an IPv4 address.
	if ip, ok := PhysicalInterfaceIPv4(); ok {
		ifaces, err := net.Interfaces()
		if err == nil {
			for i := range ifaces {
				ifc := &ifaces[i]
				if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 || isVirtualIface(ifc.Name) {
					continue
				}
				addrs, _ := ifc.Addrs()
				for _, a := range addrs {
					ipn, ok2 := a.(*net.IPNet)
					if !ok2 {
						continue
					}
					if ip4 := ipn.IP.To4(); ip4 != nil && ip4.Equal(ip) {
						return ifc, true
					}
				}
			}
		}
	}
	return nil, false
}

// htonl32 converts an interface index to network byte order for IP_UNICAST_IF.
func htonl32(i uint32) uint32 {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, i)
	return binary.BigEndian.Uint32(b)
}

var vpnBypassLogged sync.Once

// VPNBypassControl returns a net.Dialer.Control that pins the socket's egress
// to the physical adapter via IP_UNICAST_IF / IPV6_UNICAST_IF so an upstream
// VPN TUN adapter cannot capture the backend's own traffic. inner (e.g. raw
// injector registration) runs afterwards. Returns inner when no physical
// adapter can be determined, so normal operation is never broken.
func VPNBypassControl(localIP net.IP, inner func(network, address string, c syscall.RawConn) error) func(network, address string, c syscall.RawConn) error {
	iface, ok := findPhysicalIface(localIP)
	if !ok {
		return inner
	}
	vpnBypassLogged.Do(func() {
		log.Printf("VPN bypass: pinning outbound sockets to physical adapter %q (index %d), isolating backend from upstream VPNs", iface.Name, iface.Index)
	})
	return func(network, address string, c syscall.RawConn) error {
		err := c.Control(func(fd uintptr) {
			h := windows.Handle(fd)
			if network == "tcp6" || network == "udp6" {
				// IPV6_UNICAST_IF takes the index in host byte order.
				_ = windows.SetsockoptInt(h, windows.IPPROTO_IPV6, ipv6UnicastIf, iface.Index)
			} else {
				// IP_UNICAST_IF takes the index in network byte order.
				_ = windows.SetsockoptInt(h, windows.IPPROTO_IP, ipUnicastIf, int(htonl32(uint32(iface.Index))))
			}
		})
		if err != nil {
			return err
		}
		if inner != nil {
			return inner(network, address, c)
		}
		return nil
	}
}
