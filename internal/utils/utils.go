package utils

import (
	"net"
)

// GetDefaultInterfaceIPv4 returns the IPv4 address of the default interface by
// dialing a UDP socket to a public address (never actually contacted).
func GetDefaultInterfaceIPv4(dest string) string {
	if dest == "" {
		dest = "8.8.8.8"
	}
	conn, err := net.Dial("udp4", net.JoinHostPort(dest, "53"))
	if err != nil {
		return ""
	}
	defer conn.Close()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	return addr.IP.String()
}

// ResolveHost resolves a hostname to an IP address string. On failure the
// input is returned unchanged. The first IPv4 address is preferred (matching
// socket.gethostbyname semantics).
func ResolveHost(host string) string {
	addrs, err := net.LookupHost(host)
	if err != nil || len(addrs) == 0 {
		return host
	}
	for _, a := range addrs {
		if p := net.ParseIP(a); p != nil && p.To4() != nil {
			return a
		}
	}
	return addrs[0]
}

// IsValidIP reports whether addr is a valid IPv4 or IPv6 address.
func IsValidIP(addr string) bool {
	return net.ParseIP(addr) != nil
}

// IsValidPort reports whether port is a valid TCP port number.
func IsValidPort(port int) bool {
	return port >= 1 && port <= 65535
}
