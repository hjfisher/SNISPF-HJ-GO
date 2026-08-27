package utils

import (
	"log"
	"net"
	"sync"
	"time"
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

// NetworkMonitor watches for changes in the default interface IPv4 address
// and invokes a callback when a change is detected.
type NetworkMonitor struct {
	dest         string
	interval     time.Duration
	callback     func(newIP string)
	mu           sync.Mutex
	lastIP       string
	stop         chan struct{}
	wg           sync.WaitGroup
}

// NewNetworkMonitor creates a new network monitor.
func NewNetworkMonitor(dest string, interval time.Duration, callback func(newIP string)) *NetworkMonitor {
	if dest == "" {
		dest = "8.8.8.8"
	}
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &NetworkMonitor{
		dest:     dest,
		interval: interval,
		callback: callback,
		lastIP:   GetDefaultInterfaceIPv4(dest),
		stop:     make(chan struct{}),
	}
}

// Start begins monitoring in a background goroutine.
func (m *NetworkMonitor) Start() {
	m.wg.Add(1)
	go m.run()
}

// Stop stops the monitor.
func (m *NetworkMonitor) Stop() {
	close(m.stop)
	m.wg.Wait()
}

// run is the monitoring loop.
func (m *NetworkMonitor) run() {
	defer m.wg.Done()
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			m.check()
		}
	}
}

func (m *NetworkMonitor) check() {
	newIP := GetDefaultInterfaceIPv4(m.dest)
	m.mu.Lock()
	if newIP != "" && newIP != m.lastIP {
		oldIP := m.lastIP
		m.lastIP = newIP
		m.mu.Unlock()
		log.Printf("Network interface changed: %s -> %s", oldIP, newIP)
		if m.callback != nil {
			m.callback(newIP)
		}
		return
	}
	m.mu.Unlock()
}

// GetCurrentIP returns the last known interface IP.
func (m *NetworkMonitor) GetCurrentIP() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastIP
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
