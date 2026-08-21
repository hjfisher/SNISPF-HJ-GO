//go:build !linux

package forward

import "syscall"

// NewRawInjector returns nil on platforms without AF_PACKET.
func NewRawInjector(localIP, remoteIP string, remotePort int) RawInjector {
	return nil
}

// rawDialControlImpl is a no-op off-Linux.
func rawDialControlImpl(inj RawInjector, fakeHello []byte) func(network, address string, c syscall.RawConn) error {
	return nil
}

// isRawAvailable always reports false without AF_PACKET.
func isRawAvailable() bool {
	return false
}

// IsRawAvailable reports whether raw packet injection is supported.
func IsRawAvailable() bool {
	return isRawAvailable()
}

// CleanupPort is a no-op off-Linux.
func CleanupPort(localPort int) {}

// Start is a no-op off-Linux.
func Start() bool { return false }

// Stop is a no-op off-Linux.
func Stop() {}
