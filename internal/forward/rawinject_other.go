//go:build !linux && !windows

package forward

import "syscall"

// NewRawInjector returns nil on platforms without AF_PACKET or WinDivert.
func NewRawInjector(localIP, remoteIP string, remotePort int) RawInjector {
	return nil
}

// rawDialControlImpl is a no-op off-Linux/off-Windows.
func rawDialControlImpl(inj RawInjector, fakeHello []byte) func(network, address string, c syscall.RawConn) error {
	return nil
}

// isRawAvailable always reports false without AF_PACKET/WinDivert.
func isRawAvailable() bool {
	return false
}

// RawStatus returns a human-readable diagnostic for raw injection.
func RawStatus() string {
	return "unavailable: no raw-packet backend for this platform (use Linux or Windows)"
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
