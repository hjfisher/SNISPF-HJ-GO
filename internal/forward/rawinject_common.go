package forward

import (
	"encoding/binary"
	"syscall"
)

// DialControl returns a net.Dialer.Control func that registers the local
// socket port with the raw injector (before the SYN is sent) so the
// out-of-window fake-SNI hello is injected during the handshake. It is safe
// to call on any platform: it returns nil where raw injection is unsupported.
// The concrete injector is detected internally, so RawInjector may be nil.
func DialControl(inj RawInjector, fakeHello []byte) func(network, address string, c syscall.RawConn) error {
	if inj == nil {
		return nil
	}
	return rawDialControl(inj, fakeHello)
}

// htons converts a 16-bit value from host to network byte order.
func htons(v uint16) uint16 { return v<<8 | v>>8 }

// sum16 sums every 16-bit word (big-endian) of data, including a trailing
// partial byte shifted into the high-order half, for use in checksums.
func sum16(data []byte) uint32 {
	var s uint32
	for i := 0; i+1 < len(data); i += 2 {
		s += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		s += uint32(data[len(data)-1]) << 8
	}
	for s>>16 != 0 {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return s
}

// checksumFold folds a running 32-bit sum into the final 16-bit checksum.
func checksumFold(s uint32) uint16 {
	for s>>16 != 0 {
		s = (s & 0xFFFF) + (s >> 16)
	}
	return ^uint16(s)
}

// ipChecksum computes the IPv4 header checksum.
func ipChecksum(iph []byte) uint16 {
	return checksumFold(sum16(iph))
}

// tcpChecksum computes the TCP checksum including the IPv4 pseudo-header.
func tcpChecksum(iph, tcpWithPayload []byte) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], iph[12:16])
	copy(pseudo[4:8], iph[16:20])
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcpWithPayload)))
	return checksumFold(sum16(pseudo) + sum16(tcpWithPayload))
}
