//go:build linux || android

package forward

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// rawInjector sniffs the outbound TCP handshake and injects the fake
// ClientHello with an out-of-window seq (the seq_id trick). Linux-only.
type rawInjector struct {
	localIP    [4]byte
	remoteIP   [4]byte
	remotePort int
	ifaceName  string
	ifaceIdx   int
	fd         int
	running    bool

	portsMu sync.Mutex
	ports   map[int]*portState
}

// NewRawInjector builds the Linux raw injector.
func NewRawInjector(localIP, remoteIP string, remotePort int) RawInjector {
	r := &rawInjector{
		remotePort: remotePort,
		ports:      make(map[int]*portState),
	}
	copy(r.localIP[:], net.ParseIP(localIP).To4())
	copy(r.remoteIP[:], net.ParseIP(remoteIP).To4())
	return r
}

func (r *rawInjector) Start() bool {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		log.Printf("Cannot open AF_PACKET socket: %v", err)
		log.Printf("Raw injection unavailable - need root/CAP_NET_RAW")
		return false
	}
	r.fd = fd

	name, idx := findInterface(net.IPv4(r.remoteIP[0], r.remoteIP[1], r.remoteIP[2], r.remoteIP[3]).String())
	if name == "" {
		log.Printf("Cannot determine outgoing interface for raw injection")
		_ = unix.Close(fd)
		r.fd = -1
		return false
	}
	r.ifaceName = name
	r.ifaceIdx = idx
	log.Printf("Using interface %s (index %d)", name, idx)

	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(ethPAll), Ifindex: idx}); err != nil {
		log.Printf("Cannot bind raw socket to %s: %v", name, err)
		_ = unix.Close(fd)
		r.fd = -1
		return false
	}

	r.running = true
	go r.sniffLoop()
	log.Printf("Raw packet injector started")
	return true
}

func (r *rawInjector) Stop() {
	r.running = false
	if r.fd >= 0 {
		_ = unix.Close(r.fd)
		r.fd = -1
	}
}

func (r *rawInjector) RegisterPort(localPort int, fakeHello []byte) {
	r.portsMu.Lock()
	r.ports[localPort] = &portState{fakeHello: fakeHello, confirmed: make(chan struct{}), injected: make(chan struct{})}
	r.portsMu.Unlock()
}

func (r *rawInjector) CleanupPort(localPort int) {
	r.portsMu.Lock()
	delete(r.ports, localPort)
	r.portsMu.Unlock()
}

func (r *rawInjector) WaitForConfirmation(localPort int, timeout time.Duration) bool {
	r.portsMu.Lock()
	ps := r.ports[localPort]
	r.portsMu.Unlock()
	if ps == nil {
		return false
	}
	select {
	case <-ps.confirmed:
		return true
	case <-time.After(timeout):
		return false
	}
}

// WaitForInjection waits until the fake ClientHello for this connection has
// actually been injected (or the timeout expires).
func (r *rawInjector) WaitForInjection(localPort int, timeout time.Duration) bool {
	r.portsMu.Lock()
	ps := r.ports[localPort]
	r.portsMu.Unlock()
	if ps == nil {
		return false
	}
	select {
	case <-ps.injected:
		return true
	case <-time.After(timeout):
		return false
	}
}

func findInterface(remoteIP string) (string, int) {
	udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(remoteIP), Port: 53})
	if err != nil {
		return "", 0
	}
	defer udp.Close()
	local := udp.LocalAddr().(*net.UDPAddr)

	ifaces, err := net.Interfaces()
	if err != nil {
		return "", 0
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if ip4 := ipn.IP.To4(); ip4 != nil && ip4.Equal(local.IP) {
				return iface.Name, iface.Index
			}
		}
	}
	return "", 0
}

func (r *rawInjector) sniffLoop() {
	buf := make([]byte, 65536)
	for r.running {
		n, _, err := unix.Recvfrom(r.fd, buf, 0)
		if err != nil {
			if !r.running {
				break
			}
			continue
		}
		r.handlePacket(buf[:n])
	}
}

func (r *rawInjector) handlePacket(pkt []byte) {
	// Detect the IP header offset. Android interfaces (rmnet, tun) are L3 and
	// deliver bare IP packets WITHOUT the 14-byte Ethernet header; wlan0/eth
	// deliver Ethernet-framed ones. The old code assumed Ethernet everywhere,
	// which silently dropped every packet on Android.
	ipOff := 14
	if len(pkt) < 14+20+20 || binary.BigEndian.Uint16(pkt[12:14]) != ethPIP {
		if len(pkt) >= 40 && pkt[0]>>4 == 4 {
			ipOff = 0 // bare IPv4 packet (L3 interface)
		} else {
			return
		}
	}
	ip := pkt[ipOff:]
	if ip[0]>>4 != 4 || ip[9] != 6 {
		return
	}
	ihl := int(ip[0]&0x0F) * 4
	if len(ip) < ihl+20 {
		return
	}
	tcp := ip[ihl:]
	if len(tcp) < 20 {
		return
	}
	flags := tcp[13]
	tcpHdrLen := int(tcp[12]>>4) * 4
	if len(tcp) < tcpHdrLen {
		return
	}
	payloadLen := len(tcp) - tcpHdrLen

	srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
	dstPort := int(binary.BigEndian.Uint16(tcp[2:4]))

	// Outbound (device -> remote service): our ephemeral port is the source.
	// Match on the fixed remote service port + the per-connection registered
	// port instead of IP equality, so every pool IP is covered — not just the
	// single CONNECT_IP the injector was created with.
	if dstPort == r.remotePort {
		r.portsMu.Lock()
		ps := r.ports[srcPort]
		r.portsMu.Unlock()
		if ps == nil {
			return
		}

		// SYN (no ACK): record the ISN for a new connection.
		if flags&tcpSYN != 0 && flags&tcpACK == 0 {
			isn := binary.BigEndian.Uint32(tcp[4:8])
			ps.mu.Lock()
			ps.synSeq = isn
			ps.mu.Unlock()
			log.Printf("[sniff] SYN port=%d isn=%d", srcPort, isn)
			return
		}

		// 3rd-handshake ACK: inject the fake ClientHello.
		if flags&tcpACK != 0 && flags&(tcpSYN|tcpFIN|tcpRST) == 0 && payloadLen == 0 {
			ps.mu.Lock()
			if ps.fakeSent {
				ps.mu.Unlock()
				return
			}
			ps.fakeSent = true
			isn := ps.synSeq
			fake := append([]byte{}, ps.fakeHello...)
			ps.mu.Unlock()

			go func(tpl []byte, isn uint32, payload []byte, port int, l3 bool) {
				time.Sleep(time.Millisecond)
				frame := buildFakeFrame(tpl, isn, payload, ipOff)
				ok := r.injectFrame(frame, l3)
				select {
				case <-ps.injected:
				default:
					close(ps.injected)
				}
				if ok {
					outSeq := isn + 1 - uint32(len(payload))
					log.Printf("[inject] port=%d fake seq=%d (ISN=%d, fake_len=%d)", port, outSeq, isn, len(payload))
				} else {
					log.Printf("[inject] port=%d injection failed", port)
				}
			}(append([]byte{}, pkt...), isn, fake, srcPort, ipOff == 0)
		}
		return
	}

	// Inbound (remote service -> device): server ACK confirming the fake was
	// ignored.
	if srcPort == r.remotePort {
		r.portsMu.Lock()
		ps := r.ports[dstPort]
		r.portsMu.Unlock()
		if ps == nil {
			return
		}
		if flags&tcpACK != 0 && flags&(tcpSYN|tcpFIN|tcpRST) == 0 && payloadLen == 0 {
			ackNum := binary.BigEndian.Uint32(tcp[8:12])
			ps.mu.Lock()
			if ps.fakeSent && ackNum == ps.synSeq+1 {
				select {
				case <-ps.confirmed:
				default:
					close(ps.confirmed)
					log.Printf("[sniff] port=%d CONFIRMED server acked ISN+1=%d", dstPort, ackNum)
				}
			}
			ps.mu.Unlock()
		}
	}
}

// buildFakeFrame rebuilds the captured 3rd-ACK packet with the fake
// ClientHello payload and an out-of-window sequence number. ipOff is 14 for
// Ethernet-framed interfaces, 0 for L3 (raw IP) ones.
func buildFakeFrame(templatePkt []byte, isn uint32, fakePayload []byte, ipOff int) []byte {
	ihl := int(templatePkt[ipOff]&0x0F) * 4
	tcpOff := ipOff + ihl
	tcpHdrLen := int(templatePkt[tcpOff+12]>>4) * 4

	out := make([]byte, 0, tcpOff+tcpHdrLen+len(fakePayload))
	out = append(out, templatePkt[:tcpOff+tcpHdrLen]...)
	out = append(out, fakePayload...)

	// IP total length.
	binary.BigEndian.PutUint16(out[ipOff+2:], uint16(len(out)-ipOff))
	// Increment IP ID.
	binary.BigEndian.PutUint16(out[ipOff+4:], binary.BigEndian.Uint16(out[ipOff+4:])+1)
	// Recompute IP checksum.
	out[ipOff+10] = 0
	out[ipOff+11] = 0
	binary.BigEndian.PutUint16(out[ipOff+10:], ipChecksum(out[ipOff:ipOff+ihl]))

	// Set PSH flag.
	out[tcpOff+13] |= tcpPSH
	// Out-of-window sequence number.
	binary.BigEndian.PutUint32(out[tcpOff+4:], isn+1-uint32(len(fakePayload)))
	// Recompute TCP checksum.
	out[tcpOff+16] = 0
	out[tcpOff+17] = 0
	binary.BigEndian.PutUint16(out[tcpOff+16:], tcpChecksum(out[ipOff:ipOff+ihl], out[tcpOff:]))

	return out
}

func (r *rawInjector) injectFrame(frame []byte, l3 bool) bool {
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(ethPIP),
		Ifindex:  r.ifaceIdx,
	}
	if !l3 {
		addr.Halen = 6
		addr.Addr = [8]byte{frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]}
	}
	if err := unix.Sendto(r.fd, frame, 0, addr); err != nil {
		log.Printf("Inject error: %v", err)
		return false
	}
	return true
}

// rawDialControlImpl registers the outgoing socket's local port with the
// raw injector from inside net.Dialer.Control (before the SYN is sent).
func rawDialControlImpl(inj RawInjector, fakeHello []byte) func(network, address string, c syscall.RawConn) error {
	r, ok := inj.(*rawInjector)
	if !ok {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			var sa syscall.RawSockaddrInet4
			size := uint32(unsafe.Sizeof(sa))
			_, _, errno := syscall.Syscall(syscall.SYS_GETSOCKNAME, fd, uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)))
			if errno != 0 {
				return
			}
			port := int(sa.Port>>8) | int(sa.Port&0xff)<<8
			r.RegisterPort(port, fakeHello)
		})
	}
}

// isRawAvailable reports whether AF_PACKET raw sockets can be opened.
func isRawAvailable() bool {
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(ethPAll)))
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

// RawStatus returns a human-readable diagnostic for raw injection.
func RawStatus() string {
	if isRawAvailable() {
		return "available (AF_PACKET raw sockets)"
	}
	return "unavailable: AF_PACKET raw sockets require root / CAP_NET_RAW"
}

// IsRawAvailable reports whether raw packet injection is supported.
func IsRawAvailable() bool {
	return isRawAvailable()
}
