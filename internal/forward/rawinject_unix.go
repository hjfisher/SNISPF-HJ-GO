//go:build linux
//go:build android

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

const (
	ethPIP  = 0x0800
	ethPAll = 0x0003
)

// TCP flags
const (
	tcpFIN = 0x01
	tcpSYN = 0x02
	tcpRST = 0x04
	tcpPSH = 0x08
	tcpACK = 0x10
)

// portState tracks a single outgoing connection for the sniffer.
type portState struct {
	mu        sync.Mutex
	synSeq    uint32
	fakeHello []byte
	fakeSent  bool
	confirmed chan struct{}
}

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

// NewRawInjector builds the Linux raw injector (nil elsewhere).
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
	r.ports[localPort] = &portState{fakeHello: fakeHello, confirmed: make(chan struct{})}
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
	if len(pkt) < 14+20+20 {
		return
	}
	// Ethernet type must be IPv4.
	if binary.BigEndian.Uint16(pkt[12:14]) != ethPIP {
		return
	}
	ip := pkt[14:]
	if ip[0]>>4 != 4 || ip[9] != 6 {
		return
	}
	ihl := int(ip[0]&0x0F) * 4
	if len(ip) < ihl+20 {
		return
	}
	var srcIP, dstIP [4]byte
	copy(srcIP[:], ip[12:16])
	copy(dstIP[:], ip[16:20])
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

	outbound := srcIP == r.localIP && dstIP == r.remoteIP
	inbound := srcIP == r.remoteIP && dstIP == r.localIP

	if outbound {
		srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
		seq := binary.BigEndian.Uint32(tcp[4:8])

		// SYN (no ACK): record the ISN for a new connection.
		if flags&tcpSYN != 0 && flags&tcpACK == 0 {
			r.portsMu.Lock()
			ps := r.ports[srcPort]
			r.portsMu.Unlock()
			if ps != nil {
				ps.mu.Lock()
				ps.synSeq = seq
				ps.mu.Unlock()
				log.Printf("[sniff] SYN port=%d isn=%d", srcPort, seq)
			}
			return
		}

		// 3rd-handshake ACK: inject the fake ClientHello.
		if flags&tcpACK != 0 && flags&(tcpSYN|tcpFIN|tcpRST) == 0 && payloadLen == 0 {
			r.portsMu.Lock()
			ps := r.ports[srcPort]
			r.portsMu.Unlock()
			if ps == nil {
				return
			}
			ps.mu.Lock()
			if ps.fakeSent {
				ps.mu.Unlock()
				return
			}
			ps.fakeSent = true
			isn := ps.synSeq
			fake := append([]byte{}, ps.fakeHello...)
			ps.mu.Unlock()

			go func(tpl []byte, isn uint32, payload []byte, port int) {
				time.Sleep(time.Millisecond)
				frame := buildFakeFrame(tpl, isn, payload)
				if r.injectFrame(frame) {
					outSeq := isn + 1 - uint32(len(payload))
					log.Printf("[inject] port=%d fake seq=%d (ISN=%d, fake_len=%d)", port, outSeq, isn, len(payload))
				} else {
					log.Printf("[inject] port=%d injection failed", port)
				}
			}(append([]byte{}, pkt...), isn, fake, srcPort)
		}
	}

	if inbound {
		dstPort := int(binary.BigEndian.Uint16(tcp[2:4]))
		ackNum := binary.BigEndian.Uint32(tcp[8:12])

		// Server ACK confirming the fake was ignored.
		if flags&tcpACK != 0 && flags&(tcpSYN|tcpFIN|tcpRST) == 0 && payloadLen == 0 {
			r.portsMu.Lock()
			ps := r.ports[dstPort]
			r.portsMu.Unlock()
			if ps == nil {
				return
			}
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
// ClientHello payload and an out-of-window sequence number.
func buildFakeFrame(templatePkt []byte, isn uint32, fakePayload []byte) []byte {
	ipOff := 14
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

func (r *rawInjector) injectFrame(frame []byte) bool {
	addr := &unix.SockaddrLinklayer{
		Protocol: htons(ethPIP),
		Ifindex:  r.ifaceIdx,
		Halen:    6,
		Addr:     [8]byte{frame[0], frame[1], frame[2], frame[3], frame[4], frame[5]},
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
