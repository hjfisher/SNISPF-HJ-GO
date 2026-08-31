//go:build windows

package forward

import (
	"encoding/binary"
	"log"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// WinDivert functional flags (subset used here).
const (
	winDivertLayerNetwork = 0
	winDivertFlagSniff    = 0x0001
)

// Proxied WinDivert functions, loaded lazily from WinDivert.dll. The driver
// (WinDivert32.sys / WinDivert64.sys) and Administrator privileges are
// required at runtime; if opening fails we degrade to fragmentation.
var (
	winDivertDLL = syscall.NewLazyDLL("WinDivert.dll")

	procWinDivertOpen                = winDivertDLL.NewProc("WinDivertOpen")
	procWinDivertClose               = winDivertDLL.NewProc("WinDivertClose")
	procWinDivertRecv                = winDivertDLL.NewProc("WinDivertRecv")
	procWinDivertSend                = winDivertDLL.NewProc("WinDivertSend")
	procWinDivertHelperCalcChecksums = winDivertDLL.NewProc("WinDivertHelperCalcChecksums")

	procGetsockname = syscall.NewLazyDLL("ws2_32.dll").NewProc("getsockname")
)

// winDivertAddress mirrors WIN_DIVERT_ADDRESS (80 bytes). We only touch the
// fields we need, addressed by fixed byte offsets so we stay independent of
// bitfield packing.
type winDivertAddress [80]byte

// Network-layer offsets inside WIN_DIVERT_ADDRESS.
const (
	wdOffLayer    = 8  // Layer (byte)
	wdOffEvent    = 9  // Event (byte)
	wdOffFlags    = 10 // bit0=Sniffed bit1=Outbound bit2=Loopback bit3=Impostor bit4=IPv6 bit5=IPChk bit6=TCPChk bit7=UDPChk
	wdOffIfIdx    = 16 // union: Network.IfIdx
	wdOffSubIfIdx = 20 // union: Network.SubIfIdx
)

const wdFlagOutbound = 0x02 // bit1
const wdFlagIPv6     = 0x10 // bit4

func (a *winDivertAddress) setOutbound()    { a[wdOffFlags] |= wdFlagOutbound }
func (a *winDivertAddress) setIfIdx(v uint32) {
	binary.LittleEndian.PutUint32(a[wdOffIfIdx:], v)
}
func (a *winDivertAddress) setSubIfIdx(v uint32) {
	binary.LittleEndian.PutUint32(a[wdOffSubIfIdx:], v)
}

// windowsRawInjector sniffs the outbound TCP handshake and injects the fake
// ClientHello with an out-of-window seq (the seq_id trick) using WinDivert.
type windowsRawInjector struct {
	remoteIP   [4]byte
	remotePort int
	ifIdx      uint32
	subIfIdx   uint32

	handle  syscall.Handle
	running bool

	portsMu sync.Mutex
	ports   map[int]*portState

	filter string
}

// NewRawInjector builds the Windows (WinDivert) raw injector.
func NewRawInjector(localIP, remoteIP string, remotePort int) RawInjector {
	r := &windowsRawInjector{
		remotePort: remotePort,
		ports:      make(map[int]*portState),
		handle:     syscall.InvalidHandle,
	}
	copy(r.remoteIP[:], net.ParseIP(remoteIP).To4())

	// WinDivert captures at the IP layer. We match (a) outbound TCP going to
	// the destination port (to register SYN/ACK and trigger injection) and
	// (b) inbound TCP from that port (to see the server ACK that confirms the
	// fake segment was ignored). Port matching happens in userspace.
	r.filter = "(outbound && ip && tcp && tcp.DstPort == " + strconv.Itoa(remotePort) +
		") || (inbound && ip && tcp && tcp.SrcPort == " + strconv.Itoa(remotePort) + ")"

	return r
}

func (r *windowsRawInjector) Start() bool {
	if r.handle != syscall.InvalidHandle {
		return true
	}
	// Explicitly load WinDivert.dll so a missing driver/DLL degrades to
	// fragmentation instead of panicking inside LazyProc.Call.
	if err := winDivertDLL.Load(); err != nil {
		log.Printf("WinDivert: cannot load WinDivert.dll (fake SNI disabled, using fragmentation): %v", err)
		return false
	}
	if err := procWinDivertOpen.Find(); err != nil {
		log.Printf("WinDivert: WinDivert.dll missing WinDivertOpen export: %v", err)
		return false
	}
	filterPtr, err := syscall.BytePtrFromString(r.filter)
	if err != nil {
		log.Printf("WinDivert: bad filter string: %v", err)
		return false
	}

	handle, _, callErr := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(winDivertLayerNetwork),
		uintptr(0), // priority
		uintptr(winDivertFlagSniff), // SNIFF: observe without diverting normal traffic
	)
	h := syscall.Handle(handle)
	if h == syscall.InvalidHandle || h == 0 {
		log.Printf("WinDivert: cannot open handle (need Administrator privileges and the WinDivert driver installed): %v", callErr)
		return false
	}
	r.handle = h
	r.running = true

	// Resolve the outgoing interface indexes for outbound injection.
	r.resolveInterface()

	go r.sniffLoop()
	log.Printf("WinDivert raw packet injector started")
	return true
}

func (r *windowsRawInjector) resolveInterface() {
	// The outgoing interface for the remote. Use a UDP connect trick.
	remote := net.ParseIP(net.IPv4(r.remoteIP[0], r.remoteIP[1], r.remoteIP[2], r.remoteIP[3]).String())
	udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: remote, Port: 53})
	if err != nil {
		return
	}
	local := udp.LocalAddr().(*net.UDPAddr)
	_ = udp.Close()

	ifaces, err := net.Interfaces()
	if err != nil {
		return
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
				r.ifIdx = uint32(iface.Index)
				r.subIfIdx = uint32(iface.Index)
				return
			}
		}
	}
}

func (r *windowsRawInjector) Stop() {
	r.running = false
	if r.handle != syscall.InvalidHandle && r.handle != 0 {
		_, _, _ = procWinDivertClose.Call(uintptr(r.handle))
		r.handle = syscall.InvalidHandle
	}
}

func (r *windowsRawInjector) RegisterPort(localPort int, fakeHello []byte) {
	r.portsMu.Lock()
	r.ports[localPort] = &portState{fakeHello: fakeHello, confirmed: make(chan struct{}), injected: make(chan struct{})}
	r.portsMu.Unlock()
}

func (r *windowsRawInjector) CleanupPort(localPort int) {
	r.portsMu.Lock()
	delete(r.ports, localPort)
	r.portsMu.Unlock()
}

func (r *windowsRawInjector) WaitForConfirmation(localPort int, timeout time.Duration) bool {
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
func (r *windowsRawInjector) WaitForInjection(localPort int, timeout time.Duration) bool {
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

var sniffFirstOnce sync.Once

func (r *windowsRawInjector) sniffLoop() {
	buf := make([]byte, winDivertMTU)
	for r.running {
		var recvLen uint32
		var addr winDivertAddress
		n, _, callErr := procWinDivertRecv.Call(
			uintptr(r.handle),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(unsafe.Pointer(&recvLen)),
			uintptr(unsafe.Pointer(&addr)),
		)
		if n == 0 {
			if !r.running {
				break
			}
			_ = callErr
			continue
		}
		if recvLen > 0 {
			sniffFirstOnce.Do(func() {
				log.Printf("[sniff] WinDivert capture alive: first packet %d bytes", recvLen)
			})
			r.handlePacket(buf[:recvLen], &addr)
		}
	}
}

func (r *windowsRawInjector) handlePacket(pkt []byte, addr *winDivertAddress) {
	// IPv6 is not supported by the seq-id trick here.
	if addr[wdOffFlags]&wdFlagIPv6 != 0 {
		return
	}
	if len(pkt) < 20+20 {
		return
	}
	verIhl := pkt[0]
	if verIhl>>4 != 4 {
		return
	}
	ihl := int(verIhl&0x0F) * 4
	if len(pkt) < ihl+20 {
		return
	}
	protocol := pkt[9]
	if protocol != 6 { // TCP
		return
	}
	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))

	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return
	}
	srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	flags := tcp[13]
	tcpHdrLen := int(tcp[12]>>4) * 4
	if len(tcp) < tcpHdrLen {
		return
	}
	payloadLen := totalLen - ihl - tcpHdrLen

	outbound := addr[wdOffFlags]&wdFlagOutbound != 0
	if outbound {
		// Only consider outbound packets on a registered local (source) port.
		r.portsMu.Lock()
		ps := r.ports[srcPort]
		r.portsMu.Unlock()
		if ps == nil {
			return
		}

		// SYN (no ACK): record the ISN for this connection.
		if flags&0x02 != 0 && flags&0x10 == 0 {
			ps.mu.Lock()
			ps.synSeq = seq
			ps.mu.Unlock()
			log.Printf("[sniff] SYN port=%d isn=%d", srcPort, seq)
			return
		}

		// 3rd-handshake ACK (no payload): inject the fake ClientHello.
		if flags&0x10 != 0 && flags&(0x02|0x01|0x04) == 0 && payloadLen == 0 {
			ps.mu.Lock()
			if ps.fakeSent {
				ps.mu.Unlock()
				return
			}
			ps.fakeSent = true
			isn := ps.synSeq
			fake := append([]byte{}, ps.fakeHello...)
			ps.mu.Unlock()

			pktIfIdx := binary.LittleEndian.Uint32(addr[wdOffIfIdx:])
			go func(tpl []byte, isn uint32, payload []byte, port int, obsIfIdx uint32) {
				time.Sleep(time.Millisecond)
				ok := r.injectFake(tpl, isn, payload, obsIfIdx)
				ps.mu.Lock()
				select {
				case <-ps.injected:
				default:
					close(ps.injected)
				}
				ps.mu.Unlock()
				if ok {
					log.Printf("[inject] port=%d fake seq=%d (ISN=%d, fake_len=%d, ifidx=%d)", port, isn+1-uint32(len(payload)), isn, len(payload), obsIfIdx)
				} else {
					log.Printf("[inject] port=%d injection failed", port)
				}
			}(append([]byte{}, pkt...), isn, fake, srcPort, pktIfIdx)
		}
		return
	}

	// Inbound: the destination port is our local port. Look for the server
	// ACK that confirms the fake out-of-window segment was ignored.
	localPort := int(binary.BigEndian.Uint16(tcp[2:4]))
	if flags&0x10 != 0 && flags&(0x02|0x01|0x04) == 0 && payloadLen == 0 {
		r.portsMu.Lock()
		ps := r.ports[localPort]
		r.portsMu.Unlock()
		if ps == nil {
			return
		}
		ps.mu.Lock()
		if ps.fakeSent && ack == ps.synSeq+1 {
			select {
			case <-ps.confirmed:
			default:
				close(ps.confirmed)
				log.Printf("[sniff] port=%d CONFIRMED server acked ISN+1=%d", localPort, ack)
			}
		}
		ps.mu.Unlock()
	}
}

// injectFake builds an IP+TCP frame carrying the fake ClientHello with an
// out-of-window sequence number and sends it via WinDivert. obsIfIdx is the
// interface index the monitored 3rd-ACK was observed on — injections follow
// the connection's actual interface, so network switches (Wi-Fi <-> Ethernet)
// don't send the fake out a stale interface.
func (r *windowsRawInjector) injectFake(template []byte, isn uint32, fakePayload []byte, obsIfIdx uint32) bool {
	if r.handle == syscall.InvalidHandle || r.handle == 0 {
		return false
	}
	ihl := int(template[0]&0x0F) * 4
	tcpOff := ihl
	tcpHdrLen := int(template[tcpOff+12]>>4) * 4

	out := make([]byte, 0, tcpOff+tcpHdrLen+len(fakePayload))
	out = append(out, template[:tcpOff+tcpHdrLen]...)
	out = append(out, fakePayload...)

	// IP total length.
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	// Increment IP ID.
	binary.BigEndian.PutUint16(out[4:6], binary.BigEndian.Uint16(out[4:6])+1)
	// Zero IP checksum, recompute.
	out[10] = 0
	out[11] = 0
	binary.BigEndian.PutUint16(out[10:12], ipChecksum(out[:ihl]))

	// PSH flag.
	out[tcpOff+13] |= 0x08
	// Out-of-window seq.
	binary.BigEndian.PutUint32(out[tcpOff+4:], isn+1-uint32(len(fakePayload)))
	// Zero TCP checksum, recompute.
	out[tcpOff+16] = 0
	out[tcpOff+17] = 0
	binary.BigEndian.PutUint16(out[tcpOff+16:tcpOff+18], tcpChecksum(out[:ihl], out[tcpOff:]))

	var addr winDivertAddress
	addr.setOutbound()
	ifIdx := obsIfIdx
	if ifIdx == 0 {
		ifIdx = r.ifIdx
	}
	addr.setIfIdx(ifIdx)
	addr.setSubIfIdx(ifIdx)

	var sendLen uint32
	n, _, callErr := procWinDivertSend.Call(
		uintptr(r.handle),
		uintptr(unsafe.Pointer(&out[0])),
		uintptr(len(out)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if n == 0 {
		log.Printf("WinDivert send failed: %v", callErr)
		return false
	}
	return true
}

// rawDialControlImpl registers the outgoing socket's local port with the
// WinDivert injector from inside net.Dialer.Control (before the SYN is sent).
func rawDialControlImpl(inj RawInjector, fakeHello []byte) func(network, address string, c syscall.RawConn) error {
	r, ok := inj.(*windowsRawInjector)
	if !ok {
		return nil
	}
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			var sa syscall.RawSockaddrInet4
			size := uint32(unsafe.Sizeof(sa))
			r1, _, e := procGetsockname.Call(fd, uintptr(unsafe.Pointer(&sa)), uintptr(unsafe.Pointer(&size)))
			if r1 != 0 || e != syscall.Errno(0) {
				return
			}
			port := int(sa.Port>>8) | int(sa.Port&0xff)<<8
			r.RegisterPort(port, fakeHello)
		})
	}
}

// isRawAvailable reports whether the WinDivert driver can be opened.
func isRawAvailable() bool {
	return checkWinDivert() == ""
}

// RawStatus returns a human-readable diagnostic describing why raw fake-SNI
// injection is or isn't available on this platform. Empty string means it works.
func RawStatus() string {
	return checkWinDivert()
}

func checkWinDivert() string {
	// Load the DLL before touching procs (a missing DLL would otherwise panic).
	if err := winDivertDLL.Load(); err != nil {
		return "WinDivert.dll not found (place WinDivert.dll, WinDivert32.sys and WinDivert64.sys next to the exe, then re-run as Administrator)"
	}
	if err := procWinDivertOpen.Find(); err != nil {
		return "WinDivert.dll present but WinDivertOpen export missing: " + err.Error()
	}

	filterPtr, err := syscall.BytePtrFromString("outbound && ip && tcp && tcp.DstPort == 443")
	if err != nil {
		return "bad probe filter: " + err.Error()
	}
	handle, _, callErr := procWinDivertOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		uintptr(winDivertLayerNetwork),
		uintptr(0),
		uintptr(winDivertFlagSniff),
	)
	h := syscall.Handle(handle)
	if h == syscall.InvalidHandle || h == 0 {
		code := uint32(0)
		if e, ok := callErr.(syscall.Errno); ok {
			code = uint32(e)
		}
		return "WinDivertOpen failed (error " + strconv.Itoa(int(code)) +
			"). Causes: not running as Administrator, or the WinDivert kernel driver is not installed / is blocked by Secure Boot or security software. Install the signed WinDivert drivers and run elevated."
	}
	_, _, _ = procWinDivertClose.Call(uintptr(h))
	return ""
}

// IsRawAvailable reports whether WinDivert-based raw injection is supported.
func IsRawAvailable() bool {
	return isRawAvailable()
}

const winDivertMTU = 40 + 0xFFFF
