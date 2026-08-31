package forward

import (
	"context"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"snispf-hj-go/internal/finalmask"
	"snispf-hj-go/internal/pool"
	"snispf-hj-go/internal/tlsutil"
)

const bufferSize = 65535

// MAX_CONCURRENT_CONNECTIONS keeps the process under the OS fd limit.
const maxConcurrentConnections = 512

// ForwardOptions carries the standard (non-MITM) forward server config.
type ForwardOptions struct {
	ListenHost   string
	ListenPort   int
	ConnectIP    string
	ConnectPort  int
	FakeSNI      string
	Strategy     BypassStrategy
	InterfaceIP  *string
	RawInjector  *RawInjector
	ConnManager  *pool.ConnectionManager
	Masker       *finalmask.FinalMasker
	CipherSuites []uint16
	BypassVPN    bool

	// Connection-lifetime bounds (<=0 = built-in defaults). MaxActiveConns
	// rejects new client connections once live upstream connections reach it;
	// HandshakeTimeout closes connections the server never answers (DPI
	// blackhole); IdleTimeout closes connections idle that long in either
	// direction. Without these, censor-blackholed connections hang forever,
	// hold their pair counter and handler slot, and active_conns explodes
	// into thousands under client retry storms.
	MaxActiveConns   int
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
}

// activeUpstream counts live upstream connections (atomic) for the cap.
var activeUpstream int64

// StartServer runs the plain-TCP forward server until ctx is cancelled.
func StartServer(ctx context.Context, opts *ForwardOptions) error {
	ln, err := net.Listen("tcp", net.JoinHostPort(opts.ListenHost, strconv.Itoa(opts.ListenPort)))
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("Listening on %s:%d", opts.ListenHost, opts.ListenPort)
	if opts.ConnManager != nil {
		log.Printf("Upstream selection: POOL (multi-IP / multi-SNI)")
	} else {
		log.Printf("Forwarding to %s:%d", opts.ConnectIP, opts.ConnectPort)
		log.Printf("Fake SNI: %s", opts.FakeSNI)
	}
	log.Printf("Bypass strategy: %s", opts.Strategy.Name())
	if opts.Masker != nil {
		log.Printf("FinalMask TCP: ENABLED (%d layer(s))", opts.Masker.LayerCount())
	}
	if opts.CipherSuites != nil {
		log.Printf("Custom cipherSuites: ENABLED (%d suite(s))", len(opts.CipherSuites))
	}
	if opts.RawInjector != nil && *opts.RawInjector != nil {
		log.Printf("Raw packet injection: ACTIVE (seq_id trick enabled)")
	} else {
		log.Printf("Raw packet injection: not available (fragmentation only)")
	}
	if opts.InterfaceIP != nil {
		log.Printf("Interface IP: %s", interfaceLabel(*opts.InterfaceIP))
	} else {
		log.Printf("Interface IP: %s", interfaceLabel(""))
	}
	log.Printf("====================================================================")
	log.Printf("Ready! Configure your application to use:")
	log.Printf("  Address: 127.0.0.1:%d", opts.ListenPort)
	log.Printf("====================================================================")

	sem := make(chan struct{}, maxConcurrentConnections)
	var wg sync.WaitGroup
	for {
		client, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				log.Printf("Server stopped.")
				return nil
			default:
				continue
			}
		}
		sem <- struct{}{}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer func() { <-sem }()
			handleConnection(ctx, c, opts)
		}(client)
	}
}

func interfaceLabel(ip string) string {
	if ip == "" {
		return "auto"
	}
	return ip
}

func handleConnection(ctx context.Context, client net.Conn, opts *ForwardOptions) {
	peer := client.RemoteAddr().String()
	releasePair := func(pair *pool.PairStats, failed bool) {}

	// Connection-lifetime bounds with built-in defaults.
	maxActive := opts.MaxActiveConns
	if maxActive <= 0 {
		maxActive = 512
	}
	handshakeTimeout := opts.HandshakeTimeout
	if handshakeTimeout <= 0 {
		handshakeTimeout = 20 * time.Second
	}
	idleTimeout := opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = 300 * time.Second
	}

	// Global active-connection cap: reject immediately instead of queueing so
	// a censor-blackhole retry storm cannot exhaust the handler pool.
	if atomic.AddInt64(&activeUpstream, 1) > int64(maxActive) {
		atomic.AddInt64(&activeUpstream, -1)
		log.Printf("[%s] active connection limit reached (%d) — rejecting", peer, maxActive)
		_ = client.Close()
		return
	}
	defer atomic.AddInt64(&activeUpstream, -1)

	var pair *pool.PairStats
	activeIP := opts.ConnectIP
	activeSNI := opts.FakeSNI
	if opts.ConnManager != nil {
		pair = opts.ConnManager.PickPair()
		activeIP = pair.IP
		activeSNI = pair.SNI
		pair.Lock()
		pair.ActiveConnections++
		pair.TotalConnections++
		pair.Unlock()
		releasePair = func(p *pool.PairStats, failed bool) {
			if p == nil {
				return
			}
			p.Lock()
			if p.ActiveConnections > 0 {
				p.ActiveConnections--
			}
			p.Unlock()
			if failed {
				p.RecordRealPacket(true)
				opts.ConnManager.ReportFailure(p)
			}
		}
	}

	fail := func(reason string) {
		if reason != "" {
			log.Printf("[%s] %s", peer, reason)
		}
		_ = client.Close()
		releasePair(pair, true)
	}

	// ── Read the first data from the client (should be a TLS ClientHello) ──
	_ = client.SetReadDeadline(time.Now().Add(30 * time.Second))
	firstData := make([]byte, bufferSize)
	n, err := client.Read(firstData)
	if err != nil || n == 0 {
		fail("no data from client")
		return
	}
	firstData = firstData[:n]
	_ = client.SetReadDeadline(time.Time{})

	clientSNI := "unknown"
	ch := tlsutil.ParseClientHello(firstData)
	if ch.SNI != "" {
		clientSNI = ch.SNI
	}
	if opts.ConnManager != nil {
		opts.ConnManager.NoteClientSNI(clientSNI)
	}

	// ── Open the outgoing socket (raw-injector registration before SYN) ──
	dialer := &net.Dialer{Timeout: 15 * time.Second}
	var control func(network, address string, c syscall.RawConn) error
	var ifaceIPStr string
	if opts.InterfaceIP != nil {
		ifaceIPStr = *opts.InterfaceIP
	}
	if opts.RawInjector != nil && *opts.RawInjector != nil {
		// Register the connection with the injector BEFORE the SYN goes out.
		// Dialer.Control runs before Go binds the socket, so the local port
		// cannot be read there; instead we reserve a free port with a
		// throwaway listener and pin it via LocalAddr. The sniffer then
		// matches the SYN on this port and injects the fake on the 3rd ACK.
		fakeHello := tlsutil.BuildClientHelloRecord(activeSNI, opts.CipherSuites)
		if port, pErr := reserveEphemeralPort(ifaceIPStr); pErr == nil && port > 0 {
			(*opts.RawInjector).RegisterPort(port, fakeHello)
			dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(ifaceIPStr), Port: port}
		}
	} else if ifaceIPStr != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(ifaceIPStr)}
	}
	if opts.BypassVPN {
		// Bind outbound sockets to the physical interface so an upstream VPN
		// (e.g. v2rayNG) cannot capture/loop the backend's own connections.
		var localIP net.IP
		if ifaceIPStr != "" {
			localIP = net.ParseIP(ifaceIPStr)
		}
		control = VPNBypassControl(localIP, nil)
	}
	dialer.Control = control

	server, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(activeIP, strconv.Itoa(opts.ConnectPort)))
	if err != nil {
		fail("connect to " + activeIP + ":" + strconv.Itoa(opts.ConnectPort) + " failed: " + err.Error())
		return
	}
	defer server.Close()
	localPort := 0
	if tcp, ok := server.(*net.TCPConn); ok {
		localPort = tcp.LocalAddr().(*net.TCPAddr).Port
	}
	if opts.RawInjector != nil && *opts.RawInjector != nil && localPort > 0 {
		defer (*opts.RawInjector).CleanupPort(localPort)
	}

	loss := ""
	if pair != nil {
		loss = " | pool_loss=" + strconv.FormatFloat(pair.CombinedLossRate()*100, 'f', 1, 64) + "%"
	}
	log.Printf("[%s] -> %s:%d | SNI: %s | Fake: %s | Method: %s%s",
		peer, activeIP, opts.ConnectPort, clientSNI, activeSNI, opts.Strategy.Name(), loss)

	maskerInstance := (*finalmask.FinalMasker)(nil)
	if opts.Masker != nil {
		maskerInstance = opts.Masker.Clone()
	}

	// ── Send the initial data: finalmask or the bypass strategy ──────────
	if maskerInstance != nil {
		sink := func(chunk []byte) error {
			_, err := server.Write(chunk)
			return err
		}
		if mErr := maskerInstance.Send(sink, firstData); mErr != nil {
			fail("finalmask send failed")
			return
		}
	} else {
		if aErr := opts.Strategy.Apply(server, activeSNI, firstData); aErr != nil {
			log.Printf("[%s] Bypass strategy '%s' failed, falling back to direct relay", peer, opts.Strategy.Name())
			if _, wErr := server.Write(firstData); wErr != nil {
				fail("direct send failed")
				return
			}
		}
	}

	// ── Bidirectional relay ────────────────────────────────────────────────
	done := make(chan struct{})
	var serverRespondedMu sync.Mutex
	serverResponded := false
	var clientWrote int32 // atomic: client sent data beyond the initial hello

	relay := func(src, dst net.Conn, label string) {
		buf := make([]byte, bufferSize)
		for {
			if idleTimeout > 0 {
				_ = src.SetReadDeadline(time.Now().Add(idleTimeout))
			}
			r, rErr := src.Read(buf)
			if r > 0 {
				if label == "C->S" {
					atomic.StoreInt32(&clientWrote, 1)
				}
				if label == "C->S" && maskerInstance != nil {
					sink := func(chunk []byte) error {
						_, err := dst.Write(chunk)
						return err
					}
					if mErr := maskerInstance.Send(sink, buf[:r]); mErr != nil {
						break
					}
				} else {
					if _, wErr := dst.Write(buf[:r]); wErr != nil {
						break
					}
				}
				if label == "S->C" {
					serverRespondedMu.Lock()
					if !serverResponded {
						serverResponded = true
					}
					serverRespondedMu.Unlock()
				}
			}
			if rErr != nil {
				break
			}
		}
		done <- struct{}{}
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); relay(client, server, "C->S") }()
	go func() { defer wg.Done(); relay(server, client, "S->C") }()

	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		if pair == nil {
			<-done
			return
		}
		ev := pair.ForceCloseEvent()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		start := time.Now()
		for {
			select {
			case <-ev:
				log.Printf("Drain timeout reached for %s — closing connection from %s", pair.IP, peer)
				_ = client.Close()
				_ = server.Close()
				done <- struct{}{}
				return
			case <-ticker.C:
				select {
				case <-done:
					return
				default:
				}
				// Handshake window: if the server never answered (DPI
				// blackhole of the confusing out-of-window traffic) and the
				// client never sent anything beyond the initial hello, this
				// connection can never succeed. Tear it down so the pair
				// counter and handler slot are released instead of piling
				// up into thousands of stuck "active" connections.
				serverRespondedMu.Lock()
				responded := serverResponded
				serverRespondedMu.Unlock()
				wrote := atomic.LoadInt32(&clientWrote) == 1
				now := time.Now()
				if !responded && !wrote && now.Sub(start) > handshakeTimeout {
					log.Printf("[%s] no server response and no client data within %v — closing (blackhole)", peer, handshakeTimeout)
					_ = client.Close()
					_ = server.Close()
					continue
				}
				// Idle bound: nothing ever flowed beyond the hello.
				if !responded && !wrote && now.Sub(start) > idleTimeout {
					log.Printf("[%s] idle %v with no data — closing", peer, idleTimeout)
					_ = client.Close()
					_ = server.Close()
					continue
				}
			}
		}
	}()

	<-done
	_ = client.Close()
	_ = server.Close()
	wg.Wait()
	<-watcherDone

	serverRespondedMu.Lock()
	failed := !serverResponded
	serverRespondedMu.Unlock()
	releasePair(pair, failed)
}

// rawDialControl returns a net.Dialer.Control func that registers the
// outgoing socket's local port with the raw injector before the SYN goes
// out. Platform-specific implementations live in tagged files.
var rawDialControl = rawDialControlImpl

// reserveEphemeralPort asks the kernel for a free local TCP port by binding a
// throwaway listener and closing it. The port is then pinned as the dial's
// LocalAddr so the raw injector knows it before the SYN is sent. There is a
// small race window between the close and the dial's bind; if lost, that
// single dial fails (rare in practice).
func reserveEphemeralPort(host string) (int, error) {
	l, err := net.Listen("tcp4", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port, nil
}
