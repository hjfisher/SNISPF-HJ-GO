package forward

import (
	"context"
	"log"
	"net"
	"strconv"
	"sync"
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
	InterfaceIP  string
	RawInjector  RawInjector
	ConnManager  *pool.ConnectionManager
	Masker       *finalmask.FinalMasker
	CipherSuites []uint16
}

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
	if opts.RawInjector != nil {
		log.Printf("Raw packet injection: ACTIVE (seq_id trick enabled)")
	} else {
		log.Printf("Raw packet injection: not available (fragmentation only)")
	}
	log.Printf("Interface IP: %s", interfaceLabel(opts.InterfaceIP))
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
	if opts.RawInjector != nil {
		fakeHello := tlsutil.BuildClientHelloRecord(activeSNI, opts.CipherSuites)
		dialer.Control = rawDialControl(opts.RawInjector, fakeHello)
	}
	if opts.InterfaceIP != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(opts.InterfaceIP)}
	}

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
	if opts.RawInjector != nil && localPort > 0 {
		defer opts.RawInjector.CleanupPort(localPort)
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

	relay := func(src, dst net.Conn, label string) {
		buf := make([]byte, bufferSize)
		for {
			r, rErr := src.Read(buf)
			if r > 0 {
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
