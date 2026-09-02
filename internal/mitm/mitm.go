package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"

	"snispf-hj-go/internal/finalmask"
	"snispf-hj-go/internal/forward"
	"snispf-hj-go/internal/pool"
	"snispf-hj-go/internal/tlsutil"
)

const bufferSize = 65535

const (
	dialTimeout      = 15 * time.Second
	handshakeTimeout = 30 * time.Second
)

// Options carries the MITM server configuration.
type Options struct {
	ListenHost     string
	ListenPort     int
	ConnectIP      string
	ConnectPort    int
	FakeSNI        string
	CipherSuites   []uint16
	ALPN           []string
	MaskerRules    []interface{}
	CertFile       string
	KeyFile        string
	UseClientSNI   bool
	ConnManager    *pool.ConnectionManager
	Fingerprint    string
	FingerprintBin string
	// Real ECH (Xray-compatible). ECHConfigList is either a base64 ECHConfig
	// or a DNS source "domain+https://doh" / "https://doh" / "udp://dns".
	// ECHForceQuery "full" fails the connection when the config cannot be
	// fetched (SNI never leaks); "best-effort" falls back to plain TLS.
	ECHConfigList string
	ECHForceQuery string
	// Raw injection on the upstream connection (seq_id trick). When enabled
	// and a raw backend is available, the MITM upstream dial is registered
	// with the raw injector so an out-of-window fake-SNI hello is injected.
	// The decoy SNI shown to the ISP is the per-connection pool SNI
	// (activeSNI), hiding the real routing SNI.
	UseRawInjection bool
	RawInjector     *forward.RawInjector
	InterfaceIP     *string
	BypassVPN       bool
}

// Start runs the MITM relay server until ctx is cancelled.
func Start(ctx context.Context, opts *Options) error {
	cert, err := tls.LoadX509KeyPair(opts.CertFile, opts.KeyFile)
	if err != nil {
		return fmt.Errorf("mitm: load cert: %w", err)
	}

	maskerTemplate := finalmask.NewFinalMasker(opts.MaskerRules)

	ln, err := net.Listen("tcp", net.JoinHostPort(opts.ListenHost, strconv.Itoa(opts.ListenPort)))
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Println("============================================================")
	log.Println("MITM mode (tls-decrypt / tls-repack) active")
	log.Printf("Listening on %s:%d (TLS terminated with self-signed cert)", opts.ListenHost, opts.ListenPort)
	if opts.ConnManager != nil {
		log.Printf("Upstream selection: POOL (%d pair(s), %d active slot(s))",
			len(opts.ConnManager.Explorer.Stats), opts.ConnManager.Pool.Slots)
	} else {
		log.Printf("Upstream: %s:%d  SNI: %s", opts.ConnectIP, opts.ConnectPort, opts.FakeSNI)
	}
	log.Printf("Upstream cipherSuites: %v", opts.CipherSuites)
	log.Printf("Upstream fingerprint: %s", opts.Fingerprint)
	log.Printf("FinalMask TCP: %s", finalmaskStatus(maskerTemplate))
	log.Printf("Client ALPN: %v", opts.ALPN)
	log.Println("============================================================")

	var wg sync.WaitGroup
	for {
		rawConn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				wg.Wait()
				return nil
			default:
				continue
			}
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			handleClient(ctx, c, opts, maskerTemplate, cert)
		}(rawConn)
	}
}

func finalmaskStatus(m *finalmask.FinalMasker) string {
	if m == nil {
		return "disabled"
	}
	return fmt.Sprintf("ENABLED (%d layer(s))", m.LayerCount())
}

func handleClient(ctx context.Context, rawConn net.Conn, opts *Options, maskerTemplate *finalmask.FinalMasker, cert tls.Certificate) {
	peer := rawConn.RemoteAddr().String()

	// ── Server-side TLS termination (capture the client's SNI) ─────────
	var capturedSNI string
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   opts.ALPN,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			if chi.ServerName != "" {
				capturedSNI = chi.ServerName
			}
			return nil, nil
		},
	}
	tconn := tls.Server(rawConn, serverCfg)
	if err := tconn.HandshakeContext(ctx); err != nil {
		_ = rawConn.Close()
		return
	}
	clientALPN := tconn.ConnectionState().NegotiatedProtocol
	reader := tconn

	// ── Pool integration: pick the best (IP, SNI) pair ─────────────────
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
	}

	releasePair := func(failed bool) {
		if pair == nil {
			return
		}
		pair.Lock()
		if pair.ActiveConnections > 0 {
			pair.ActiveConnections--
		}
		pair.Unlock()
		if failed {
			pair.RecordRealPacket(true)
			opts.ConnManager.ReportFailure(pair)
		}
	}

	clientSNI := capturedSNI
	if opts.ConnManager != nil {
		opts.ConnManager.NoteClientSNI(clientSNI)
	}

	// ── Upstream TLS: fresh ClientHello (fake SNI / client SNI + uTLS) ──
	upALPN := opts.ALPN
	if clientALPN != "" {
		upALPN = []string{clientALPN}
	}
	serverName := activeSNI
	if opts.UseClientSNI && clientSNI != "" {
		serverName = clientSNI
	}

	// ── Upstream dial: optionally register with the raw injector ────────
	var dialer *net.Dialer
	var rawLocalPort int
	var control func(network, address string, c syscall.RawConn) error
	rawActive := opts.UseRawInjection && opts.RawInjector != nil && *opts.RawInjector != nil
	localIP := net.ParseIP("")
	if opts.InterfaceIP != nil && *opts.InterfaceIP != "" {
		localIP = net.ParseIP(*opts.InterfaceIP)
	}
	if rawActive {
		// Decoy SNI shown to the ISP: the per-connection pool SNI (activeSNI)
		// so the censor sees a rotating fake SNI; falls back to FAKE_SNI.
		decoy := activeSNI
		if decoy == "" {
			decoy = opts.FakeSNI
		}
		fakeHello := tlsutil.BuildClientHelloRecord(decoy, opts.CipherSuites)
		control = forward.DialControl(*opts.RawInjector, fakeHello)
		log.Printf("[%s] MITM upstream raw injection ACTIVE (decoy SNI=%s, real SNI=%s)", peer, decoy, serverName)
	}
	if opts.BypassVPN {
		// Bind outbound sockets to the physical interface so an upstream VPN
		// (e.g. v2rayNG) cannot capture/loop the backend's own connections.
		control = forward.VPNBypassControl(localIP, control)
	}
	if control != nil || rawActive || opts.BypassVPN {
		dialer = &net.Dialer{Timeout: dialTimeout, Control: control}
		if opts.InterfaceIP != nil && *opts.InterfaceIP != "" {
			dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(*opts.InterfaceIP)}
		}
	}

	up, err := openUpstream(ctx, activeIP, opts.ConnectPort, serverName, upALPN, opts.Fingerprint, opts.CipherSuites, dialer, opts.ECHConfigList, opts.ECHForceQuery)
	if err != nil {
		log.Printf("[%s] upstream connect %s:%d failed: %v", peer, activeIP, opts.ConnectPort, err)
		releasePair(true)
		_ = tconn.Close()
		return
	}
	if rawActive {
		if tcp, ok := up.(*net.TCPConn); ok {
			if la, ok := tcp.LocalAddr().(*net.TCPAddr); ok {
				rawLocalPort = la.Port
			}
		}
	}
	defer func() {
		if rawActive && rawLocalPort > 0 {
			(*opts.RawInjector).CleanupPort(rawLocalPort)
		}
	}()
	defer up.Close()

	loss := ""
	if pair != nil {
		loss = fmt.Sprintf(" | pool_loss=%.1f%%", pair.CombinedLossRate()*100)
	}
	log.Printf("[%s] MITM relay: client=%s sni=%s alpn=%s -> %s:%d sni=%s cipherSuites=%v fingerprint=%s%s",
		peer, peer, clientSNI, clientALPN, activeIP, opts.ConnectPort, serverName, opts.CipherSuites, opts.Fingerprint, loss)

	masker := maskerTemplate.Clone()
	done := make(chan struct{})
	var serverRespondedMu sync.Mutex
	serverResponded := false

	sink := func(chunk []byte) error {
		_, err := up.Write(chunk)
		return err
	}

	var wg sync.WaitGroup
	wg.Add(2)

	// C->S
	go func() {
		defer wg.Done()
		buf := make([]byte, bufferSize)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				if masker != nil {
					if mErr := masker.Send(sink, buf[:n]); mErr != nil {
						break
					}
				} else {
					if _, wErr := up.Write(buf[:n]); wErr != nil {
						break
					}
				}
			}
			if err != nil {
				break
			}
		}
		select {
		case done <- struct{}{}:
		default:
		}
	}()

	// S->C
	go func() {
		defer wg.Done()
		buf := make([]byte, bufferSize)
		for {
			n, err := up.Read(buf)
			if n > 0 {
				if _, wErr := tconn.Write(buf[:n]); wErr != nil {
					break
				}
				serverRespondedMu.Lock()
				if !serverResponded {
					serverResponded = true
					if pair != nil {
						pair.RecordRealPacket(false)
					}
				}
				serverRespondedMu.Unlock()
			}
			if err != nil {
				break
			}
		}
		select {
		case done <- struct{}{}:
		default:
		}
	}()

	// Drain watcher
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
				log.Printf("Drain timeout reached for %s / %s — closing MITM relay from %s", pair.IP, pair.SNI, peer)
				_ = tconn.Close()
				_ = up.Close()
				select {
				case done <- struct{}{}:
				default:
				}
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
	_ = tconn.Close()
	_ = up.Close()
	wg.Wait()
	<-watcherDone

	serverRespondedMu.Lock()
	failed := !serverResponded
	serverRespondedMu.Unlock()
	releasePair(failed)
}

// openUpstream connects to the real upstream and completes TLS. With a
// fingerprint profile the handshake is driven in-process by uTLS (a
// byte-perfect browser ClientHello); otherwise Go's crypto/tls builds it.
// When echConfigList is set, real ECH is applied: the SNI travels encrypted
// in the inner hello and the outer hello carries the ECH config's
// public_name (see ech.go for the Xray-compatible config formats).
func openUpstream(ctx context.Context, activeIP string, connectPort int, serverName string, alpn []string, fingerprint string, cipherSuites []uint16, dialer *net.Dialer, echConfigList string, echForceQuery string) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: dialTimeout}
	}
	raw, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(activeIP, strconv.Itoa(connectPort)))
	if err != nil {
		return nil, err
	}

	fpName := tlsutil.ResolveFingerprint(fingerprint)
	if fpName == "" {
		// Plain crypto/tls path. Go 1.24+ supports ECH natively via
		// EncryptedClientHelloConfigList.
		tlsCfg := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			NextProtos:         alpn,
			CipherSuites:       cipherSuites,
		}
		if echConfigList != "" {
			cfg, failClosed, echErr := applyECH(echConfigList, echForceQuery, serverName)
			if echErr != nil && failClosed {
				log.Printf("[ECH] config fetch failed (force-query=full): %v — connection will fail closed", echErr)
			} else if echErr != nil {
				log.Printf("[ECH] config fetch failed, falling back to plain TLS: %v", echErr)
			}
			if cfg != nil {
				tlsCfg.EncryptedClientHelloConfigList = cfg
			} else if failClosed {
				tlsCfg.EncryptedClientHelloConfigList = invalidECHConfig
			}
		}
		tconn := tls.Client(raw, tlsCfg)
		_ = tconn.SetDeadline(time.Now().Add(handshakeTimeout))
		if err := tconn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		_ = tconn.SetDeadline(time.Time{})
		return tconn, nil
	}

	id, err := tlsutil.ClientHelloID(fpName)
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	utls.EnableWeakCiphers()

	// Real ECH (Xray-compatible MITM_ECH_CONFIG_LIST) takes priority over the
	// GREASE-only option. With ECH active the SNI travels encrypted in the
	// inner hello; the outer hello carries the config's public_name. Note the
	// plaintext serverName passed in becomes the inner (protected) SNI.
	uTLSConfig := &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         alpn,
	}
	if echConfigList != "" {
		cfg, failClosed, echErr := applyECH(echConfigList, echForceQuery, serverName)
		if echErr != nil && failClosed {
			log.Printf("[ECH] config fetch failed (force-query=full): %v — connection will fail closed", echErr)
		} else if echErr != nil {
			log.Printf("[ECH] config fetch failed, falling back to plain TLS: %v", echErr)
		}
		if cfg != nil {
			// With ECH the inner hello carries the client's forwarded ALPN
			// (the outer hello keeps the fingerprint's own ALPN list, which
			// is what the censor sees). xray forces http/1.1 here because
			// its upstream never forwards client ALPN; our MITM does.
			uTLSConfig.EncryptedClientHelloConfigList = cfg
		}
	}

	uconn := utls.UClient(raw, uTLSConfig, id)
	uconn.SetSNI(serverName)
	_ = uconn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	_ = uconn.SetDeadline(time.Time{})
	return uconn, nil
}