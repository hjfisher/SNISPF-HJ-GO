package mitm

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"

	"snispf-hj-go/internal/finalmask"
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
}

// maskedConn wraps the upstream socket so every write is routed through a
// per-connection FinalMasker. This puts the mask at the wire level, which
// means the upstream TLS handshake flight — the ClientHello carrying the
// SNI — is fragmented before DPI can read it (mirrors xray finalmask
// semantics: the masker sits on the outbound socket for the connection's
// lifetime; rules like "tlshello" / "1-3" simply stop applying once their
// write window passes).
type maskedConn struct {
	net.Conn
	masker *finalmask.FinalMasker
}

func (c *maskedConn) Write(b []byte) (int, error) {
	if c.masker == nil {
		return c.Conn.Write(b)
	}
	if err := c.masker.Send(func(p []byte) error {
		_, werr := c.Conn.Write(p)
		return werr
	}, b); err != nil {
		return 0, err
	}
	return len(b), nil
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

	up, err := openUpstream(ctx, activeIP, opts.ConnectPort, serverName, upALPN, opts.Fingerprint, opts.CipherSuites, maskerTemplate)
	if err != nil {
		log.Printf("[%s] upstream connect %s:%d failed: %v", peer, activeIP, opts.ConnectPort, err)
		releasePair(true)
		_ = tconn.Close()
		return
	}
	defer up.Close()

	loss := ""
	if pair != nil {
		loss = fmt.Sprintf(" | pool_loss=%.1f%%", pair.CombinedLossRate()*100)
	}
	log.Printf("[%s] MITM relay: client=%s sni=%s alpn=%s -> %s:%d sni=%s cipherSuites=%v fingerprint=%s finalmask=%d layer(s)%s",
		peer, peer, clientSNI, clientALPN, activeIP, opts.ConnectPort, serverName, opts.CipherSuites, opts.Fingerprint, maskerTemplate.LayerCount(), loss)

	done := make(chan struct{})
	var serverRespondedMu sync.Mutex
	serverResponded := false

	var wg sync.WaitGroup
	wg.Add(2)

	// C->S (finalmask fragmentation is applied inside maskedConn on the wire)
	go func() {
		defer wg.Done()
		buf := make([]byte, bufferSize)
		for {
			n, err := reader.Read(buf)
			if n > 0 {
				if _, wErr := up.Write(buf[:n]); wErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
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
		done <- struct{}{}
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
// The raw socket is wrapped in a maskedConn so the handshake flight —
// including the ClientHello that carries the SNI — passes through
// finalmask fragmentation on the wire, and every later C->S write too.
func openUpstream(ctx context.Context, activeIP string, connectPort int, serverName string, alpn []string, fingerprint string, cipherSuites []uint16, maskerTemplate *finalmask.FinalMasker) (net.Conn, error) {
	raw, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(activeIP, strconv.Itoa(connectPort)))
	if err != nil {
		return nil, err
	}
	var upstreamConn net.Conn = raw
	upstreamConn = &maskedConn{Conn: raw, masker: maskerTemplate.Clone()}

	fpName := tlsutil.ResolveFingerprint(fingerprint)
	if fpName == "" {
		tconn := tls.Client(upstreamConn, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
			NextProtos:         alpn,
			CipherSuites:       cipherSuites,
		})
		_ = tconn.SetDeadline(time.Now().Add(handshakeTimeout))
		if err := tconn.HandshakeContext(ctx); err != nil {
			_ = upstreamConn.Close()
			return nil, err
		}
		_ = tconn.SetDeadline(time.Time{})
		return tconn, nil
	}

	id, err := tlsutil.ClientHelloID(fpName)
	if err != nil {
		_ = upstreamConn.Close()
		return nil, err
	}
	utls.EnableWeakCiphers()
	uconn := utls.UClient(upstreamConn, &utls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true,
		NextProtos:         alpn,
	}, id)
	uconn.SetSNI(serverName)
	_ = uconn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err := uconn.HandshakeContext(ctx); err != nil {
		_ = upstreamConn.Close()
		return nil, err
	}
	_ = uconn.SetDeadline(time.Time{})
	return uconn, nil
}
