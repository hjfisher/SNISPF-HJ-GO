package forward

import (
	"log"
	"net"
	"time"

	"snispf-hj-go/internal/tlsutil"
)

// RawInjector is the interface the bypass strategies need from the Linux raw
// packet injector (waiting for the server to confirm it ignored the fake).
type RawInjector interface {
	WaitForConfirmation(localPort int, timeout time.Duration) bool
	CleanupPort(localPort int)
	Start() bool
	Stop()
}

// BypassStrategy applies a DPI bypass technique to an outgoing connection.
type BypassStrategy interface {
	Name() string
	// Apply sends the client's first data (normally a TLS ClientHello) to the
	// server using the strategy. Returns error on failure.
	Apply(server net.Conn, fakeSNI string, firstData []byte) error
}

// DirectBypass forwards the client's data unmodified — no SNI spoofing.
type DirectBypass struct{}

func (DirectBypass) Name() string { return "direct" }

func (DirectBypass) Apply(server net.Conn, fakeSNI string, firstData []byte) error {
	_, err := server.Write(firstData)
	return err
}

// FragmentBypass splits the real ClientHello so DPI cannot read the SNI.
type FragmentBypass struct {
	Strategy      string
	FragmentDelay time.Duration
	TCPNoDelay    bool
}

func (FragmentBypass) Name() string { return "fragment" }

func (b *FragmentBypass) Apply(server net.Conn, fakeSNI string, firstData []byte) error {
	tcp, ok := server.(*net.TCPConn)
	if ok && b.TCPNoDelay {
		_ = tcp.SetNoDelay(true)
	}
	fragments := tlsutil.FragmentClientHello(firstData, b.Strategy)
	for i, fragment := range fragments {
		if _, err := server.Write(fragment); err != nil {
			return err
		}
		if i < len(fragments)-1 && b.FragmentDelay > 0 {
			time.Sleep(b.FragmentDelay)
		}
	}
	if ok && b.TCPNoDelay {
		_ = tcp.SetNoDelay(false)
	}
	return nil
}

// FakeSNIBypass injects a fake ClientHello via the raw injector (out-of-window
// seq trick) or falls back to fragmenting the real hello.
type FakeSNIBypass struct {
	RawInjector   RawInjector
	FragmentReal  bool
	FragmentStrat string
	RealFragDelay time.Duration
}

func (FakeSNIBypass) Name() string { return "fake_sni" }

func (b *FakeSNIBypass) Apply(server net.Conn, fakeSNI string, firstData []byte) error {
	if b.RawInjector != nil {
		return b.rawInjectSend(server, firstData)
	}
	return b.fragmentFallback(server, firstData)
}

func (b *FakeSNIBypass) rawInjectSend(server net.Conn, firstData []byte) error {
	localPort := server.LocalAddr().(*net.TCPAddr).Port
	confirmed := b.RawInjector.WaitForConfirmation(localPort, 2*time.Second)
	if !confirmed {
		log.Printf("port=%d: server did not confirm fake was ignored (timeout). Sending real data anyway.", localPort)
	}
	tcp, _ := server.(*net.TCPConn)
	if b.FragmentReal {
		if tcp != nil {
			_ = tcp.SetNoDelay(true)
		}
		fragments := tlsutil.FragmentClientHello(firstData, b.FragmentStrat)
		for i, fragment := range fragments {
			if _, err := server.Write(fragment); err != nil {
				return err
			}
			if i < len(fragments)-1 && b.RealFragDelay > 0 {
				time.Sleep(b.RealFragDelay)
			}
		}
		if tcp != nil {
			_ = tcp.SetNoDelay(false)
		}
	} else {
		_, err := server.Write(firstData)
		return err
	}
	return nil
}

func (b *FakeSNIBypass) fragmentFallback(server net.Conn, firstData []byte) error {
	tcp, _ := server.(*net.TCPConn)
	if tcp != nil {
		_ = tcp.SetNoDelay(true)
	}
	fragments := tlsutil.FragmentClientHello(firstData, "sni_split")
	for i, fragment := range fragments {
		if _, err := server.Write(fragment); err != nil {
			return err
		}
		if i < len(fragments)-1 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if tcp != nil {
		_ = tcp.SetNoDelay(false)
	}
	return nil
}

// CombinedBypass combines raw-injection and fragmentation.
type CombinedBypass struct {
	FragmentStrat string
	FragmentDelay time.Duration
	RawInjector   RawInjector
}

func (CombinedBypass) Name() string { return "combined" }

func (b *CombinedBypass) Apply(server net.Conn, fakeSNI string, firstData []byte) error {
	tcp, _ := server.(*net.TCPConn)
	if tcp != nil {
		_ = tcp.SetNoDelay(true)
	}
	if b.RawInjector != nil {
		localPort := server.LocalAddr().(*net.TCPAddr).Port
		if !b.RawInjector.WaitForConfirmation(localPort, 2*time.Second) {
			log.Printf("port=%d: no confirmation that server ignored the fake packet (timeout)", localPort)
		}
	}
	fragments := tlsutil.FragmentClientHello(firstData, b.FragmentStrat)
	for i, fragment := range fragments {
		if _, err := server.Write(fragment); err != nil {
			return err
		}
		if i < len(fragments)-1 && b.FragmentDelay > 0 {
			time.Sleep(b.FragmentDelay)
		}
	}
	if tcp != nil {
		_ = tcp.SetNoDelay(false)
	}
	return nil
}

// SetRawInjector updates the raw injector used by this strategy.
// Used when network interface changes and a new raw injector is created.
func (b *FakeSNIBypass) SetRawInjector(inj RawInjector) {
	b.RawInjector = inj
}

// SetRawInjector updates the raw injector used by this strategy.
// Used when network interface changes and a new raw injector is created.
func (b *CombinedBypass) SetRawInjector(inj RawInjector) {
	b.RawInjector = inj
}
