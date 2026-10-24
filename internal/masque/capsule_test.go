package masque

import (
	"bytes"
	"net"
	"testing"
)

func TestCapsuleRoundTrip(t *testing.T) {
	types := []uint64{CapsuleDatagram, CapsuleAddressAssign, CapsuleAddressRequest, CapsuleRouteAdvertisement, 999}
	values := [][]byte{
		{},
		[]byte("hello"),
		[]byte("some binary data \x00\x01\xff"),
	}

	for _, typ := range types {
		for _, val := range values {
			encoded := EncodeCapsule(typ, val)
			parser := NewParser(256 * 1024)
			if _, err := parser.Write(encoded); err != nil {
				t.Fatal(err)
			}
			cap, ok, err := parser.Next()
			if err != nil || !ok {
				t.Fatalf("failed to parse capsule type %d: err=%v, ok=%v", typ, err, ok)
			}
			if cap.Type != typ {
				t.Fatalf("expected type %d, got %d", typ, cap.Type)
			}
			if !bytes.Equal(cap.Value, val) {
				t.Fatalf("expected value %x, got %x", val, cap.Value)
			}
		}
	}
}

func TestParserByteByByteAndBatched(t *testing.T) {
	c1 := EncodeCapsule(CapsuleDatagram, []byte("one"))
	c2 := EncodeCapsule(CapsuleAddressAssign, []byte("two"))
	combined := append(c1, c2...)

	// Test byte-by-byte
	p1 := NewParser(256 * 1024)
	var parsed []Capsule
	for _, b := range combined {
		_, _ = p1.Write([]byte{b})
		for {
			c, ok, err := p1.Next()
			if err != nil {
				t.Fatal(err)
			}
			if !ok {
				break
			}
			parsed = append(parsed, c)
		}
	}

	if len(parsed) != 2 {
		t.Fatalf("expected 2 parsed capsules, got %d", len(parsed))
	}
	if parsed[0].Type != CapsuleDatagram || !bytes.Equal(parsed[0].Value, []byte("one")) {
		t.Fatalf("mismatch in first capsule")
	}
	if parsed[1].Type != CapsuleAddressAssign || !bytes.Equal(parsed[1].Value, []byte("two")) {
		t.Fatalf("mismatch in second capsule")
	}
}

func TestParserBufferLimitExceeded(t *testing.T) {
	p := NewParser(10) // small buffer limit
	// Declare length 100 which exceeds maxBuffer 10
	badCapsule := EncodeCapsule(CapsuleDatagram, make([]byte, 100))
	_, err := p.Write(badCapsule)
	if err == nil {
		t.Fatalf("expected buffer limit error")
	}
}

func TestDatagramContextID(t *testing.T) {
	payload := []byte("tun-packet")
	dg0 := EncodeDatagram(ContextIDIP, payload)
	ctxID, data, err := DecodeDatagram(dg0)
	if err != nil || ctxID != ContextIDIP || !bytes.Equal(data, payload) {
		t.Fatalf("datagram context 0 failed: err=%v, ctxID=%d", err, ctxID)
	}

	dg1 := EncodeDatagram(42, payload)
	ctxID1, data1, err := DecodeDatagram(dg1)
	if err != nil || ctxID1 != 42 || !bytes.Equal(data1, payload) {
		t.Fatalf("datagram context 42 failed: err=%v, ctxID=%d", err, ctxID1)
	}
}

func TestAddressAssignRoundTrip(t *testing.T) {
	assignments := []AddressAssignment{
		{RequestID: 1, IPVersion: 4, IPAddress: net.ParseIP("192.0.2.1"), PrefixLength: 24},
		{RequestID: 2, IPVersion: 6, IPAddress: net.ParseIP("2001:db8::1"), PrefixLength: 64},
	}

	encoded := EncodeAddressAssign(assignments)
	decoded, err := DecodeAddressAssign(encoded)
	if err != nil {
		t.Fatalf("decode address assign failed: %v", err)
	}
	if len(decoded) != 2 {
		t.Fatalf("expected 2 assignments, got %d", len(decoded))
	}
	if decoded[0].IPVersion != 4 || !decoded[0].IPAddress.Equal(net.ParseIP("192.0.2.1")) || decoded[0].PrefixLength != 24 {
		t.Fatalf("IPv4 assignment mismatch: %+v", decoded[0])
	}
	if decoded[1].IPVersion != 6 || !decoded[1].IPAddress.Equal(net.ParseIP("2001:db8::1")) || decoded[1].PrefixLength != 64 {
		t.Fatalf("IPv6 assignment mismatch: %+v", decoded[1])
	}
}

func TestAddressAssignValidationErrors(t *testing.T) {
	// Bad IP version (e.g. 5)
	badVer := []byte{0x01, 0x05, 1, 2, 3, 4, 24}
	if _, err := DecodeAddressAssign(badVer); err == nil {
		t.Fatalf("expected error for bad IP version")
	}

	// Prefix length too large for IPv4 (>32)
	badPrefix := []byte{0x01, 0x04, 192, 0, 2, 1, 33}
	if _, err := DecodeAddressAssign(badPrefix); err == nil {
		t.Fatalf("expected error for prefix length > 32")
	}
}

func TestRouteAdvertisementValidation(t *testing.T) {
	// Start greater than end
	routes := []RouteAdvertisement{
		{
			IPVersion:  4,
			StartIP:    net.ParseIP("192.0.2.10"),
			EndIP:      net.ParseIP("192.0.2.1"),
			IPProtocol: 6,
		},
	}
	encoded := EncodeRouteAdvertisement(routes)
	if _, err := DecodeRouteAdvertisement(encoded); err == nil {
		t.Fatalf("expected error when start IP > end IP")
	}
}

func FuzzParser(f *testing.F) {
	f.Add([]byte{0x00, 0x05, 'h', 'e', 'l', 'l', 'o'})
	f.Fuzz(func(t *testing.T, data []byte) {
		p := NewParser(1024)
		_, _ = p.Write(data)
		for {
			_, ok, err := p.Next()
			if err != nil || !ok {
				break
			}
		}
	})
}

func FuzzDecodeAddressAssign(f *testing.F) {
	f.Add([]byte{0x01, 0x04, 192, 0, 2, 1, 24})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeAddressAssign(data)
	})
}
