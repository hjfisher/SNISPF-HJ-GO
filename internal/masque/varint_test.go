package masque

import (
	"bytes"
	"testing"
)

func TestVarintRFC9000Vectors(t *testing.T) {
	vectors := []struct {
		hexEncoded []byte
		val        uint64
	}{
		{[]byte{0x25}, 37},
		{[]byte{0x7b, 0xbd}, 15293},
		{[]byte{0x9d, 0x7f, 0x3e, 0x7d}, 494878333},
		{[]byte{0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c}, 151288809941952652},
	}

	for _, tc := range vectors {
		v, n, err := ReadVarint(tc.hexEncoded)
		if err != nil {
			t.Fatalf("ReadVarint failed for %x: %v", tc.hexEncoded, err)
		}
		if n != len(tc.hexEncoded) {
			t.Fatalf("expected consumed bytes %d, got %d", len(tc.hexEncoded), n)
		}
		if v != tc.val {
			t.Fatalf("expected value %d, got %d", tc.val, v)
		}

		encoded := AppendVarint(nil, tc.val)
		if !bytes.Equal(encoded, tc.hexEncoded) {
			t.Fatalf("AppendVarint(%d) = %x, want %x", tc.val, encoded, tc.hexEncoded)
		}
	}
}

func TestVarintShortestFormBoundaries(t *testing.T) {
	boundaries := []struct {
		val         uint64
		expectedLen int
	}{
		{0, 1},
		{63, 1},
		{64, 2},
		{16383, 2},
		{16384, 4},
		{1073741823, 4},
		{1073741824, 8},
		{(1 << 62) - 1, 8},
	}

	for _, b := range boundaries {
		enc := AppendVarint(nil, b.val)
		if len(enc) != b.expectedLen {
			t.Fatalf("val %d: expected encoded length %d, got %d", b.val, b.expectedLen, len(enc))
		}
		v, n, err := ReadVarint(enc)
		if err != nil || v != b.val || n != b.expectedLen {
			t.Fatalf("roundtrip fail for %d: v=%d, n=%d, err=%v", b.val, v, n, err)
		}
	}
}

func TestVarintOverflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic for varint >= 2^62")
		}
	}()
	AppendVarint(nil, 1<<62)
}

func TestVarintTruncatedInput(t *testing.T) {
	// 4-byte varint prefix (0x80) but only 2 bytes provided
	truncated := []byte{0x80, 0x01}
	_, _, err := ReadVarint(truncated)
	if err == nil {
		t.Fatalf("expected underflow/unexpected EOF error")
	}
}

func TestNonShortestFormDecoderAccepted(t *testing.T) {
	// Value 37 encoded in 2 bytes (0x4025 instead of 0x25)
	nonShortest := []byte{0x40, 0x25}
	v, n, err := ReadVarint(nonShortest)
	if err != nil {
		t.Fatalf("decoder should accept non-shortest form: %v", err)
	}
	if v != 37 || n != 2 {
		t.Fatalf("expected v=37, n=2, got v=%d, n=%d", v, n)
	}
}
