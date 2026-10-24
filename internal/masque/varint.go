package masque

import (
	"errors"
	"io"
)

var (
	ErrVarintOverflow  = errors.New("varint exceeds 2^62-1")
	ErrVarintUnderflow = io.ErrUnexpectedEOF
)

// AppendVarint appends the varint encoding of v to dst in RFC 9000 format (shortest form).
func AppendVarint(dst []byte, v uint64) []byte {
	if v < 64 {
		return append(dst, byte(v))
	} else if v < 16384 {
		val := uint16(v) | 0x4000
		return append(dst, byte(val>>8), byte(val))
	} else if v < 1073741824 {
		val := uint32(v) | 0x80000000
		return append(dst, byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
	} else if v < (1 << 62) {
		val := v | 0xC000000000000000
		return append(dst,
			byte(val>>56), byte(val>>48), byte(val>>40), byte(val>>32),
			byte(val>>24), byte(val>>16), byte(val>>8), byte(val),
		)
	} else {
		panic("varint overflow (> 2^62-1)")
	}
}

// ReadVarint decodes an RFC 9000 variable-length integer from b.
// Returns the value, number of bytes consumed (n), and error if any.
// It accepts non-shortest form encodings per RFC 9000 rules.
func ReadVarint(b []byte) (v uint64, n int, err error) {
	if len(b) == 0 {
		return 0, 0, ErrVarintUnderflow
	}

	first := b[0]
	prefix := first >> 6
	length := 1 << prefix // 1, 2, 4, or 8

	if len(b) < length {
		return 0, 0, ErrVarintUnderflow
	}

	switch length {
	case 1:
		v = uint64(first & 0x3F)
	case 2:
		v = uint64(first&0x3F)<<8 | uint64(b[1])
	case 4:
		v = uint64(first&0x3F)<<24 | uint64(b[1])<<16 | uint64(b[2])<<8 | uint64(b[3])
	case 8:
		v = uint64(first&0x3F)<<56 |
			uint64(b[1])<<48 |
			uint64(b[2])<<40 |
			uint64(b[3])<<32 |
			uint64(b[4])<<24 |
			uint64(b[5])<<16 |
			uint64(b[6])<<8 |
			uint64(b[7])
	}

	if v >= (1 << 62) {
		return 0, length, ErrVarintOverflow
	}

	return v, length, nil
}
