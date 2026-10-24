package masque

import (
	"bytes"
	"errors"
	"fmt"
	"net"
)

const (
	CapsuleDatagram           = 0x00
	CapsuleAddressAssign      = 0x01
	CapsuleAddressRequest     = 0x02
	CapsuleRouteAdvertisement = 0x03

	ContextIDIP             = 0
	DefaultMaxCapsuleBuffer = 256 * 1024 // 256 KiB
)

type Capsule struct {
	Type  uint64
	Value []byte
}

// EncodeCapsule encodes a capsule with type and value into wire format.
func EncodeCapsule(typ uint64, value []byte) []byte {
	var dst []byte
	dst = AppendVarint(dst, typ)
	dst = AppendVarint(dst, uint64(len(value)))
	dst = append(dst, value...)
	return dst
}

// Parser is a streaming parser for HTTP/2 capsules (RFC 9297).
type Parser struct {
	buf       bytes.Buffer
	maxBuffer int
}

func NewParser(maxBuffer int) *Parser {
	if maxBuffer <= 0 {
		maxBuffer = DefaultMaxCapsuleBuffer
	}
	return &Parser{maxBuffer: maxBuffer}
}

func (p *Parser) Write(data []byte) (int, error) {
	if p.buf.Len()+len(data) > p.maxBuffer {
		return 0, fmt.Errorf("capsule parser buffer exceeded limit (%d bytes)", p.maxBuffer)
	}
	return p.buf.Write(data)
}

// Next attempts to read the next complete capsule from the buffer.
// Returns (capsule, true, nil) if a capsule is parsed, (Capsule{}, false, nil) if not enough data,
// or (Capsule{}, false, err) if a protocol error occurs.
func (p *Parser) Next() (Capsule, bool, error) {
	b := p.buf.Bytes()
	if len(b) == 0 {
		return Capsule{}, false, nil
	}

	// Try reading capsule type
	typ, nType, err := ReadVarint(b)
	if err != nil {
		if errors.Is(err, ErrVarintUnderflow) {
			return Capsule{}, false, nil
		}
		return Capsule{}, false, err
	}

	rem := b[nType:]
	length, nLen, err := ReadVarint(rem)
	if err != nil {
		if errors.Is(err, ErrVarintUnderflow) {
			return Capsule{}, false, nil
		}
		return Capsule{}, false, err
	}

	if length > uint64(p.maxBuffer) {
		return Capsule{}, false, fmt.Errorf("declared capsule length %d exceeds buffer limit %d", length, p.maxBuffer)
	}

	totalHeaderLen := nType + nLen
	totalLen := totalHeaderLen + int(length)

	if len(b) < totalLen {
		return Capsule{}, false, nil // not enough data yet
	}

	// Consume the complete capsule from buffer
	valueCopy := make([]byte, length)
	copy(valueCopy, b[totalHeaderLen:totalLen])

	// Advance buffer
	p.buf.Next(totalLen)

	return Capsule{Type: typ, Value: valueCopy}, true, nil
}

// Datagram decoding and encoding (RFC 9297)
func DecodeDatagram(value []byte) (contextID uint64, payload []byte, err error) {
	ctxID, n, err := ReadVarint(value)
	if err != nil {
		return 0, nil, err
	}
	return ctxID, value[n:], nil
}

func EncodeDatagram(contextID uint64, payload []byte) []byte {
	var dst []byte
	dst = AppendVarint(dst, contextID)
	dst = append(dst, payload...)
	return dst
}

// Address Assignment / Request structures and codecs (RFC 9484 sections 4.7 & 4.8)
type AddressAssignment struct {
	RequestID    uint64
	IPVersion    byte // 4 or 6
	IPAddress    net.IP
	PrefixLength byte
}

func decodeAddressEntries(value []byte) ([]AddressAssignment, error) {
	var assignments []AddressAssignment
	buf := bytes.NewBuffer(value)

	for buf.Len() > 0 {
		reqID, n, err := ReadVarint(buf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("read request ID: %w", err)
		}
		buf.Next(n)

		if buf.Len() < 1 {
			return nil, errors.New("truncated address entry: missing IP version")
		}
		ipVer := buf.Next(1)[0]
		if ipVer != 4 && ipVer != 6 {
			return nil, fmt.Errorf("unsupported IP version %d", ipVer)
		}

		addrLen := 4
		maxPrefix := 32
		if ipVer == 6 {
			addrLen = 16
			maxPrefix = 128
		}

		if buf.Len() < addrLen {
			return nil, fmt.Errorf("truncated IP address for version %d", ipVer)
		}
		addrBytes := buf.Next(addrLen)

		if buf.Len() < 1 {
			return nil, errors.New("truncated address entry: missing prefix length")
		}
		prefLen := buf.Next(1)[0]
		if int(prefLen) > maxPrefix {
			return nil, fmt.Errorf("prefix length %d exceeds max %d for IPv%d", prefLen, maxPrefix, ipVer)
		}

		assignments = append(assignments, AddressAssignment{
			RequestID:    reqID,
			IPVersion:    ipVer,
			IPAddress:    net.IP(addrBytes),
			PrefixLength: prefLen,
		})
	}

	return assignments, nil
}

func encodeAddressEntries(assignments []AddressAssignment) []byte {
	var buf bytes.Buffer
	for _, a := range assignments {
		buf.Write(AppendVarint(nil, a.RequestID))
		buf.WriteByte(a.IPVersion)
		ip := a.IPAddress.To4()
		if a.IPVersion == 6 {
			ip = a.IPAddress.To16()
		}
		if ip == nil {
			ip = a.IPAddress
		}
		buf.Write(ip)
		buf.WriteByte(a.PrefixLength)
	}
	return buf.Bytes()
}

func DecodeAddressAssign(value []byte) ([]AddressAssignment, error) {
	return decodeAddressEntries(value)
}

func EncodeAddressAssign(assignments []AddressAssignment) []byte {
	return encodeAddressEntries(assignments)
}

func DecodeAddressRequest(value []byte) ([]AddressAssignment, error) {
	return decodeAddressEntries(value)
}

func EncodeAddressRequest(requests []AddressAssignment) []byte {
	return encodeAddressEntries(requests)
}

// Route Advertisement structures and codecs (RFC 9484 section 4.9)
type RouteAdvertisement struct {
	IPVersion  byte // 4 or 6
	StartIP    net.IP
	EndIP      net.IP
	IPProtocol uint64
}

func DecodeRouteAdvertisement(value []byte) ([]RouteAdvertisement, error) {
	var routes []RouteAdvertisement
	buf := bytes.NewBuffer(value)

	for buf.Len() > 0 {
		if buf.Len() < 1 {
			return nil, errors.New("truncated route entry: missing IP version")
		}
		ipVer := buf.Next(1)[0]
		if ipVer != 4 && ipVer != 6 {
			return nil, fmt.Errorf("unsupported route IP version %d", ipVer)
		}

		addrLen := 4
		if ipVer == 6 {
			addrLen = 16
		}

		if buf.Len() < addrLen*2 {
			return nil, errors.New("truncated route start/end addresses")
		}
		startBytes := buf.Next(addrLen)
		endBytes := buf.Next(addrLen)

		proto, n, err := ReadVarint(buf.Bytes())
		if err != nil {
			return nil, fmt.Errorf("read route IP protocol: %w", err)
		}
		buf.Next(n)

		startIP := net.IP(startBytes)
		endIP := net.IP(endBytes)

		if bytes.Compare(startIP, endIP) > 0 {
			return nil, fmt.Errorf("start IP %s greater than end IP %s", startIP, endIP)
		}

		routes = append(routes, RouteAdvertisement{
			IPVersion:  ipVer,
			StartIP:    startIP,
			EndIP:      endIP,
			IPProtocol: proto,
		})
	}

	return routes, nil
}

func EncodeRouteAdvertisement(routes []RouteAdvertisement) []byte {
	var buf bytes.Buffer
	for _, rt := range routes {
		buf.WriteByte(rt.IPVersion)
		addrLen := 4
		if rt.IPVersion == 6 {
			addrLen = 16
		}
		startIP := rt.StartIP
		if rt.IPVersion == 4 {
			startIP = startIP.To4()
		} else {
			startIP = startIP.To16()
		}
		if startIP == nil {
			startIP = rt.StartIP
		}
		buf.Write(startIP[:addrLen])

		endIP := rt.EndIP
		if rt.IPVersion == 4 {
			endIP = endIP.To4()
		} else {
			endIP = endIP.To16()
		}
		if endIP == nil {
			endIP = rt.EndIP
		}
		buf.Write(endIP[:addrLen])

		buf.Write(AppendVarint(nil, rt.IPProtocol))
	}
	return buf.Bytes()
}
