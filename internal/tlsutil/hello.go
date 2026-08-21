package tlsutil

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
)

// ClientHelloBuilder constructs TLS 1.3 ClientHello records with customizable
// SNI fields for DPI bypass purposes. It is a faithful port of the Python
// builder in sni_spoofing/tls/__init__.py.
type ClientHelloBuilder struct{}

// Pre-built template parts from the original tool.
var defaultCipherSuites = mustHex("" +
	"0024" + // length = 36 bytes (18 cipher suites x 2)
	"1302" + // TLS_AES_256_GCM_SHA384
	"1303" + // TLS_CHACHA20_POLY1305_SHA256
	"1301" + // TLS_AES_128_GCM_SHA256
	"c02c" + // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
	"c030" + // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	"c02b" + // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
	"c02f" + // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	"cca9" + // TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
	"cca8" + // TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
	"c024" + // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
	"c028" + // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
	"c023" + // TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
	"c027" + // TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
	"009f" + // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
	"009e" + // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
	"006b" + // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
	"0067" + // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
	"00ff") // TLS_EMPTY_RENEGOTIATION_INFO_SCSV

var supportedGroups = mustHex("" +
	"000a" + // extension type: supported_groups
	"0016" + // length
	"0014" + // list length
	"001d" + // x25519
	"0017" + // secp256r1
	"001e" + // x448
	"0019" + // secp521r1
	"0018" + // secp384r1
	"0100" + // ffdhe2048
	"0101" + // ffdhe3072
	"0102" + // ffdhe4096
	"0103" + // ffdhe6144
	"0104") // ffdhe8192

var signatureAlgorithms = mustHex("" +
	"000d" + // extension type: signature_algorithms
	"002a" + // length
	"0028" + // list length
	"0403" + // ecdsa_secp256r1_sha256
	"0503" + // ecdsa_secp384r1_sha384
	"0603" + // ecdsa_secp521r1_sha512
	"0807" + // ed25519
	"0808" + // ed448
	"0809" + "080a" + "080b" +
	"0804" + // rsa_pss_rsae_sha256
	"0805" + // rsa_pss_rsae_sha384
	"0806" + // rsa_pss_rsae_sha512
	"0401" + // rsa_pkcs1_sha256
	"0501" + // rsa_pkcs1_sha384
	"0601" + // rsa_pkcs1_sha512
	"0303" + "0301" + "0302" + "0402" + "0502" + "0602")

var ecPointFormats = mustHex("" +
	"000b" + // extension type: ec_point_formats
	"0004" + // length
	"0300" + // list length + uncompressed
	"0102") // ansiX962_compressed_prime + ansiX962_compressed_char2

var sessionTicket = mustHex("0023" + "0000") // session_ticket, length 0

var alpnExt = mustHex("" +
	"0010" + // extension type: ALPN
	"000e" + // length
	"000c" + // protocols length
	"0268" + // length + 'h'
	"3208" + // '2' + length
	"6874" + // 'ht'
	"7470" + // 'tp'
	"2f31" + // '/1'
	"2e31") // '.1'

var encryptThenMac = mustHex("0016" + "0000")

var extendedMasterSecret = mustHex("0017" + "0000")

var supportedVersions = mustHex("" +
	"002b" + // extension type: supported_versions
	"0005" + // length: 5 bytes of data follow
	"04" + // supported_versions list length: 4 bytes (2 versions x 2 bytes)
	"0304" + // TLS 1.3
	"0303") // TLS 1.2

var pskKeyExchange = mustHex("002d" + "0002" + "0101") // psk_dhe_ke

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func u16(v int) []byte {
	return []byte{byte(v >> 8), byte(v)}
}

// BuildSNIExtension builds the SNI (Server Name Indication) extension.
func (ClientHelloBuilder) BuildSNIExtension(sni string) []byte {
	sniBytes := []byte(sni)
	entry := append(u16(0), u16(len(sniBytes))...)
	entry = append(entry, sniBytes...)
	nameList := append(u16(len(entry)), entry...)
	return append(u16(0x0000), append(u16(len(nameList)), nameList...)...)
}

// BuildKeyShareExtension builds the key_share extension with an x25519 key.
func (ClientHelloBuilder) BuildKeyShareExtension(publicKey []byte) []byte {
	if len(publicKey) == 0 {
		publicKey = make([]byte, 32)
		_, _ = rand.Read(publicKey)
	}
	entry := append(u16(0x001D), u16(len(publicKey))...)
	entry = append(entry, publicKey...)
	data := append(u16(len(entry)), entry...)
	return append(u16(0x0033), append(u16(len(data)), data...)...)
}

// BuildPaddingExtension builds a padding extension to reach a target size.
func (ClientHelloBuilder) BuildPaddingExtension(targetLength, currentLength int) []byte {
	paddingNeeded := targetLength - currentLength - 4
	if paddingNeeded < 0 {
		return nil
	}
	ext := append(u16(0x0015), u16(paddingNeeded)...)
	pad := make([]byte, paddingNeeded)
	return append(ext, pad...)
}

// BuildClientHelloRecord builds a complete fake ClientHello with the given
// SNI (default target size 517, optional cipher-suite IDs). Convenience
// wrapper used by the raw injector for the decoy hello.
func BuildClientHelloRecord(sni string, cipherSuiteIDs []uint16) []byte {
	return (ClientHelloBuilder{}).BuildClientHello(sni, nil, nil, nil, 517, cipherSuiteIDs)
}

// BuildClientHello builds a complete TLS ClientHello record.
//
//   - sni: the Server Name Indication to include
//   - sessionID: 32-byte session ID (random if nil)
//   - randomBytes: 32-byte client random (random if nil)
//   - keyShare: 32-byte x25519 public key (random if nil)
//   - targetSize: target total size for the TLS record (default 517)
//   - cipherSuites: optional parsed suite IDs (or nil for built-in list)
func (ClientHelloBuilder) BuildClientHello(sni string, sessionID, randomBytes, keyShare []byte, targetSize int, cipherSuites []uint16) []byte {
	if targetSize <= 0 {
		targetSize = 517
	}
	if len(sessionID) == 0 {
		sessionID = make([]byte, 32)
		_, _ = rand.Read(sessionID)
	}
	if len(randomBytes) == 0 {
		randomBytes = make([]byte, 32)
		_, _ = rand.Read(randomBytes)
	}
	var csField []byte
	if len(cipherSuites) > 0 {
		csField = BuildCipherSuitesField(cipherSuites)
	} else {
		csField = defaultCipherSuites
	}

	clientVersion := []byte{0x03, 0x03}
	sessionIDField := append([]byte{byte(len(sessionID))}, sessionID...)
	compression := []byte{0x01, 0x00}

	sniExt := (ClientHelloBuilder{}).BuildSNIExtension(sni)
	keyShareExt := (ClientHelloBuilder{}).BuildKeyShareExtension(keyShare)

	var extensions []byte
	extensions = append(extensions, sniExt...)
	extensions = append(extensions, ecPointFormats...)
	extensions = append(extensions, supportedGroups...)
	extensions = append(extensions, sessionTicket...)
	extensions = append(extensions, alpnExt...)
	extensions = append(extensions, encryptThenMac...)
	extensions = append(extensions, extendedMasterSecret...)
	extensions = append(extensions, signatureAlgorithms...)
	extensions = append(extensions, supportedVersions...)
	extensions = append(extensions, pskKeyExchange...)
	extensions = append(extensions, keyShareExt...)

	handshakeBodyNoPad := append([]byte{}, clientVersion...)
	handshakeBodyNoPad = append(handshakeBodyNoPad, randomBytes...)
	handshakeBodyNoPad = append(handshakeBodyNoPad, sessionIDField...)
	handshakeBodyNoPad = append(handshakeBodyNoPad, csField...)
	handshakeBodyNoPad = append(handshakeBodyNoPad, compression...)

	totalSoFar := 4 + len(handshakeBodyNoPad) + 2 + len(extensions)
	recordSoFar := 5 + totalSoFar

	paddingExt := (ClientHelloBuilder{}).BuildPaddingExtension(targetSize, recordSoFar)
	extensions = append(extensions, paddingExt...)

	extensionsWithLen := append(u16(len(extensions)), extensions...)
	handshakeBody := append(handshakeBodyNoPad, extensionsWithLen...)

	hsLen := len(handshakeBody)
	handshake := []byte{0x01, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)}
	handshake = append(handshake, handshakeBody...)

	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	record = append(record, handshake...)
	return record
}

// BuildClientResponse builds a fake TLS client response (ChangeCipherSpec +
// ApplicationData).
func (ClientHelloBuilder) BuildClientResponse(randomBytes []byte) []byte {
	if len(randomBytes) == 0 {
		randomBytes = make([]byte, 32)
		_, _ = rand.Read(randomBytes)
	}
	ccs := []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01}
	appData := []byte{0x17, 0x03, 0x03, byte(len(randomBytes) >> 8), byte(len(randomBytes))}
	appData = append(appData, randomBytes...)
	return append(ccs, appData...)
}

// ClientHelloInfo holds the parsed fields of a TLS ClientHello.
type ClientHelloInfo struct {
	ContentType   byte
	TLSVersion    string
	HandshakeType string
	ClientVersion string
	Random        string
	SessionID     string
	SNI           string
}

// ParseClientHello parses a TLS ClientHello record and extracts the SNI and
// other diagnostic fields.
func ParseClientHello(data []byte) ClientHelloInfo {
	var r ClientHelloInfo
	if len(data) < 5 {
		return r
	}
	r.ContentType = data[0]
	r.TLSVersion = "0x" + hex.EncodeToString(data[1:3])
	if r.ContentType != 0x16 {
		return r
	}
	pos := 5
	if pos+4 > len(data) {
		return r
	}
	hsType := data[pos]
	pos += 4
	if hsType != 0x01 {
		return r
	}
	r.HandshakeType = "ClientHello"
	if pos+2 > len(data) {
		return r
	}
	r.ClientVersion = "0x" + hex.EncodeToString(data[pos:pos+2])
	pos += 2
	if pos+32 > len(data) {
		return r
	}
	r.Random = hex.EncodeToString(data[pos : pos+32])
	pos += 32
	if pos >= len(data) {
		return r
	}
	sessLen := int(data[pos])
	pos += 1
	if pos+sessLen > len(data) {
		return r
	}
	r.SessionID = hex.EncodeToString(data[pos : pos+sessLen])
	pos += sessLen
	if pos+2 > len(data) {
		return r
	}
	csLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + csLen
	if pos >= len(data) {
		return r
	}
	compLen := int(data[pos])
	pos += 1 + compLen
	if pos+2 > len(data) {
		return r
	}
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2
	extEnd := pos + extLen
	for pos+4 <= extEnd {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		extData := data[pos+4 : pos+4+extDataLen]
		pos += 4 + extDataLen
		if extType == 0x0000 { // SNI
			if len(extData) >= 5 {
				nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
				if 5+nameLen <= len(extData) {
					r.SNI = string(extData[5 : 5+nameLen])
				}
			}
		}
	}
	return r
}

// ServerHelloInfo holds the parsed fields of a TLS ServerHello.
type ServerHelloInfo struct {
	ContentType   byte
	HandshakeType string
	ServerVersion string
	Random        string
	SessionID     string
	CipherSuite   string
	Compression   byte
}

// ParseServerHello parses a TLS ServerHello message.
func ParseServerHello(data []byte) ServerHelloInfo {
	var r ServerHelloInfo
	if len(data) < 5 {
		return r
	}
	r.ContentType = data[0]
	if r.ContentType != 0x16 {
		return r
	}
	pos := 5
	if pos+4 > len(data) {
		return r
	}
	hsType := data[pos]
	pos += 4
	if hsType != 0x02 {
		return r
	}
	r.HandshakeType = "ServerHello"
	if pos+2 > len(data) {
		return r
	}
	r.ServerVersion = "0x" + hex.EncodeToString(data[pos:pos+2])
	pos += 2
	if pos+32 > len(data) {
		return r
	}
	r.Random = hex.EncodeToString(data[pos : pos+32])
	pos += 32
	if pos >= len(data) {
		return r
	}
	sessLen := int(data[pos])
	pos += 1
	if pos+sessLen > len(data) {
		return r
	}
	r.SessionID = hex.EncodeToString(data[pos : pos+sessLen])
	pos += sessLen
	if pos+2 > len(data) {
		return r
	}
	r.CipherSuite = "0x" + hex.EncodeToString(data[pos:pos+2])
	pos += 2
	if pos >= len(data) {
		return r
	}
	r.Compression = data[pos]
	return r
}
