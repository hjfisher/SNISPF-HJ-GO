package tlsutil

import (
	"encoding/binary"
)

// FragmentClientHello fragments a TLS ClientHello into multiple TCP segments.
// Strategies: "sni_split", "half", "multi", "tls_record_frag", "none".
func FragmentClientHello(data []byte, strategy string) [][]byte {
	if strategy == "none" || len(data) < 10 {
		return [][]byte{data}
	}
	switch strategy {
	case "sni_split":
		return fragmentAtSNI(data)
	case "half":
		mid := len(data) / 2
		return [][]byte{data[:mid], data[mid:]}
	case "multi":
		return fragmentMulti(data, 24)
	case "tls_record_frag":
		return tlsRecordFragment(data)
	default:
		return [][]byte{data}
	}
}

// findSNIOffset returns the offset and length of the SNI value in a
// ClientHello, or (-1, 0) if not found.
func findSNIOffset(data []byte) (int, int) {
	pos := 0
	for pos < len(data)-10 {
		if data[pos] == 0x00 && data[pos+1] == 0x00 {
			if pos+9 <= len(data) {
				extLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
				if extLen > 4 && extLen < 256 && pos+9+0 <= len(data) {
					if pos+6 <= len(data) {
						nameType := data[pos+6]
						if pos+9 <= len(data) {
							nameLen := int(binary.BigEndian.Uint16(data[pos+7 : pos+9]))
							if nameType == 0 && nameLen > 0 && nameLen < 256 {
								sniStart := pos + 9
								if sniStart+nameLen <= len(data) {
									sniData := data[sniStart : sniStart+nameLen]
									printable := true
									for _, b := range sniData {
										if b < 0x20 || b >= 0x7F {
											printable = false
											break
										}
									}
									if printable {
										return sniStart, nameLen
									}
								}
							}
						}
					}
				}
			}
		}
		pos++
	}
	return -1, 0
}

func fragmentAtSNI(data []byte) [][]byte {
	sniOffset, sniLen := findSNIOffset(data)
	if sniOffset < 0 {
		mid := len(data) / 2
		return [][]byte{data[:mid], data[mid:]}
	}
	splitPoint := sniOffset + sniLen/2
	return [][]byte{data[:splitPoint], data[splitPoint:]}
}

func fragmentMulti(data []byte, chunkSize int) [][]byte {
	if chunkSize <= 0 {
		chunkSize = 24
	}
	var fragments [][]byte
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		fragments = append(fragments, data[i:end])
	}
	return fragments
}

func tlsRecordFragment(data []byte) [][]byte {
	if len(data) < 6 || data[0] != 0x16 {
		return [][]byte{data}
	}
	recordVersion := data[1:3]
	handshakeData := data[5:]
	mid := len(handshakeData) / 2
	part1 := handshakeData[:mid]
	part2 := handshakeData[mid:]
	record1 := []byte{0x16, recordVersion[0], recordVersion[1], byte(len(part1) >> 8), byte(len(part1))}
	record1 = append(record1, part1...)
	record2 := []byte{0x16, recordVersion[0], recordVersion[1], byte(len(part2) >> 8), byte(len(part2))}
	record2 = append(record2, part2...)
	return [][]byte{record1, record2}
}

// FragmentData fragments data into the given sizes. The last fragment gets
// all remaining data.
func FragmentData(data []byte, sizes []int) [][]byte {
	if len(sizes) == 0 || len(data) == 0 {
		if len(data) == 0 {
			return nil
		}
		return [][]byte{data}
	}
	var fragments [][]byte
	pos := 0
	for i, size := range sizes {
		if pos >= len(data) {
			break
		}
		if i == len(sizes)-1 {
			fragments = append(fragments, data[pos:])
			pos = len(data)
		} else {
			if size < 0 {
				size = 0
			}
			end := pos + size
			if end > len(data) {
				end = len(data)
			}
			fragments = append(fragments, data[pos:end])
			pos = end
		}
	}
	if pos < len(data) {
		fragments = append(fragments, data[pos:])
	}
	if len(fragments) == 0 {
		return [][]byte{data}
	}
	return fragments
}
