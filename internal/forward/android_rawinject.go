// The following helper functions are required and can be copied from the Linux version:

// findInterface finds the network interface index for a given remote IP address.
func findInterface(remoteIP string) (string, int) {
    udp, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.ParseIP(remoteIP), Port: 53})
    if err != nil {
        return "", 0
    }
    defer udp.Close()
    local := udp.LocalAddr().(*net.UDPAddr)

    ifaces, err := net.Interfaces()
    if err != nil {
        return "", 0
    }
    for _, iface := range ifaces {
        if iface.Flags&net.FlagUp == 0 {
            continue
        }
        addrs, _ := iface.Addrs()
        for _, a := range addrs {
            ipn, ok := a.(*net.IPNet)
            if !ok {
                continue
            }
            if ip4 := ipn.IP.To4(); ip4 != nil && ip4.Equal(local.IP) {
                return iface.Name, iface.Index
            }
        }
    }
    return "", 0
}

// buildFakeFrame is used to construct a fake frame for injection.
func buildFakeFrame(templatePkt []byte, isn uint32, fakePayload []byte) []byte {
    ipOff := 14
    ihl := int(templatePkt[ipOff] & 0x0F) * 4
    tcpOff := ipOff + ihl
    tcpHdrLen := int(templatePkt[tcpOff+12] >> 4) * 4

    out := make([]byte, 0, tcpOff+tcpHdrLen+len(fakePayload))
    out = append(out, templatePkt[:tcpOff+tcpHdrLen]...)
    out = append(out, fakePayload...)

    binary.BigEndian.PutUint16(out[ipOff+2:], uint16(len(out)-ipOff))
    binary.BigEndian.PutUint16(out[ipOff+4:], binary.BigEndian.Uint16(out[ipOff+4:])+1)
    out[ipOff+10] = 0
    out[ipOff+11] = 0
    binary.BigEndian.PutUint16(out[ipOff+10:], ipChecksum(out[ipOff:ipOff+ihl]))

    out[tcpOff+13] |= tcpPSH
    binary.BigEndian.PutUint32(out[tcpOff+4:], isn+1-uint32(len(fakePayload)))
    out[tcpOff+16] = 0
    out[tcpOff+17] = 0
    binary.BigEndian.PutUint16(out[tcpOff+16:], tcpChecksum(out[ipOff:ipOff+ihl], out[tcpOff:]))

    return out
}

// ipChecksum computes the IPv4 header checksum.
func ipChecksum(iph []byte) uint16 {
    return checksumFold(sum16(iph))
}

// tcpChecksum computes the TCP checksum including the IPv4 pseudo-header.
func tcpChecksum(iph, tcpWithPayload []byte) uint16 {
    pseudo := make([]byte, 12)
    copy(pseudo[0:4], iph[12:16])
    copy(pseudo[4:8], iph[16:20])
    pseudo[9] = 6
    binary.BigEndian.PutUint16(pseudo[10:], uint16(len(tcpWithPayload)))
    return checksumFold(sum16(pseudo) + sum16(tcpWithPayload))
}

// sum16 is from rawinject_common.go
func sum16(data []byte) uint32 {
    var s uint32
    for i := 0; i+1 < len(data); i += 2 {
        s += uint32(binary.BigEndian.Uint16(data[i:]))
    }
    if len(data)%2 == 1 {
        s += uint32(data[len(data)-1]) << 8
    }
    for s>>16 != 0 {
        s = (s & 0xFFFF) + (s >> 16)
    }
    return s
}

// checksumFold is from rawinject_common.go
func checksumFold(s uint32) uint16 {
    for s>>16 != 0 {
        s = (s & 0xFFFF) + (s >> 16)
    }
    return ^uint16(s)
}
