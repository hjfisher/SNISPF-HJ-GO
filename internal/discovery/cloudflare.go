package discovery

import (
	"math/rand"
	"net"
)

// CloudflareCIDRs are the official Cloudflare IPv4 ranges (cloudflare.com/ips-v4).
var CloudflareCIDRs = []string{
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"108.162.192.0/18",
	"131.0.72.0/22",
	"141.101.64.0/18",
	"162.158.0.0/15",
	"172.64.0.0/13",
	"173.245.48.0/20",
	"188.114.96.0/20",
	"190.93.240.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
}

var cfNetworks = func() []*net.IPNet {
	var nets []*net.IPNet
	for _, c := range CloudflareCIDRs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}()

// IsCloudflareIP reports whether an IPv4 address falls inside Cloudflare's ranges.
func IsCloudflareIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() == nil {
		return false
	}
	for _, n := range cfNetworks {
		if n.Contains(parsed) {
			return true
		}
	}
	return false
}

// sampleRandomIPs returns count random host IPs drawn uniformly from a CIDR.
func sampleRandomIPs(cidr string, count int) []string {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil
	}
	bits, size := network.Mask.Size()
	hostBits := size - bits
	hostCount := int64(1) << hostBits
	usable := hostCount - 2 // exclude network + broadcast
	if usable <= 0 {
		return nil
	}
	base := network.IP.To4()
	baseVal := int64(base[0])<<24 | int64(base[1])<<16 | int64(base[2])<<8 | int64(base[3])

	var out []string
	seen := map[int64]bool{}
	k := int64(count)
	if k > usable {
		k = usable
	}
	for int64(len(out)) < k {
		off := rand.Int63n(usable)
		v := baseVal + 1 + off
		if seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)).String())
	}
	return out
}

// SampleCloudflareIPs draws total random IPs spread proportionally across the
// CIDR ranges and returns a shuffled slice (length ≤ total).
func SampleCloudflareIPs(total int, cidrs []string) []string {
	if len(cidrs) == 0 {
		return nil
	}
	var weights []int64
	totalHosts := int64(0)
	for _, cidr := range cidrs {
		_, network, err := net.ParseCIDR(cidr)
		var w int64
		if err == nil {
			bits, size := network.Mask.Size()
			w = (int64(1) << (size - bits)) - 2
		}
		weights = append(weights, w)
		totalHosts += w
	}
	if totalHosts == 0 {
		return nil
	}
	var result []string
	for i, cidr := range cidrs {
		if weights[i] == 0 {
			continue
		}
		share := int64(float64(total) * float64(weights[i]) / float64(totalHosts))
		if share < 1 {
			share = 1
		}
		result = append(result, sampleRandomIPs(cidr, int(share))...)
	}
	rand.Shuffle(len(result), func(i, j int) { result[i], result[j] = result[j], result[i] })
	if len(result) > total {
		result = result[:total]
	}
	return result
}
