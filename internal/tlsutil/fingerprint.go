package tlsutil

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"

	utls "github.com/refraction-networking/utls"
)

// Preset profiles accepted from the FINGERPRINT config / --fingerprint CLI
// value. Mirrors xray-core's PresetFingerprints. "random" picks one concrete
// preset browser per connection; "randomized"/"randomizednoalpn" send a unique
// randomized hello; "unsafe" uses the plain Go TLS stack.
var PresetFingerprints = []string{
	"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
	"random", "randomized", "randomizednoalpn", "unsafe",
}

// Pinned per-version names (xray's ModernFingerprints / OtherFingerprints).
// Only the ones utls v1.8.2 provides are listed; unknown pinned names are
// rejected with a clear error.
var PinnedFingerprints = []string{
	"hellogolang",
	"hellorandomized",
	"hellorandomizedalpn",
	"hellorandomizednoalpn",
	"hellofirefox_auto", "hellofirefox_120", "hellofirefox_105",
	"hellofirefox_102", "hellofirefox_99", "hellofirefox_65",
	"hellofirefox_63", "hellofirefox_56", "hellofirefox_55",
	"hellochrome_auto", "hellochrome_133", "hellochrome_131",
	"hellochrome_120", "hellochrome_120_pq", "hellochrome_115_pq_psk",
	"hellochrome_115_pq", "hellochrome_114_padding_psk_shuf",
	"hellochrome_112_psk_shuf", "hellochrome_106_shuffle", "hellochrome_102",
	"hellochrome_100_psk", "hellochrome_100", "hellochrome_96",
	"hellochrome_87", "hellochrome_83", "hellochrome_72", "hellochrome_70",
	"hellochrome_62", "hellochrome_58",
	"helloios_auto", "helloios_14", "helloios_13", "helloios_12_1",
	"helloios_11_1",
	"helloedge_auto", "helloedge_106", "helloedge_85",
	"hello360_auto", "hello360_11_0", "hello360_7_5",
	"helloqq_auto", "helloqq_11_1",
	"hellosafari_auto", "hellosafari_16_0",
	"helloandroid_11_okhttp",
}

// ValidFingerprints is the full set of accepted names plus "none".
var ValidFingerprints = append(append([]string{}, PresetFingerprints...), PinnedFingerprints...)

var randomPool = []string{
	"chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq",
}

var disabledSet = map[string]bool{
	"": true, "none": true, "disabled": true, "off": true, "null": true,
}

// presets mirrors xray-core's PresetFingerprints.
var presets = map[string]utls.ClientHelloID{
	"chrome":           utls.HelloChrome_Auto,
	"firefox":          utls.HelloFirefox_Auto,
	"safari":           utls.HelloSafari_Auto,
	"ios":              utls.HelloIOS_Auto,
	"android":          utls.HelloAndroid_11_OkHttp,
	"edge":             utls.HelloEdge_Auto,
	"360":              utls.Hello360_Auto,
	"qq":               utls.HelloQQ_Auto,
	"randomized":       utls.HelloRandomizedALPN,
	"randomizednoalpn": utls.HelloRandomizedNoALPN,
	"unsafe":           utls.HelloGolang,
}

// pinnedHellos mirrors xray-core's ModernFingerprints / OtherFingerprints.
var pinnedHellos = map[string]utls.ClientHelloID{
	"hellogolang":           utls.HelloGolang,
	"hellorandomized":       utls.HelloRandomized,
	"hellorandomizedalpn":   utls.HelloRandomizedALPN,
	"hellorandomizednoalpn": utls.HelloRandomizedNoALPN,

	"hellofirefox_auto": utls.HelloFirefox_Auto,
	"hellofirefox_120":  utls.HelloFirefox_120,
	"hellofirefox_105":  utls.HelloFirefox_105,
	"hellofirefox_102":  utls.HelloFirefox_102,
	"hellofirefox_99":   utls.HelloFirefox_99,
	"hellofirefox_65":   utls.HelloFirefox_65,
	"hellofirefox_63":   utls.HelloFirefox_63,
	"hellofirefox_56":   utls.HelloFirefox_56,
	"hellofirefox_55":   utls.HelloFirefox_55,

	"hellochrome_auto":                 utls.HelloChrome_Auto,
	"hellochrome_133":                  utls.HelloChrome_133,
	"hellochrome_131":                  utls.HelloChrome_131,
	"hellochrome_120":                  utls.HelloChrome_120,
	"hellochrome_120_pq":               utls.HelloChrome_120_PQ,
	"hellochrome_115_pq_psk":           utls.HelloChrome_115_PQ_PSK,
	"hellochrome_115_pq":               utls.HelloChrome_115_PQ,
	"hellochrome_114_padding_psk_shuf": utls.HelloChrome_114_Padding_PSK_Shuf,
	"hellochrome_112_psk_shuf":         utls.HelloChrome_112_PSK_Shuf,
	"hellochrome_106_shuffle":          utls.HelloChrome_106_Shuffle,
	"hellochrome_102":                  utls.HelloChrome_102,
	"hellochrome_100_psk":              utls.HelloChrome_100_PSK,
	"hellochrome_100":                  utls.HelloChrome_100,
	"hellochrome_96":                   utls.HelloChrome_96,
	"hellochrome_87":                   utls.HelloChrome_87,
	"hellochrome_83":                   utls.HelloChrome_83,
	"hellochrome_72":                   utls.HelloChrome_72,
	"hellochrome_70":                   utls.HelloChrome_70,
	"hellochrome_62":                   utls.HelloChrome_62,
	"hellochrome_58":                   utls.HelloChrome_58,

	"helloios_auto": utls.HelloIOS_Auto,
	"helloios_14":   utls.HelloIOS_14,
	"helloios_13":   utls.HelloIOS_13,
	"helloios_12_1": utls.HelloIOS_12_1,
	"helloios_11_1": utls.HelloIOS_11_1,

	"helloedge_auto": utls.HelloEdge_Auto,
	"helloedge_106":  utls.HelloEdge_106,
	"helloedge_85":   utls.HelloEdge_85,

	"hello360_auto": utls.Hello360_Auto,
	"hello360_11_0": utls.Hello360_11_0,
	"hello360_7_5":  utls.Hello360_7_5,

	"helloqq_auto": utls.HelloQQ_Auto,
	"helloqq_11_1": utls.HelloQQ_11_1,

	"hellosafari_auto": utls.HelloSafari_Auto,
	"hellosafari_16_0": utls.HelloSafari_16_0,

	"helloandroid_11_okhttp": utls.HelloAndroid_11_OkHttp,
}

// ResolveFingerprint resolves a FINGERPRINT value to a concrete profile name.
// nil/empty/"none"/"disabled" -> "" (feature off). "random" -> one concrete
// preset browser per call so each upstream connection gets a different browser.
// Everything else passes through unchanged. Unknown names log a warning and
// return "".
func ResolveFingerprint(value string) string {
	if value == "" {
		return ""
	}
	v := strings.TrimSpace(strings.ToLower(value))
	if disabledSet[v] {
		return ""
	}
	if v == "random" {
		return randomPool[rand.Intn(len(randomPool))]
	}
	if v == "randomized" || v == "randomizednoalpn" || v == "unsafe" {
		return v
	}
	if presets[v] != (utls.ClientHelloID{}) || pinnedHellos[v] != (utls.ClientHelloID{}) {
		return v
	}
	return ""
}

// SortedFingerprintList returns the comma-separated list of valid names.
func SortedFingerprintList() string {
	names := make([]string, 0, len(ValidFingerprints))
	names = append(names, ValidFingerprints...)
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// ClientHelloID returns the uTLS ClientHelloID for a resolved profile name.
// It validates the name first so a typo surfaces as an error before dialing.
func ClientHelloID(name string) (utls.ClientHelloID, error) {
	switch name {
	case "randomized":
		return randomizedID(false), nil
	case "randomizednoalpn":
		return randomizedID(true), nil
	}
	if id, ok := presets[name]; ok {
		return id, nil
	}
	if id, ok := pinnedHellos[name]; ok {
		return id, nil
	}
	if name == "random" {
		return presets[randomPool[rand.Intn(len(randomPool))]], nil
	}
	return utls.ClientHelloID{}, fmt.Errorf("unknown fingerprint %q\n  valid names: %s",
		name, SortedFingerprintList())
}

func randomizedID(noALPN bool) utls.ClientHelloID {
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	seed, _ := utls.NewPRNGSeed()
	id := utls.HelloRandomizedALPN
	if noALPN {
		id = utls.HelloRandomizedNoALPN
	}
	id.Seed = seed
	id.Weights = &weights
	return id
}
