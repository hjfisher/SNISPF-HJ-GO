# SNISPF-HJ-GO

### Cross-Platform DPI Bypass Tool (Go Port) — Adaptive Multi-IP/SNI Pool

```
███████╗███╗   ██╗██╗███████╗██████╗ ███████╗    ██╗  ██╗     ██╗       ██████╗  ██████╗ 
██╔════╝████╗  ██║██║██╔════╝██╔══██╗██╔════╝    ██║  ██║     ██║      ██╔════╝ ██╔═══██╗
███████╗██╔██╗ ██║██║███████╗██████╔╝█████╗█████╗███████║     ██║█████╗██║  ███╗██║   ██║
╚════██║██║╚██╗██║██║╚════██║██╔═══╝ ██╔══╝╚════╝██╔══██║██   ██║╚════╝██║   ██║██║   ██║
███████║██║ ╚████║██║███████║██║     ██║         ██║  ██║╚█████╔╝      ╚██████╔╝╚██████╔╝
╚══════╝╚═╝  ╚═══╝╚═╝╚══════╝╚═╝     ╚═╝         ╚═╝  ╚═╝ ╚════╝        ╚═════╝  ╚═════╝ 
```

**[FA README](README_FA.md)**

**SNISPF-HJ-GO** is the **Go port** of
[SNISPF-HJ](https://github.com/hjfisher/SNISPF-HJ), with **in-process
uTLS** — no sidecar binary required. The upstream TLS handshake (browser
fingerprint ClientHello) is performed directly in Go using the same
[uTLS](https://github.com/refraction-networking/utls) library that xray uses.

Runs on **Windows, macOS, Linux, and Android (Termux)** — no root required for
the default bypass method.

Webui Configurator → **[SNISPF-HJ-Config-Studio](https://hjfisher.github.io/SNISPF-HJ-Config-Studio/)**

---

## What's New in the Go Port

| Feature | SNISPF-HJ (Python) | SNISPF-HJ-GO (Go) |
|---|---|---|
| Upstream TLS fingerprint | Sidecar binary (`snispf-tls`) | **In-process uTLS** — no sidecar needed |
| MITM relay | Sidecar + Python relay | **In-process uTLS** on the real wire |
| Binary | Python + PyInstaller (~15 MB) | **Single Go binary** (~14 MB) |
| Dependencies | Python 3.8+ | **None** — statically compiled |
| Build time | ~30s (PyInstaller) | ~10s (`go build`) |
| Memory usage | ~30 MB (Python) | ~10 MB (Go) |
| Startup time | ~2s (PyInstaller extract) | **Instant** |

All original features (pool, discovery, fragmentation, fake-SNI, combined,
domain checker, raw injection, finalmask) are fully preserved.

---

## How Does It Work?

When you open an HTTPS site, your device sends a **TLS ClientHello** containing
the target hostname in plain text — the **SNI** (Server Name Indication). DPI
firewalls read that name and decide whether to block you.

SNISPF-HJ-GO sits between your app and the internet, intercepting that hello and
either **fragmenting it** or **sending a decoy** so the censor cannot read the
real hostname.

```
┌──────────┐     ┌──────────────────┐     ┌──────────┐     ┌──────────────┐
│ Your App ├────>│   SNISPF-HJ-GO   ├────>│  DPI /   ├────>│ Real Server  │
│          │     │  (local proxy)   │     │ Firewall │     │ (Cloudflare) │
│          │     │                  │     │          │     │              │
│          │     │ 1) pool picks    │     │ sees fake│     │              │
│          │     │   best (IP, SNI) │     │ or split │     │              │
│          │     │ 2) discovery adds│     │   SNI    │     │              │
│          │     │   fresh IPs live │     │          │     │              │
└──────────┘     └──────────────────┘     └──────────┘     └──────────────┘
```

### The Connection Pool

On startup the tool probes a random sample of `(IP, SNI)` pairs with a real
**TLS handshake** (not just a TCP connect — a server can accept TCP but still
reject or drop TLS traffic, so a true handshake is the only reliable test).
Pairs that respond well enter the **active pool**. A background goroutine
re-checks the pool every ~15–30 seconds and rotates out degraded pairs. Each new
connection is assigned a pair using **weighted-random selection** — lower
score means higher probability of being picked.

### In-Process uTLS Fingerprinting

In MITM mode, the upstream TLS handshake is performed **directly in Go** using
[uTLS](https://github.com/refraction-networking/utls) — the same library xray
uses. This sends a byte-perfect parrot of the requested browser's ClientHello
with full JA3/JA4 fidelity. No external sidecar binary is needed.

Supported fingerprints: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`,
`360`, `qq`, `random`, `randomized`, `randomizednoalpn`, `unsafe`, plus pinned
versions like `hellochrome_120`, `hellofirefox_105`, etc.

---

## Requirements

- **Go 1.24** or newer (for building from source)
- No external dependencies for the compiled binary

---

## Installation

### Option 1 — Download binary (recommended)

Download the latest release from
[GitHub Releases](https://github.com/hjfisher/SNISPF-HJ-GO/releases).

### Option 2 — Build from source

```bash
git clone https://github.com/hjfisher/SNISPF-HJ-GO.git
cd SNISPF-HJ-GO
go build -o snispf.exe .
snispf.exe --info
```

### Option 3 — Offline build (no internet)

If you cannot download Go modules, use the offline build script:

```bash
# Windows
build.bat

# Linux / macOS
chmod +x build.sh && ./build.sh
```

This copies the project to a temp directory and uses local stub modules for
`klauspost/compress`, `golang.org/x/net`, and `golang.org/x/text`.

---

## Quick Start

```bash
# Multi-IP / multi-SNI pool + dynamic discovery
snispf.exe --config config.json

# Single-pair mode (no pool)
snispf.exe --listen 0.0.0.0:40443 --connect 172.66.41.252:443 --sni github.com --method fragment
```

Expected output:

```
Connection pool active — 418 pair(s), 3 active slot(s)
Dynamic IP discovery active — batch=100  interval=120s
Upstream selection: POOL (multi-IP / multi-SNI)
Bypass strategy: combined
Listening on 0.0.0.0:40443
Ready! Configure your application to use:
  Address: 127.0.0.1:40443
```

Point your client (`v2ray`, `xray`, browser proxy plugin, …) at
**`127.0.0.1:40443`**.

---

## Configuration

CLI flags override config file values.

```jsonc
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_PORT": 443,
  "BYPASS_METHOD": "combined",       // direct | fragment | fake_sni | combined | mitm
  "FRAGMENT_STRATEGY": "sni_split",  // sni_split | half | multi | tls_record_frag
  "FRAGMENT_DELAY": 0.1,
  "FAKE_SNI_METHOD": "prefix_fake",

  // -- Pool ---------------------------------------------------------------
  "ACTIVE_SLOTS": 3,
  "HEALTH_CHECK_INTERVAL": 30,
  "HEALTH_CHECK_TIMEOUT": 3,
  "PROBE_COUNT": 5,
  "LOSS_THRESHOLD": 0.20,
  "DEAD_THRESHOLD": 0.80,
  "DRAIN_TIMEOUT": 30,
  "MAX_DRAINING": 5,

  // -- Eviction & recycling -----------------------------------------------
  "EVICT_EVERY": 3,
  "EVICT_COUNT": 2,
  "RECYCLE_ENABLED": true,
  "RECYCLE_EVERY": 6,
  "RECYCLE_BATCH": 2,
  "RECYCLE_MIN_COOLDOWN": 180,
  "RECYCLE_MAX_QUARANTINE": 100,
  "QUARANTINE_SCOPE": "both",        // static | dynamic | both

  "CONNECT_IPS": ["172.66.41.252", "108.162.196.145"],
  "FAKE_SNIS": ["github.com", "google.com"],

  // -- Dynamic IP discovery -----------------------------------------------
  "DYNAMIC_IP_DISCOVERY": true,
  "DISCOVERY_BATCH": 100,
  "DISCOVERY_INTERVAL": 120,
  "DISCOVERY_PROBE_TRIES": 3,
  "DISCOVERY_TIMEOUT": 2.0,
  "DISCOVERY_MIN_SUCCESS": 0.50,
  "DISCOVERY_MAX_IPS": 200,

  // -- SNI eviction & recycling -------------------------------------------
  "SNI_EVICT_EVERY": 3,
  "SNI_EVICT_COUNT": 1,
  "SNI_RECYCLE_ENABLED": true,
  "SNI_RECYCLE_EVERY": 6,
  "SNI_RECYCLE_BATCH": 2,
  "SNI_RECYCLE_MIN_COOLDOWN": 180,
  "SNI_RECYCLE_MAX_QUARANTINE": 100,
  "SNI_QUARANTINE_SCOPE": "both",

  // -- Dynamic SNI discovery ----------------------------------------------
  "DYNAMIC_SNI_DISCOVERY": true,
  "SNI_DISCOVERY_BATCH": 50,
  "SNI_DISCOVERY_INTERVAL": 120,
  "SNI_SOURCE_REFRESH_INTERVAL": 21600,
  "SNI_DISCOVERY_PROBE_TRIES": 3,
  "SNI_DISCOVERY_TIMEOUT": 2.0,
  "SNI_DISCOVERY_MIN_SUCCESS": 0.50,
  "MAX_DYNAMIC_SNIS": 100,
  "SNI_DISCOVERY_DOMAINS_PER_SOURCE": 5000
}
```

---

## Pool Settings

| Key | Default | Description |
|---|---|---|
| `CONNECT_IPS` | `[]` | Static upstream IP list |
| `FAKE_SNIS` | `[]` | Fake SNI hostname list |
| `ACTIVE_SLOTS` | `3` | Pairs kept active simultaneously |
| `HEALTH_CHECK_INTERVAL` | `30` | Seconds between re-probe cycles |
| `HEALTH_CHECK_TIMEOUT` | `3` | TLS handshake timeout per probe (s) |
| `PROBE_COUNT` | `5` | TLS probes per pair per cycle |
| `LOSS_THRESHOLD` | `0.20` | Loss score above which a pair is drained |
| `DEAD_THRESHOLD` | `0.80` | Loss score above which a pair is marked dead |
| `DRAIN_TIMEOUT` | `30` | Seconds before a draining pair's connections are force-closed |
| `MAX_DRAINING` | `5` | Max simultaneous draining pairs; oldest is force-closed if exceeded |

**Single-pair mode:** if both `CONNECT_IPS`/`FAKE_SNIS` lists have exactly one
entry (or legacy `CONNECT_IP` / `FAKE_SNI` keys are used), the pool is
disabled and the tool runs in direct mode with no overhead.

---

## Scoring: How a Pair's Health Is Measured

Every `(IP, SNI)` pair is probed with a **real TLS handshake** — a plain TCP
connect isn't enough, since a server can accept the TCP connection and still
refuse or drop the TLS layer.

### Loss tracking — exponential moving average

Instead of a lifetime "successes vs failures" counter, each pair keeps an
**EMA (exponential moving average)** of its loss:

```
ema_loss_new = alpha x loss_this_event + (1 - alpha) x ema_loss_previous
```

### Composite score

```
score = 0.60 x combined_loss_rate
      + 0.20 x latency_score
      + 0.20 x probe_loss_rate
```

Lower score = better. A dead pair scores `+inf` (never selected). A
not-yet-probed pair scores `0.5` so unknowns get a fair first chance.

---

## IP Eviction, Quarantine & Recycling

Weak IPs aren't deleted forever — they're **quarantined** and periodically
re-tested. If an IP genuinely recovers, it's welcomed back with a clean slate.

| Key | Default | Description |
|---|---|---|
| `EVICT_EVERY` | `3` | Evict weakest IPs every N health cycles |
| `EVICT_COUNT` | `2` | Number of IPs to evict per eviction cycle |
| `RECYCLE_ENABLED` | `true` | Enable/disable the recycling mechanism |
| `RECYCLE_EVERY` | `6` | Attempt recycling every N health cycles |
| `RECYCLE_BATCH` | `2` | How many quarantined IPs to re-test per attempt |
| `RECYCLE_MIN_COOLDOWN` | `180` | Minimum seconds between re-test attempts on the same IP |
| `RECYCLE_MAX_QUARANTINE` | `100` | Cap on quarantine size; oldest entries dropped beyond this |
| `QUARANTINE_SCOPE` | `"both"` | Which IP origin is eligible: `"static"`, `"dynamic"`, or `"both"` |

---

## Dynamic IP Discovery

| Key | Default | Description |
|---|---|---|
| `DYNAMIC_IP_DISCOVERY` | `false` | Enable discovery (set `true` to activate) |
| `DISCOVERY_BATCH` | `100` | Random IPs sampled per round |
| `DISCOVERY_INTERVAL` | `120` | Seconds between scan rounds |
| `DISCOVERY_PROBE_TRIES` | `3` | TLS handshake attempts per candidate |
| `DISCOVERY_TIMEOUT` | `2.0` | TLS handshake timeout per attempt (s) |
| `DISCOVERY_MIN_SUCCESS` | `0.50` | Minimum success rate to accept an IP (0-1) |
| `DISCOVERY_MAX_IPS` | `200` | Cap on dynamically discovered IPs |

---

## Dynamic SNI Discovery

| Key | Default | Description |
|---|---|---|
| `DYNAMIC_SNI_DISCOVERY` | `false` | Enable SNI discovery (set `true` to activate) |
| `SNI_DISCOVERY_BATCH` | `50` | Candidate domains sampled per discovery round |
| `SNI_DISCOVERY_INTERVAL` | `120` | Seconds between discovery rounds |
| `SNI_SOURCE_REFRESH_INTERVAL` | `21600` | Seconds between re-downloading Tranco/Umbrella/Majestic (default: 6h) |
| `SNI_DISCOVERY_PROBE_TRIES` | `3` | TLS handshake attempts per candidate |
| `SNI_DISCOVERY_TIMEOUT` | `2.0` | TLS handshake timeout per attempt (s) |
| `SNI_DISCOVERY_MIN_SUCCESS` | `0.50` | Minimum success rate to accept an SNI (0-1) |
| `MAX_DYNAMIC_SNIS` | `100` | Cap on dynamically discovered SNIs |
| `SNI_DISCOVERY_DOMAINS_PER_SOURCE` | `5000` | Max domains pulled from each ranking list |

---

## MITM Mode, cipherSuites & finalmask

### MITM relay (`BYPASS_METHOD: "mitm"`)

`mitm` is a bypass method like `direct` / `combined` — instead of plain-TCP
forwarding, the tool **builds its own SSL** using in-process uTLS: it terminates
the client's TLS session with an automatically generated self-signed certificate,
then opens a *fresh* TLS connection to the real upstream with a brand-new,
fingerprint-clean ClientHello.

| Key | Default | Description |
|---|---|---|
| `BYPASS_METHOD` | `"fragment"` | `"mitm"` = TLS-terminating relay |
| `MITM_CERT_FILE` / `MITM_KEY_FILE` | `null` | Paths to an existing cert/key pair; auto-generated if absent |
| `MITM_CERT_CN` | `"SNISPF-HJ"` | Common Name for the generated certificate |
| `MITM_ALPN` | `["h2", "http/1.1"]` | ALPN offered upstream when the client sends no ALPN |
| `MITM_USE_CLIENT_SNI` | `false` | Use the client's own SNI for the upstream TLS handshake |
| `FINGERPRINT` | `null` | Browser TLS fingerprint: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`, `randomized`, `randomizednoalpn`, `unsafe`, or pinned versions |

### `FINGERPRINT` — browser TLS fingerprinting (JA3/JA4)

In the Go port, the upstream TLS handshake is performed **directly in Go** using
[uTLS](https://github.com/refraction-networking/utls). No sidecar binary is
needed.

Profiles mirror xray-core's fingerprint names:

| FINGERPRINT | uTLS preset | Notes |
| --- | --- | --- |
| `chrome` | `HelloChrome_Auto` (Chrome 133) | default |
| `firefox` | `HelloFirefox_Auto` (Firefox 120) | |
| `safari` | `HelloSafari_Auto` (Safari 16.0) | |
| `ios` | `HelloIOS_Auto` (iOS 14) | |
| `android` | `HelloAndroid_11_OkHttp` | |
| `edge` | `HelloEdge_Auto` (Edge/Chromium 85) | |
| `360` | `Hello360_Auto` (Qihoo 360 7.5) | |
| `qq` | `HelloQQ_Auto` (QQ 11.1) | |
| `random` | per-connection pick of the above | different browser per connection |
| `randomized` | `HelloRandomizedALPN` (xray weights) | unique randomized hello per connection |
| `randomizednoalpn` | `HelloRandomizedNoALPN` (xray weights) | as above, no ALPN ext |
| `unsafe` | `HelloGolang` | plain Go TLS, no impersonation |

Pinned per-version names are accepted too: `hellochrome_58` ... `hellochrome_133`,
`hellofirefox_55` ... `hellofirefox_120`, `helloios_11_1` ... `helloios_14`,
`helloedge_85` / `helloedge_106`, `hellosafari_16_0`, `hello360_7_5` /
`hello360_11_0`, `helloqq_11_1`, `helloandroid_11_okhttp`, plus
`hellogolang`, `hellorandomized`, `hellorandomizedalpn`,
`hellorandomizednoalpn` and the `*_auto` variants.

### `CIPHER_SUITES`

Custom TLS cipher suites for the upstream ClientHello, in xray's
`cipherSuites` format:

```
"CIPHER_SUITES": "TLS_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
```

### `FINALMASK_TCP` — finalmask TCP fragmentation

A faithful Go port of xray's `finalmask` TCP mask. `null` to disable, or
a JSON array of `fragment` rules:

```json
"FINALMASK_TCP": [
  { "type": "fragment", "settings": { "packets": "tlshello", "lengths": ["5", "94", "1"], "delays": ["0"], "maxSplit": "0" } },
  { "type": "fragment", "settings": { "packets": "1-1",      "lengths": ["109", "1"],    "delays": ["1"], "maxSplit": "355" } }
]
```

---

## CLI Flags

```
--config, -C FILE         Path to JSON config file
--generate-config PATH    Write a default config and exit
--listen, -l HOST:PORT    Listen address (default: 0.0.0.0:40443)
--connect, -c IP:PORT     Target server (single-pair mode)
--sni,    -s HOSTNAME     Fake SNI hostname (single-pair mode)
--method, -m METHOD       direct | fragment | fake_sni | combined | mitm
--cipher-suites LIST      Upstream TLS cipher suites (xray cipherSuites format)
--fingerprint PROFILE     Browser TLS fingerprint
--finalmask FILE          JSON file with a finalmask TCP rules array
--fragment-strategy STR   sni_split | half | multi | tls_record_frag
--fragment-delay  SEC     Delay between fragments (seconds)
--no-raw                  Disable raw socket injection
--check-domains FILE      Bulk-check domains for Cloudflare backing
--check-workers N         Parallel workers (default: 50)
--check-timeout SEC       Per-domain timeout (default: 3.0)
--output FILE             Save verified domains to file
--check-http              Also verify HTTP during domain check
--verbose, -v             Debug logging
--quiet,   -q             Warnings only
--version, -V             Print version and exit
--info                    Show platform capabilities and exit
```

---

## Bypass Methods

| Method | How it works | Privileges needed |
|---|---|---|
| `fragment` | Splits ClientHello at the SNI boundary into multiple TCP segments | None |
| `fake_sni` | Sends decoy ClientHello(s) before the real one | Root for raw sockets; fragments without |
| `combined` | Both simultaneously — recommended | Same as `fake_sni` |

---

## Fragment Strategies

| Strategy | Description |
|---|---|
| `sni_split` (default) | Split exactly at the SNI hostname boundary |
| `half` | Two roughly equal halves |
| `multi` | Many 5-10 byte fragments |
| `tls_record_frag` | Split at the TLS record layer |

---

## Domain Checker

```bash
snispf.exe --check-domains domains.txt
snispf.exe --check-domains domains.txt --output verified.txt --check-http -v
```

Outputs which domains are Cloudflare-backed — useful for building `FAKE_SNIS`.

---

## Platform Support

| Platform | Status | Notes |
|---|---|---|
| Linux | Full | Raw injection with `sudo` / `CAP_NET_RAW` |
| macOS | Full | Fragmentation + fake-SNI; no raw sockets |
| Windows 10/11 | Full | Fragment/combined; no raw sockets |
| Android (Termux) | Supported | No root needed; fragmentation + fake-SNI |

Run `snispf.exe --info` to see what your system supports.

---

## Troubleshooting

**Port already in use**
```bash
snispf.exe --listen :40444 --config config.json
```

**Pool shows all pairs as dead**
- Check that `CONNECT_IPS` are reachable on port 443 with a real TLS handshake
- Raise `HEALTH_CHECK_TIMEOUT` to `6`
- Raise `DEAD_THRESHOLD` to `0.90`

**Connections getting closed unexpectedly**
- This may be `DRAIN_TIMEOUT` firing. Raise it: `"DRAIN_TIMEOUT": 60`

**Discovery finds nothing**
- Your network may block outbound probes — try `"DISCOVERY_TIMEOUT": 4.0`
- Loosen the threshold: `"DISCOVERY_MIN_SUCCESS": 0.34`

---

## Project Structure

```
SNISPF-HJ-GO/
├── main.go                     # Entry point (go build -o snispf.exe .)
├── config.json                 # Default config
├── go.mod / go.sum             # Go module files
├── build.bat / build.sh        # Offline build scripts
├── README.md / README_FA.md
└── internal/
    ├── certs/                  # Self-signed cert generation + SHA-256 fingerprint
    ├── config/                 # Config loader (JSON, typed getters)
    ├── discovery/              # IP discovery + SNI discovery + Cloudflare CIDRs
    ├── finalmask/              # xray finalmask TCP fragmentation (faithful port)
    ├── forward/                # TCP forwarder + bypass strategies + raw injection
    ├── mitm/                   # MITM relay (in-process uTLS handshake)
    ├── pool/                   # PairStats, CombinationExplorer, ActivePool
    ├── scanner/                # Bulk Cloudflare domain checker
    ├── tlsutil/                # ClientHello builder + parser + fingerprint resolver
    └── utils/                  # Platform detection, IP/port helpers
```

---

## Credits

- **[@Rainman69](https://github.com/Rainman69)** — original SNISPF architecture
- **[@patterniha](https://github.com/patterniha)** — original SNI-spoofing concept
- **[@hjfisher](https://github.com/hjfisher)** — pool, discovery, EMA scoring, Go port
- **[@bia-pain-bache](https://github.com/bia-pain-bache)** — Cloudflare IP scanning methodology
- **[@refraction-networking](https://github.com/refraction-networking)** — uTLS library

---

## License

[MIT](LICENSE) © Rainman69, hjfisher
