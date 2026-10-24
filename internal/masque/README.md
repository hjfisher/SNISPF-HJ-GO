# Masque Probe (`internal/masque`)

Phase 1 probe package for MASQUE transport in `SNISPF-HJ-GO`.

## Overview

`internal/masque` opens a TLS connection (using uTLS and HTTP/2) to a Cloudflare edge IP, negotiates `h2`, sends a single HTTP/2 `CONNECT` request, and reports the resulting status code and handshake metrics without sending any tunnel data.

## API Usage

```go
import "snispf-hj-go/internal/masque"

res := masque.Probe(ctx, masque.ProbeOptions{
    IP:          "203.0.113.10",
    Port:        443,
    SNI:         "www.cloudflare.com",
    Authority:   "cloudflareaccess.com",
    Fingerprint: "chrome",
    Timeout:     10 * time.Second,
})
```
