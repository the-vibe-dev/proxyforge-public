# HTTP/3 and QUIC Transport Mode

## Overview

HTTP/3 runs over QUIC — a multiplexed transport built on UDP rather than TCP. ProxyForge can intercept and inspect HTTP/3 traffic when the optional `proxyforge-quic` side-car binary is installed. Without the side-car the module stubs return capability objects and `isHttp3Supported()` returns `false`.

## Platform Requirements

- **Any platform** (Linux, macOS, Windows) — QUIC runs in userspace
- UDP reachability to the target host (port 443 by default)
- **`proxyforge-quic` side-car binary** installed beside the Electron app or in `PATH`
  - The side-car is built with the [quiche](https://github.com/cloudflare/quiche) or [quinn](https://github.com/quinn-rs/quinn) Rust library
  - TLS 1.3 support is included in the side-car

> **Note:** The side-car is an optional separate download. Without it `isHttp3Supported()` returns `false` and all connection calls resolve gracefully without doing anything.

## When to Use

| Scenario | Use HTTP/3 Mode? |
|----------|-----------------|
| Target explicitly negotiates h3 via Alt-Svc | Yes |
| Inspecting QUIC connection metadata (RTT, stream IDs) | Yes |
| Standard HTTPS browsing (HTTP/1.1 or HTTP/2) | No — standard MITM proxy is sufficient |
| Target only speaks HTTP/2 | No |

## Configuration

```jsonc
// Example Http3TransportConfig
{
  "maxStreams": 100,        // Max concurrent QUIC streams
  "idleTimeoutMs": 30000,  // QUIC idle timeout in ms
  "allowInsecure": false,  // Accept self-signed TLS certs
  "alpn": ["h3"]           // ALPN protocols (default: ["h3"])
}
```

## Usage

```ts
import {
  isHttp3Supported,
  getHttp3Capabilities,
  openHttp3Connection,
} from 'electron/traffic/http3Transport';

if (!isHttp3Supported()) {
  const caps = getHttp3Capabilities();
  console.warn('HTTP/3 unavailable:', caps.reason);
} else {
  const conn = await openHttp3Connection('https://target.example', {
    maxStreams: 50,
    idleTimeoutMs: 15000,
  });
  if (conn.connected) {
    console.log('HTTP/3 connected, RTT:', conn.rttMs, 'ms');
  }
}
```

## How It Works (with side-car)

1. ProxyForge calls the side-car via an IPC channel with the target URL and config.
2. The side-car establishes a QUIC connection to the target, performing a TLS 1.3 handshake with the ProxyForge CA certificate.
3. HTTP/3 request/response frames are forwarded to ProxyForge, which records them in the traffic view like standard HTTP exchanges.
4. Connection metadata (RTT samples, stream IDs, QUIC version) appears in the exchange detail panel.

## Limitations

- Requires optional side-car not bundled in the default release
- Some servers fall back to HTTP/2 even when h3 is advertised — ProxyForge handles the negotiation gracefully
- UDP may be blocked by corporate firewalls; h3 will not connect in those environments
