# Transparent Proxy Mode (TPROXY)

## Overview

Transparent proxy mode intercepts traffic at the kernel level using Linux TPROXY, eliminating the need to configure individual applications to use a proxy. All TCP/UDP traffic on selected ports is redirected to ProxyForge without any client-side configuration.

## Platform Requirements

- **Linux only** — TPROXY is a Linux kernel feature (kernel ≥ 4.14 with `CONFIG_NETFILTER_TPROXY=y`)
- `CAP_NET_ADMIN` capability (or root)
- `iptables` or `nftables` available in the host environment
- **`proxyforge-tproxy` side-car binary** installed beside the Electron app or in `PATH`

> **Note:** The side-car is an optional separate download. Without it `isTransparentModeSupported()` returns `false` and all capture calls resolve gracefully without doing anything.

## When to Use

| Scenario | Use Transparent Mode? |
|----------|-----------------------|
| Mobile device traffic via tethering | Yes |
| Containerised app that ignores HTTP_PROXY | Yes |
| Thick client with hard-coded connections | Yes |
| Standard browser testing | No — HTTP proxy mode is simpler |
| macOS / Windows targets | No — use upstream proxy chaining instead |

## Configuration

```jsonc
// Example TransparentModeConfig
{
  "interface": "eth0",       // Network interface to capture on
  "ports": [80, 443, 8080], // Ports to intercept (default: [80, 443])
  "family": "ipv4",          // "ipv4" | "ipv6" | "both" (default: "both")
  "exemptUid": 1000          // UID to exempt from capture (e.g. the proxy process)
}
```

## Usage

```ts
import {
  isTransparentModeSupported,
  getTransparentModeCapabilities,
  startTransparentCapture,
  stopTransparentCapture,
} from 'electron/traffic/transparentMode';

if (!isTransparentModeSupported()) {
  const caps = getTransparentModeCapabilities();
  console.warn('Transparent mode unavailable:', caps.reason);
} else {
  const session = await startTransparentCapture({
    interface: 'eth0',
    ports: [80, 443],
  });
  // … capture traffic …
  await stopTransparentCapture(session.sessionId);
}
```

## How It Works (with side-car)

1. The side-car binary sets up iptables/nftables `TPROXY` rules that redirect matching packets to a local socket.
2. ProxyForge binds to that socket with `IP_TRANSPARENT` set, receiving original destination addresses.
3. Intercepted flows appear in the ProxyForge traffic view as if they came from a standard HTTP/S proxy.
4. On session stop the side-car tears down the iptables rules.

## Limitations

- Linux only — no macOS or Windows support planned
- Requires elevated privileges
- UDP capture requires the side-car to handle connection-less flows
- Optional side-car not bundled in the default ProxyForge release
