# WireGuard Mode

Proxy Forge supports an optional WireGuard tunnel mode via the `wireguard` side-car binary. When the side-car is installed, Proxy Forge can route captured traffic through a WireGuard interface for VPN-based target reach.

## Requirements

- Linux: `wireguard-tools` or the bundled `side-cars/wireguard/` boringtun binary.
- Windows: WireGuard for Windows with the tunnel service.
- macOS: WireGuard app or `wireguard-go`.

The side-car is optional. Proxy Forge runs fine without it — WireGuard mode simply remains unavailable.

## Configuration

```json
{
  "mode": "wireguard",
  "wireguard": {
    "privateKey": "...",
    "peerPublicKey": "...",
    "endpoint": "vpn.example.com:51820",
    "allowedIPs": ["10.0.0.0/8"],
    "dns": "10.0.0.1"
  }
}
```

## Smoke test

`tests/traffic-wireguard.mjs` verifies the module exports and capability flags without requiring a live WireGuard peer.

## Safety

All ProxyForge scope, rate-limit, and mode guards apply normally when WireGuard mode is active. The tunnel does not bypass scope checks.
