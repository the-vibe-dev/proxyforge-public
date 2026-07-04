// Transparent proxy mode stub — Linux tproxy side-car
//
// Real implementation requires an optional Rust side-car binary that sets up
// iptables/nftables TPROXY rules and captures raw traffic at the kernel level.
// Without the side-car installed these functions return capability/status
// objects rather than throwing, so callers can degrade gracefully.

export interface TransparentModeConfig {
  /** Network interface to capture on (e.g. "eth0") */
  interface?: string;
  /** Port range to intercept. Defaults to [80, 443]. */
  ports?: number[];
  /** IPv4/IPv6 — omit for both */
  family?: 'ipv4' | 'ipv6' | 'both';
  /** UID/GID to exempt from capture (e.g. the proxy process itself) */
  exemptUid?: number;
}

export interface TransparentModeCapabilities {
  supported: boolean;
  reason: string;
  platform: string;
  sideCar: {
    installed: boolean;
    version: string | null;
    binaryPath: string | null;
  };
  requirements: string[];
}

export interface TransparentSessionResult {
  sessionId: string;
  started: boolean;
  reason: string;
}

export interface StopSessionResult {
  sessionId: string;
  stopped: boolean;
  reason: string;
}

// ──────────────────────────────────────────────────────────────────────────────
// Capability detection
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Returns whether transparent (TPROXY) mode is supported on this host.
 * Currently always returns false — the Rust side-car is not yet bundled.
 */
export function isTransparentModeSupported(): boolean {
  return false;
}

/**
 * Returns a detailed capability report for the transparent proxy mode.
 */
export function getTransparentModeCapabilities(): TransparentModeCapabilities {
  const isLinux = process.platform === 'linux';
  return {
    supported: false,
    reason: isLinux
      ? 'side-car not installed — install the proxyforge-tproxy sidecar to enable TPROXY capture'
      : `transparent mode requires Linux (current platform: ${process.platform})`,
    platform: process.platform,
    sideCar: {
      installed: false,
      version: null,
      binaryPath: null,
    },
    requirements: [
      'Linux kernel ≥ 4.14 with CONFIG_NETFILTER_TPROXY=y',
      'CAP_NET_ADMIN capability (or run as root)',
      'proxyforge-tproxy side-car binary in PATH or beside the Electron app',
      'iptables / nftables available',
    ],
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Session lifecycle stubs
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Starts a transparent capture session.
 * Stub — always resolves with supported: false until the side-car is present.
 */
export async function startTransparentCapture(
  config: TransparentModeConfig,
): Promise<TransparentSessionResult> {
  void config; // unused until side-car is integrated
  const sessionId = `tproxy-stub-${Date.now()}`;
  return {
    sessionId,
    started: false,
    reason: 'side-car not installed',
  };
}

/**
 * Stops a transparent capture session by ID.
 * Stub — always resolves gracefully even for unknown sessions.
 */
export async function stopTransparentCapture(
  sessionId: string,
): Promise<StopSessionResult> {
  return {
    sessionId,
    stopped: false,
    reason: 'side-car not installed (no session to stop)',
  };
}
