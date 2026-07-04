// WireGuard capture mode stub
//
// Real implementation requires an optional Rust side-car built with the
// `boringtun` WireGuard userspace implementation. Without it these functions
// return capability/status objects rather than throwing, allowing the rest of
// the application to degrade gracefully.

export interface WireguardModeConfig {
  /** WireGuard interface name to use (e.g. "wg0") */
  interface?: string;
  /** Base64-encoded private key for the capture peer */
  privateKey?: string;
  /** Peer public key to capture traffic from */
  peerPublicKey?: string;
  /** Peer endpoint in host:port form */
  peerEndpoint?: string;
  /** Allowed IP ranges for the WireGuard tunnel */
  allowedIps?: string[];
  /** Persistent keep-alive interval in seconds (0 = disabled) */
  keepAliveSeconds?: number;
}

export interface WireguardCapabilities {
  supported: boolean;
  reason: string;
  platform: string;
  sideCar: {
    installed: boolean;
    version: string | null;
    binaryPath: string | null;
    engine: string | null;
  };
  kernelModule: {
    available: boolean;
    reason: string;
  };
  requirements: string[];
}

export interface WireguardSessionResult {
  sessionId: string;
  started: boolean;
  reason: string;
  interface: string | null;
}

export interface StopWireguardResult {
  sessionId: string;
  stopped: boolean;
  reason: string;
}

// ──────────────────────────────────────────────────────────────────────────────
// Capability detection
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Returns whether WireGuard capture mode is supported on this host.
 * Always false until the boringtun side-car is installed.
 */
export function isWireguardSupported(): boolean {
  return false;
}

/**
 * Returns a detailed capability report for WireGuard capture mode.
 */
export function getWireguardCapabilities(): WireguardCapabilities {
  const isLinux = process.platform === 'linux';
  return {
    supported: false,
    reason: isLinux
      ? 'side-car not installed — install the proxyforge-wg sidecar to enable WireGuard capture'
      : `WireGuard capture requires Linux (current platform: ${process.platform})`,
    platform: process.platform,
    sideCar: {
      installed: false,
      version: null,
      binaryPath: null,
      engine: null,
    },
    kernelModule: {
      available: false,
      reason: isLinux
        ? 'wireguard kernel module availability not yet probed (side-car absent)'
        : `wireguard kernel module not applicable on ${process.platform}`,
    },
    requirements: [
      'Linux kernel ≥ 5.6 (built-in WireGuard) or wireguard-dkms',
      'CAP_NET_ADMIN capability (or run as root)',
      'proxyforge-wg side-car binary (built with boringtun) in PATH or beside the Electron app',
      'ip / wg-quick tools for interface management',
    ],
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Session lifecycle stubs
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Starts a WireGuard capture session.
 * Stub — always resolves with started: false until the side-car is present.
 */
export async function startWireguardCapture(
  config: WireguardModeConfig,
): Promise<WireguardSessionResult> {
  void config;
  const sessionId = `wg-stub-${Date.now()}`;
  return {
    sessionId,
    started: false,
    reason: 'side-car not installed',
    interface: config.interface ?? null,
  };
}

/**
 * Stops a WireGuard capture session by ID.
 * Stub — always resolves gracefully even for unknown session IDs.
 */
export async function stopWireguardCapture(
  sessionId: string,
): Promise<StopWireguardResult> {
  return {
    sessionId,
    stopped: false,
    reason: 'side-car not installed (no session to stop)',
  };
}
