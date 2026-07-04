// HTTP/3 + QUIC transport stub
//
// Real implementation requires an optional Rust side-car built with the
// `quiche` or `quinn` library (the QUIC/HTTP3 protocol stack is not available
// in vanilla Node.js or Electron's built-in modules).
// All functions here return capability/status objects and never throw so that
// the rest of the application can degrade gracefully when the side-car is
// absent.

export interface Http3TransportConfig {
  /** Maximum stream concurrency on a single QUIC connection */
  maxStreams?: number;
  /** QUIC idle timeout in milliseconds */
  idleTimeoutMs?: number;
  /** Whether to accept self-signed TLS certificates on the remote */
  allowInsecure?: boolean;
  /** Optional ALPN protocols to negotiate (defaults to ['h3']) */
  alpn?: string[];
}

export interface Http3Capabilities {
  supported: boolean;
  version: string | null;
  reason: string;
  sideCar: {
    installed: boolean;
    binaryPath: string | null;
    engine: string | null;
  };
  platform: string;
  requirements: string[];
}

export interface Http3ConnectionResult {
  connected: boolean;
  url: string;
  reason: string;
  protocol: string | null;
  /** Round-trip time sample in milliseconds, null when not connected */
  rttMs: number | null;
}

// ──────────────────────────────────────────────────────────────────────────────
// Capability detection
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Returns whether HTTP/3 is supported on this host.
 * Always false until the quiche/quinn side-car is installed.
 */
export function isHttp3Supported(): boolean {
  return false;
}

/**
 * Returns a detailed capability report for HTTP/3 / QUIC transport.
 */
export function getHttp3Capabilities(): Http3Capabilities {
  return {
    supported: false,
    version: null,
    reason: 'side-car not installed — install the proxyforge-quic sidecar to enable HTTP/3 capture',
    sideCar: {
      installed: false,
      binaryPath: null,
      engine: null,
    },
    platform: process.platform,
    requirements: [
      'proxyforge-quic side-car binary (built with quiche or quinn)',
      'UDP port reachability to target (QUIC runs over UDP)',
      'TLS 1.3 support (included in the side-car)',
    ],
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection stub
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Opens an HTTP/3 connection to the given URL.
 * Stub — always resolves with connected: false until the side-car is present.
 *
 * @param url   Target URL (must use https: scheme for QUIC)
 * @param opts  Optional transport configuration
 */
export async function openHttp3Connection(
  url: string,
  opts?: Http3TransportConfig,
): Promise<Http3ConnectionResult> {
  void opts;
  return {
    connected: false,
    url,
    reason: 'side-car not installed',
    protocol: null,
    rttMs: null,
  };
}
