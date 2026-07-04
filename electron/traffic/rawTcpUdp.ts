// Raw TCP/UDP transport stub — pure Node.js, no side-car required
//
// Provides capability introspection and thin wrappers around Node's built-in
// `net` and `dgram` modules. The stubs always resolve rather than opening real
// sockets so that tests can import and call them without network access.
// Full socket integration is wired in when this module is actually used from
// the main/capture process with real config.

import type * as net from 'node:net';
import type * as dgram from 'node:dgram';

export interface RawTcpUdpConfig {
  /** Connect timeout in milliseconds */
  connectTimeoutMs?: number;
  /** Whether to enable TCP keep-alive */
  keepAlive?: boolean;
  /** Keep-alive initial delay in milliseconds */
  keepAliveInitialDelayMs?: number;
  /** Whether to disable Nagle algorithm (TCP_NODELAY) */
  noDelay?: boolean;
}

export interface TcpSocketOptions extends RawTcpUdpConfig {
  localAddress?: string;
  localPort?: number;
  family?: 4 | 6;
}

export interface UdpSocketOptions {
  family?: 4 | 6;
  /** Bind to a local port before sending */
  localPort?: number;
  localAddress?: string;
  /** Datagram receive buffer size */
  recvBufferSize?: number;
}

export interface RawTransportCapabilities {
  supported: boolean;
  tcp: {
    available: boolean;
    reason: string;
  };
  udp: {
    available: boolean;
    reason: string;
  };
  platform: string;
  nodeVersion: string;
}

export interface TcpSocketResult {
  opened: boolean;
  reason: string;
  /** Populated only when opened is true */
  socket: net.Socket | null;
}

export interface UdpSocketResult {
  opened: boolean;
  reason: string;
  /** Populated only when opened is true */
  socket: dgram.Socket | null;
}

// ──────────────────────────────────────────────────────────────────────────────
// Capability introspection
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Returns capability information for raw TCP/UDP transport.
 * Both TCP and UDP are always available via Node.js builtins.
 */
export function getRawTransportCapabilities(): RawTransportCapabilities {
  return {
    supported: true,
    tcp: {
      available: true,
      reason: 'node:net available',
    },
    udp: {
      available: true,
      reason: 'node:dgram available',
    },
    platform: process.platform,
    nodeVersion: process.version,
  };
}

// ──────────────────────────────────────────────────────────────────────────────
// Socket stubs
// ──────────────────────────────────────────────────────────────────────────────

/**
 * Opens a raw TCP socket to the given host and port.
 * In stub mode (no live capture integration) this returns an un-connected
 * result rather than actually dialling, so callers can test code paths
 * without requiring network access.
 *
 * @param host   Target hostname or IP address
 * @param port   Target TCP port (1–65535)
 * @param opts   Optional socket configuration
 */
export async function openRawTcpSocket(
  host: string,
  port: number,
  opts?: TcpSocketOptions,
): Promise<TcpSocketResult> {
  void opts;
  if (!host || host.trim().length === 0) {
    return { opened: false, reason: 'invalid host', socket: null };
  }
  if (port < 1 || port > 65535) {
    return { opened: false, reason: `invalid port: ${port}`, socket: null };
  }
  // Stub: report capability without opening a real socket
  return {
    opened: false,
    reason: 'stub — live TCP dial not active in this build',
    socket: null,
  };
}

/**
 * Opens a raw UDP socket bound to the given local address/port for sending
 * datagrams to host:port.
 * In stub mode returns an un-connected result.
 *
 * @param host  Target hostname or IP address
 * @param port  Target UDP port (1–65535)
 * @param opts  Optional socket configuration
 */
export async function openRawUdpSocket(
  host: string,
  port: number,
  opts?: UdpSocketOptions,
): Promise<UdpSocketResult> {
  void opts;
  if (!host || host.trim().length === 0) {
    return { opened: false, reason: 'invalid host', socket: null };
  }
  if (port < 1 || port > 65535) {
    return { opened: false, reason: `invalid port: ${port}`, socket: null };
  }
  // Stub: report capability without opening a real socket
  return {
    opened: false,
    reason: 'stub — live UDP bind not active in this build',
    socket: null,
  };
}
