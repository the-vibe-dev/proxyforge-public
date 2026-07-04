// ALPN negotiation helper for HTTP/2 and HTTP/1.1 protocol selection.

import * as tls from 'node:tls';

export const SUPPORTED_ALPN_PROTOCOLS: readonly string[] = ['h2', 'http/1.1'];

/**
 * Returns the negotiated ALPN protocol from a TLS socket, or null if none was
 * agreed upon / the socket does not support ALPN.
 */
export function negotiateAlpn(socket: tls.TLSSocket): 'h2' | 'http/1.1' | null {
  const proto = socket.alpnProtocol;
  if (proto === 'h2' || proto === 'http/1.1') return proto;
  return null;
}

/**
 * Returns true when the request headers signal an h2c (HTTP/2 cleartext)
 * upgrade via the Upgrade or Connection headers.
 */
export function shouldUpgradeToH2(requestHeaders: Record<string, string>): boolean {
  const upgrade = (requestHeaders['upgrade'] ?? '').toLowerCase();
  const connection = (requestHeaders['connection'] ?? '').toLowerCase();
  if (upgrade === 'h2c') return true;
  if (connection.split(',').map((s) => s.trim()).includes('upgrade') && upgrade === 'h2c') {
    return true;
  }
  // Also accept the Upgrade header regardless of Connection spelling
  if (upgrade.includes('h2c')) return true;
  return false;
}

/**
 * Removes the Upgrade, HTTP2-Settings, and any 'upgrade' token from the
 * Connection header — headers that are hop-by-hop for h2c negotiation.
 */
export function stripH2cUpgradeHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (lower === 'upgrade') continue;
    if (lower === 'http2-settings') continue;
    if (lower === 'connection') {
      // Remove 'upgrade' token from Connection value; drop if empty
      const tokens = value
        .split(',')
        .map((t) => t.trim())
        .filter((t) => t.toLowerCase() !== 'upgrade');
      if (tokens.length > 0) {
        result[key] = tokens.join(', ');
      }
      continue;
    }
    result[key] = value;
  }
  return result;
}
