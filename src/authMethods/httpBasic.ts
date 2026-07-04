// HTTP Basic authentication helpers.
// Builds RFC 7617-compliant Authorization header values.
// No external dependencies.

/**
 * Builds a Base64-encoded HTTP Basic Authorization header value.
 *
 * @returns The full header value, e.g. "Basic dXNlcjpwYXNz"
 */
export function buildBasicAuthHeader(username: string, password: string): string {
  const credentials = `${username}:${password}`;
  const encoded = Buffer.from(credentials, 'utf-8').toString('base64');
  return `Basic ${encoded}`;
}

/**
 * Decodes a Basic Authorization header value back to { username, password }.
 * Returns null if the header is not a valid Basic auth value.
 */
export function parseBasicAuthHeader(
  headerValue: string,
): { username: string; password: string } | null {
  const match = /^Basic\s+([A-Za-z0-9+/=]+)$/i.exec(headerValue.trim());
  if (!match) return null;
  const decoded = Buffer.from(match[1], 'base64').toString('utf-8');
  const colon = decoded.indexOf(':');
  if (colon < 0) return null;
  return {
    username: decoded.slice(0, colon),
    password: decoded.slice(colon + 1),
  };
}
