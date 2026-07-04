// Proxy access auth: validates a Proxy-Authorization header on incoming proxy connections.
export function validateProxyAuth(authHeader: string | undefined, expectedCredentials: string): boolean {
  if (!authHeader) return false;
  const match = authHeader.match(/^Basic\s+(.+)$/i);
  if (!match) return false;
  const decoded = Buffer.from(match[1], 'base64').toString('utf8');
  return decoded === expectedCredentials;
}
