// Upstream proxy auth: injects Proxy-Authorization for upstream proxy chains.
export function applyUpstreamAuth(headers: Record<string, string>, credentials: string): Record<string, string> {
  const encoded = Buffer.from(credentials).toString('base64');
  return { ...headers, 'Proxy-Authorization': `Basic ${encoded}` };
}
