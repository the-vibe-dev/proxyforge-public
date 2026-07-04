// Strip DNS HTTPS records / Alt-Svc from responses to prevent h3 upgrade.
export function stripDnsHttpsHeaders(headers: Record<string, string>): Record<string, string> {
  const result = { ...headers };
  delete result['alt-svc'];
  delete result['Alt-Svc'];
  return result;
}
