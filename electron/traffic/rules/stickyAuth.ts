// Sticky auth rule: pins an Authorization header value.
export function applyStickyAuth(headers: Record<string, string>, authValue: string): Record<string, string> {
  return { ...headers, Authorization: authValue };
}
