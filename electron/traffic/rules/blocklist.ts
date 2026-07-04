// Blocklist rule: prevents requests to matching URLs.
export function isBlocked(url: string, patterns: (string | RegExp)[]): boolean {
  return patterns.some((p) => typeof p === 'string' ? url.includes(p) : p.test(url));
}
