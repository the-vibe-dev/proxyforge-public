// Map remote rule: redirects matching URLs to a different remote URL.
export interface MapRemoteRule { id: string; fromPattern: string | RegExp; toUrl: string; enabled: boolean; }
export function resolveMapRemote(url: string, rules: MapRemoteRule[]): string | null {
  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (typeof rule.fromPattern === 'string') {
      if (url.includes(rule.fromPattern)) return url.replace(rule.fromPattern, rule.toUrl);
    } else {
      const replaced = url.replace(rule.fromPattern, rule.toUrl);
      if (replaced !== url) return replaced;
    }
  }
  return null;
}
