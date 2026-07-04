// Map local rule: serves local file content for matching URL patterns.
import fs from 'node:fs';
export interface MapLocalRule { id: string; urlPattern: string | RegExp; localPath: string; enabled: boolean; }
export function resolveMapLocal(url: string, rules: MapLocalRule[]): Buffer | null {
  for (const rule of rules) {
    if (!rule.enabled) continue;
    const matches = typeof rule.urlPattern === 'string' ? url.includes(rule.urlPattern) : rule.urlPattern.test(url);
    if (!matches) continue;
    try { return fs.readFileSync(rule.localPath); } catch { return null; }
  }
  return null;
}
