// Passive rule: Cookie with overly broad Domain= scope (.tld or bare TLD)
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const setCookies = responseRaw.match(/^Set-Cookie:[^\r\n]+/gim) ?? [];
  const broad: string[] = [];

  for (const c of setCookies) {
    // Match Domain= with only one or two segments (e.g. Domain=.example.com or Domain=example.com)
    const domMatch = /;\s*[Dd]omain=\.?([^;,\s]+)/.exec(c);
    if (!domMatch) continue;
    const domain = domMatch[1];
    // Flag if domain has exactly one dot-segment (e.g. "example.com") — no subdomain restriction
    const parts = domain.split('.');
    if (parts.length <= 2) {
      broad.push(domain);
    }
  }

  if (broad.length === 0) return null;

  return {
    checkId: 'loosely-scoped-cookie',
    title: 'Cookie scoped to overly broad domain',
    severity: 'low',
    confidence: 'tentative',
    detail: 'A cookie Domain attribute set to a bare TLD or root domain makes it accessible to all subdomains, increasing the blast radius of any subdomain compromise.',
    evidence: `Broad Domain scope(s): ${broad.join(', ')}`,
  };
}
