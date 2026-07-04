// Passive rule: /.well-known/* returning 200, /robots.txt, /sitemap.xml
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const METADATA_PATHS = [
  /\/\.well-known\//i,
  /\/robots\.txt(?:\?|$)/i,
  /\/sitemap(?:\d*|-\w+)?\.xml(?:\?|$)/i,
  /\/security\.txt(?:\?|$)/i,
  /\/humans\.txt(?:\?|$)/i,
];

export function check(_requestRaw: string, responseRaw: string, url?: string): PassiveCheckResult | null {
  if (!url) return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status < 200 || status >= 300) return null;

  const matched = METADATA_PATHS.find((p) => p.test(url));
  if (!matched) return null;

  return {
    checkId: 'wellknown-metadata',
    title: 'Well-known or metadata file accessible',
    severity: 'info',
    confidence: 'certain',
    detail: 'Metadata files like robots.txt or .well-known entries can reveal internal paths, policies, or service configurations.',
    evidence: `Accessible metadata URL: ${url}`,
  };
}
