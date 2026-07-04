// Passive rule: X-Frame-Options absent and no frame-ancestors CSP directive
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const contentType = /Content-Type:\s*([^\r\n]+)/i.exec(responseRaw)?.[1] ?? '';
  if (!contentType.includes('html') && contentType !== '') return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status < 200 || status >= 300) return null;

  const hasXFO = /^X-Frame-Options:/im.test(responseRaw);
  const csp = /^Content-Security-Policy:\s*([^\r\n]+)/im.exec(responseRaw)?.[1] ?? '';
  const hasFrameAncestors = /frame-ancestors/i.test(csp);

  if (hasXFO || hasFrameAncestors) return null;

  return {
    checkId: 'anti-clickjacking-missing',
    title: 'Anti-clickjacking protection missing',
    severity: 'medium',
    confidence: 'firm',
    detail: 'Neither X-Frame-Options nor a CSP frame-ancestors directive is present. The page can be embedded in an iframe for clickjacking attacks.',
    evidence: 'X-Frame-Options absent; no frame-ancestors in CSP',
  };
}
