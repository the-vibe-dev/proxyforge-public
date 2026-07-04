// Passive rule: Sec-Fetch-* headers sent in request with no indication of server-side validation
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  // Only flag if the browser sent Sec-Fetch-* metadata headers
  const hasFetchSite = /^Sec-Fetch-Site:\s*cross-site/im.test(requestRaw);
  if (!hasFetchSite) return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  // If server returned 200 on a cross-site request, it may not be checking
  if (status < 200 || status >= 300) return null;

  // Check for any policy header that suggests awareness
  const hasVary = /^Vary:\s*[^\r\n]*Sec-Fetch/im.test(responseRaw);
  if (hasVary) return null;

  return {
    checkId: 'fetch-metadata-not-validated',
    title: 'Fetch metadata (Sec-Fetch-Site: cross-site) not validated',
    severity: 'info',
    confidence: 'tentative',
    detail: 'The server responded 200 to a cross-site request without Vary: Sec-Fetch-*, suggesting fetch metadata isolation policies may not be enforced.',
    evidence: 'Sec-Fetch-Site: cross-site request succeeded without Vary: Sec-Fetch-* response',
  };
}
