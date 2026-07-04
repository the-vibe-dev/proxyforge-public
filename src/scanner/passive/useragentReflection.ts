// Passive rule: User-Agent request header value reflected in response body
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const uaMatch = /^User-Agent:\s*(.+)$/im.exec(requestRaw);
  if (!uaMatch) return null;

  const ua = uaMatch[1].trim();
  if (ua.length < 10) return null;

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  // Check for a meaningful substring (not just a common word)
  const snippet = ua.slice(0, 30);
  if (!body.includes(snippet)) return null;

  return {
    checkId: 'useragent-reflection',
    title: 'User-Agent header reflected in response body',
    severity: 'low',
    confidence: 'firm',
    detail: 'The User-Agent request header value appears in the response body. If not properly encoded, this could be a stored or reflected XSS vector.',
    evidence: `Reflected User-Agent: "${ua.slice(0, 60)}"`,
  };
}
