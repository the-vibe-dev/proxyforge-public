// Passive rule: Cache-Control missing no-store on authenticated 200 responses with Set-Cookie
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status !== 200) return null;

  const hasAuth = /^(?:Authorization|Cookie):/im.test(requestRaw);
  const hasSetCookie = /^Set-Cookie:/im.test(responseRaw);
  if (!hasAuth && !hasSetCookie) return null;

  const ccMatch = /^Cache-Control:\s*([^\r\n]+)/im.exec(responseRaw);
  const cc = ccMatch ? ccMatch[1].toLowerCase() : '';
  if (cc.includes('no-store')) return null;

  return {
    checkId: 'cache-privacy-posture',
    title: 'Authenticated response may be cached',
    severity: 'medium',
    confidence: 'tentative',
    detail: 'Authenticated responses without Cache-Control: no-store may be stored by shared proxies or browser caches, exposing sensitive data.',
    evidence: `Cache-Control: ${cc || '(absent)'}; Set-Cookie: ${hasSetCookie ? 'present' : 'absent'}`,
  };
}
