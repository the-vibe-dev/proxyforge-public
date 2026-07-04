// Passive rule: Cache-Control and Pragma absent on authenticated pages
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const hasAuth = /^(?:Authorization|Cookie):/im.test(requestRaw);
  if (!hasAuth) return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status < 200 || status >= 300) return null;

  const contentType = /Content-Type:\s*([^\r\n]+)/i.exec(responseRaw)?.[1] ?? '';
  if (!contentType.includes('html') && !contentType.includes('json')) return null;

  const hasCC = /^Cache-Control:/im.test(responseRaw);
  const hasPragma = /^Pragma:/im.test(responseRaw);
  if (hasCC || hasPragma) return null;

  return {
    checkId: 'cache-control-missing',
    title: 'Cache-Control and Pragma absent on authenticated response',
    severity: 'low',
    confidence: 'tentative',
    detail: 'Authenticated responses without caching directives may be stored by proxy caches or browser, exposing sensitive data to subsequent users.',
    evidence: 'Neither Cache-Control nor Pragma header found on authenticated response',
  };
}
