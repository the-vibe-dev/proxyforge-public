// Passive rule: Flag secret-like strings (API keys, tokens) in JS bundles
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const SECRET_PATTERN = /(?:api[_-]?key|secret|token)\s*[:=]\s*["']([A-Za-z0-9]{20,})/gi;

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const contentType = /Content-Type:\s*([^\r\n]+)/i.exec(responseRaw)?.[1] ?? '';
  if (!contentType.includes('javascript') && !contentType.includes('html') && contentType !== '') return null;

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const hits: string[] = [];
  let match: RegExpExecArray | null;
  SECRET_PATTERN.lastIndex = 0;
  while ((match = SECRET_PATTERN.exec(body)) !== null) {
    hits.push(`"${match[1].slice(0, 12)}..."`);
    if (hits.length >= 3) break;
  }

  if (hits.length === 0) return null;

  return {
    checkId: 'client-config-secret',
    title: 'Secret-like value in client-side JS bundle',
    severity: 'high',
    confidence: 'tentative',
    detail: 'An API key, secret, or token pattern was found in client-side JavaScript. Hardcoded secrets in client code are publicly accessible.',
    evidence: `Matched values: ${hits.join(', ')}`,
  };
}
