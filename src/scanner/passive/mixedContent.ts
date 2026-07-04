// Passive rule: HTTPS page loading HTTP subresources (mixed content)
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const HTTP_RESOURCE = /(?:src|href|action)\s*=\s*["'](http:\/\/[^"']+)/gi;

export function check(_requestRaw: string, responseRaw: string, url?: string): PassiveCheckResult | null {
  if (!url?.startsWith('https://')) return null;

  const contentType = /Content-Type:\s*([^\r\n]+)/i.exec(responseRaw)?.[1] ?? '';
  if (!contentType.includes('html')) return null;

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const found: string[] = [];
  let match: RegExpExecArray | null;
  HTTP_RESOURCE.lastIndex = 0;
  while ((match = HTTP_RESOURCE.exec(body)) !== null) {
    found.push(match[1].slice(0, 80));
    if (found.length >= 5) break;
  }

  if (found.length === 0) return null;

  return {
    checkId: 'mixed-content',
    title: 'Mixed content: HTTPS page loads HTTP subresources',
    severity: 'medium',
    confidence: 'firm',
    detail: 'HTTP resources loaded on an HTTPS page can be intercepted and modified by a network attacker (active mixed content).',
    evidence: `HTTP resources: ${found.slice(0, 3).join(', ')}`,
  };
}
