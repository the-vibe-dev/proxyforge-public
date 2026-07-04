// Passive rule: Referrer-Policy header absent on HTML responses
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
  if (!contentType.includes('html')) return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status < 200 || status >= 300) return null;

  if (/^Referrer-Policy:/im.test(responseRaw)) return null;

  return {
    checkId: 'referrer-policy-missing',
    title: 'Referrer-Policy header absent on HTML response',
    severity: 'info',
    confidence: 'certain',
    detail: 'Without Referrer-Policy, browsers send the full URL as a Referer header to third parties, potentially leaking sensitive path or query parameters.',
    evidence: 'Referrer-Policy header not present in response',
  };
}
