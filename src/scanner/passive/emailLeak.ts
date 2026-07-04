// Passive rule: Email address patterns in response body not present in request
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const EMAIL_PATTERN = /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/g;

export function check(requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const found: string[] = [];
  let match: RegExpExecArray | null;
  EMAIL_PATTERN.lastIndex = 0;
  while ((match = EMAIL_PATTERN.exec(body)) !== null) {
    if (!requestRaw.includes(match[0])) {
      found.push(match[0]);
    }
    if (found.length >= 5) break;
  }

  if (found.length === 0) return null;

  return {
    checkId: 'email-leak',
    title: 'Email address(es) leaked in response',
    severity: 'low',
    confidence: 'tentative',
    detail: 'Email addresses found in the response were not present in the request, suggesting server-side data leakage.',
    evidence: `Emails: ${found.join(', ')}`,
  };
}
