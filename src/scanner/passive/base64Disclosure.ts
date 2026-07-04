// Passive rule: Base64-encoded values on sensitive fields (password=base64, Authorization: Basic)
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const BASIC_AUTH_HEADER = /^Authorization:\s*Basic\s+([A-Za-z0-9+/]{4,}={0,2})/im;
const SENSITIVE_B64_IN_BODY = /(?:password|passwd|pwd|secret|credential)\s*[:=]\s*["']?([A-Za-z0-9+/]{20,}={0,2})["']?/i;

export function check(requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const hits: string[] = [];

  const basicMatch = BASIC_AUTH_HEADER.exec(requestRaw);
  if (basicMatch) {
    try {
      const decoded = Buffer.from(basicMatch[1], 'base64').toString('utf-8');
      if (decoded.includes(':')) hits.push(`Basic auth credentials in request (decoded: ${decoded.split(':')[0]}:***)`);
    } catch { /* ignore */ }
  }

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;
  const bodyMatch = SENSITIVE_B64_IN_BODY.exec(body);
  if (bodyMatch) hits.push(`Sensitive field with base64-like value in response body`);

  if (hits.length === 0) return null;

  return {
    checkId: 'base64-disclosure',
    title: 'Base64-encoded credential or secret detected',
    severity: 'low',
    confidence: 'tentative',
    detail: 'Base64 encoding provides no security — credentials or secrets encoded in base64 are trivially decoded.',
    evidence: hits.join('; '),
  };
}
