// Passive rule: <script src="cdn..."> without integrity= attribute (SRI missing)
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const EXTERNAL_SCRIPT = /<script\s[^>]*src\s*=\s*["'](https?:\/\/[^"']+)["'][^>]*>/gi;
const HAS_INTEGRITY = /\bintegrity\s*=/i;

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const contentType = /Content-Type:\s*([^\r\n]+)/i.exec(responseRaw)?.[1] ?? '';
  if (!contentType.includes('html') && contentType !== '') return null;

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const missing: string[] = [];
  let match: RegExpExecArray | null;
  EXTERNAL_SCRIPT.lastIndex = 0;
  while ((match = EXTERNAL_SCRIPT.exec(body)) !== null) {
    if (!HAS_INTEGRITY.test(match[0])) {
      missing.push(match[1].slice(0, 80));
      if (missing.length >= 5) break;
    }
  }

  if (missing.length === 0) return null;

  return {
    checkId: 'sri-missing',
    title: 'Subresource Integrity (SRI) missing on external script',
    severity: 'low',
    confidence: 'firm',
    detail: 'External scripts without integrity= hashes can be silently tampered with at the CDN, allowing supply-chain XSS.',
    evidence: `Scripts without SRI: ${missing.slice(0, 3).join(', ')}`,
  };
}
