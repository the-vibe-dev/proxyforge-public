// Passive rule: MD5/SHA-1/SHA-256/bcrypt hash patterns in response body
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const HASH_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}/, label: 'bcrypt' },
  { pattern: /\b[0-9a-f]{64}\b/i, label: 'SHA-256' },
  { pattern: /\b[0-9a-f]{40}\b/i, label: 'SHA-1' },
  { pattern: /\b[0-9a-f]{32}\b/i, label: 'MD5' },
];

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const found: string[] = [];
  for (const { pattern, label } of HASH_PATTERNS) {
    if (pattern.test(body)) {
      found.push(label);
      break; // report once per type detected to avoid noise
    }
  }

  if (found.length === 0) return null;

  return {
    checkId: 'hash-leak',
    title: 'Cryptographic hash pattern detected in response',
    severity: 'medium',
    confidence: 'tentative',
    detail: 'Hash values in responses may indicate leaked password hashes or other sensitive digests that can be cracked offline.',
    evidence: `Hash type(s) detected: ${found.join(', ')}`,
  };
}
