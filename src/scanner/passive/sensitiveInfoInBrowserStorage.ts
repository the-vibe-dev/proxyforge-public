// Passive rule: Flag localStorage/sessionStorage setItem calls with sensitive patterns in JS
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const STORAGE_CALL = /(?:localStorage|sessionStorage)\.setItem\s*\(\s*["']([^"']+)["']/gi;
const SENSITIVE_KEY = /(?:token|password|secret|auth|key|credential|session|jwt|passwd|pwd)/i;

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  let match: RegExpExecArray | null;
  const hits: string[] = [];
  STORAGE_CALL.lastIndex = 0;
  while ((match = STORAGE_CALL.exec(body)) !== null) {
    if (SENSITIVE_KEY.test(match[1])) hits.push(match[1]);
  }

  if (hits.length === 0) return null;

  return {
    checkId: 'sensitive-info-browser-storage',
    title: 'Sensitive data written to browser storage',
    severity: 'medium',
    confidence: 'tentative',
    detail: 'JavaScript code writes sensitive-named keys to localStorage or sessionStorage, which is accessible to any same-origin script.',
    evidence: `Sensitive storage keys: ${hits.slice(0, 5).join(', ')}`,
  };
}
