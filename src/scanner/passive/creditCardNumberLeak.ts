// Passive rule: Luhn-valid 16-digit card number patterns in response body
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const CARD_PATTERN = /\b(\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4})\b/g;

function luhn(digits: string): boolean {
  const d = digits.replace(/\D/g, '');
  if (d.length !== 16) return false;
  let sum = 0;
  for (let i = 0; i < 16; i++) {
    let n = parseInt(d[15 - i], 10);
    if (i % 2 === 1) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
  }
  return sum % 10 === 0;
}

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  let match: RegExpExecArray | null;
  const found: string[] = [];
  CARD_PATTERN.lastIndex = 0;
  while ((match = CARD_PATTERN.exec(body)) !== null) {
    if (luhn(match[1])) found.push(match[1].replace(/\D/g, '').slice(0, 4) + 'xxxxxxxxxxxx');
    if (found.length >= 3) break;
  }

  if (found.length === 0) return null;

  return {
    checkId: 'credit-card-leak',
    title: 'Credit card number (Luhn-valid) in response',
    severity: 'critical',
    confidence: 'firm',
    detail: 'A Luhn-valid 16-digit sequence matching a credit card number pattern was found in the response body.',
    evidence: `Card(s) detected (masked): ${found.join(', ')}`,
  };
}
