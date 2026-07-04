// Passive rule: target="_blank" without rel="noopener noreferrer"
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const BLANK_LINK = /<a\s[^>]*target\s*=\s*["']?_blank["']?[^>]*>/gi;
const HAS_NOOPENER = /rel\s*=\s*["'][^"']*noopener[^"']*["']/i;

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const unsafe: string[] = [];
  let match: RegExpExecArray | null;
  BLANK_LINK.lastIndex = 0;
  while ((match = BLANK_LINK.exec(body)) !== null) {
    if (!HAS_NOOPENER.test(match[0])) {
      unsafe.push(match[0].slice(0, 80));
      if (unsafe.length >= 3) break;
    }
  }

  if (unsafe.length === 0) return null;

  return {
    checkId: 'blank-link-target',
    title: 'target="_blank" without rel="noopener noreferrer"',
    severity: 'low',
    confidence: 'firm',
    detail: 'Links with target="_blank" but without rel="noopener" allow the opened page to access window.opener, enabling tab-napping attacks.',
    evidence: `Unsafe links (${unsafe.length}): ${unsafe[0]}`,
  };
}
