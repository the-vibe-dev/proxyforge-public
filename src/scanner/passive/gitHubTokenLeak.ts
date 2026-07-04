// Passive rule: GitHub token patterns (ghp_, gho_, ghr_, ghs_, ghu_) in response
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const GH_TOKEN = /\b(gh[phosu]_[A-Za-z0-9]{36,})\b/g;

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const found: string[] = [];
  let match: RegExpExecArray | null;
  GH_TOKEN.lastIndex = 0;
  while ((match = GH_TOKEN.exec(body)) !== null) {
    found.push(`${match[1].slice(0, 8)}...`);
    if (found.length >= 3) break;
  }

  if (found.length === 0) return null;

  return {
    checkId: 'github-token-leak',
    title: 'GitHub token exposed in response',
    severity: 'critical',
    confidence: 'certain',
    detail: 'A GitHub personal access token or OAuth token was found in the response. These tokens provide API access to GitHub resources.',
    evidence: `Token(s): ${found.join(', ')}`,
  };
}
