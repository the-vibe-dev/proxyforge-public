// Passive rule: High-risk query parameter names (debug, admin, ssrf, redir, file, etc.)
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const HIGH_RISK_PARAMS = /[?&](debug|admin|ssrf|redir|redirect|file|upload|path|exec|cmd|command|shell|eval|include|require)=/i;

export function check(requestRaw: string, _responseRaw: string, url?: string): PassiveCheckResult | null {
  const target = url ?? (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)/i.exec(requestRaw)?.[1] ?? '');
  if (!target) return null;

  const match = HIGH_RISK_PARAMS.exec(target);
  if (!match) return null;

  return {
    checkId: 'high-risk-param-names',
    title: 'High-risk query parameter name detected',
    severity: 'info',
    confidence: 'tentative',
    detail: 'Query parameter names associated with dangerous functionality (path traversal, SSRF, command injection, redirects) were found.',
    evidence: `High-risk parameter: "${match[1]}" in ${target.slice(0, 120)}`,
  };
}
