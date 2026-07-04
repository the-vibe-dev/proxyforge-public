// Passive rule: Sensitive query params (api_key, token, session, password) in request URL
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const SENSITIVE_PARAMS = /[?&](api[_-]?key|token|session|password|passwd|secret|access[_-]?token|auth)=/i;

export function check(requestRaw: string, _responseRaw: string, url?: string): PassiveCheckResult | null {
  const target = url ?? (/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\S+)/i.exec(requestRaw)?.[1] ?? '');
  if (!target) return null;

  const match = SENSITIVE_PARAMS.exec(target);
  if (!match) return null;

  return {
    checkId: 'tokens-in-url',
    title: 'Sensitive credential in URL query parameter',
    severity: 'medium',
    confidence: 'firm',
    detail: 'Secrets or tokens in URLs are captured in server access logs, browser history, and Referer headers.',
    evidence: `Sensitive parameter "${match[1]}" found in URL: ${target.slice(0, 120)}`,
  };
}
