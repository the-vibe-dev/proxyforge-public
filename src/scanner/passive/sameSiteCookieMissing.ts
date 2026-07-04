// Passive rule: Set-Cookie without SameSite attribute on authenticated responses
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const hasAuth = /^(?:Authorization|Cookie):/im.test(requestRaw);
  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (!hasAuth && status !== 200) return null;

  const setCookies = responseRaw.match(/^Set-Cookie:[^\r\n]+/gim) ?? [];
  const missing = setCookies.filter((c) => !/samesite/i.test(c));

  if (missing.length === 0) return null;

  const names = missing.map((c) => /Set-Cookie:\s*([^=;]+)/i.exec(c)?.[1]?.trim() ?? '?');

  return {
    checkId: 'samesite-cookie-missing',
    title: 'Set-Cookie missing SameSite attribute',
    severity: 'medium',
    confidence: 'firm',
    detail: 'Cookies without SameSite are sent on cross-site requests by default, enabling CSRF attacks.',
    evidence: `Cookies without SameSite: ${names.join(', ')}`,
  };
}
