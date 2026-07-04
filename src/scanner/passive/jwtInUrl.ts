// Passive rule: Flag JWT tokens in URL query params (3-part base64url)
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const JWT_PATTERN = /[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/;

export function check(_requestRaw: string, _responseRaw: string, url?: string): PassiveCheckResult | null {
  if (!url) return null;

  let search = '';
  try {
    const parsed = new URL(url.startsWith('http') ? url : `https://x${url}`);
    search = parsed.search;
  } catch {
    const qi = url.indexOf('?');
    if (qi !== -1) search = url.slice(qi);
  }

  if (!search) return null;
  const match = JWT_PATTERN.exec(search);
  if (!match) return null;

  return {
    checkId: 'jwt-in-url',
    title: 'JWT token in URL query parameter',
    severity: 'medium',
    confidence: 'firm',
    detail: 'A JWT-shaped token (three base64url segments) was found in the URL query string. Tokens in URLs are logged in server logs and browser history.',
    evidence: `Token fragment: "${match[0].slice(0, 60)}..."`,
  };
}
