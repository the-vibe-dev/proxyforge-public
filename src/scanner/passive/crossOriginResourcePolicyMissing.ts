// Passive rule: Cross-Origin-Resource-Policy header missing on API JSON responses
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const contentType = /Content-Type:\s*([^\r\n]+)/i.exec(responseRaw)?.[1] ?? '';
  if (!contentType.includes('json')) return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status < 200 || status >= 300) return null;

  if (/^Cross-Origin-Resource-Policy:/im.test(responseRaw)) return null;

  return {
    checkId: 'corp-missing',
    title: 'Cross-Origin-Resource-Policy (CORP) header missing on JSON API',
    severity: 'info',
    confidence: 'tentative',
    detail: 'Without CORP, browser side-channel attacks (e.g., Spectre) can leak cross-origin JSON responses included via <img> or <script> tags.',
    evidence: 'Cross-Origin-Resource-Policy header absent on JSON response',
  };
}
