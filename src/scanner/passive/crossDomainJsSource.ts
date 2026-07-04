// Passive rule: <script src="..."> loading from untrusted or unexpected cross-domain origins
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

// Well-known legitimate CDNs (allowlist to reduce noise)
const TRUSTED_CDN = /(?:cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|ajax\.googleapis\.com|code\.jquery\.com|stackpath\.bootstrapcdn\.com)/i;
const EXTERNAL_SCRIPT = /<script\s[^>]*src\s*=\s*["'](https?:\/\/([^/"']+)[^"']*)["'][^>]*>/gi;

export function check(_requestRaw: string, responseRaw: string, url?: string): PassiveCheckResult | null {
  const contentType = /Content-Type:\s*([^\r\n]+)/i.exec(responseRaw)?.[1] ?? '';
  if (!contentType.includes('html') && contentType !== '') return null;

  const pageHost = url ? (() => { try { return new URL(url).hostname; } catch { return ''; } })() : '';
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const found: string[] = [];
  let match: RegExpExecArray | null;
  EXTERNAL_SCRIPT.lastIndex = 0;
  while ((match = EXTERNAL_SCRIPT.exec(body)) !== null) {
    const host = match[2];
    if (pageHost && host === pageHost) continue;
    if (TRUSTED_CDN.test(host)) continue;
    found.push(`${host}: ${match[1].slice(0, 80)}`);
    if (found.length >= 5) break;
  }

  if (found.length === 0) return null;

  return {
    checkId: 'cross-domain-js',
    title: 'Cross-domain JavaScript source detected',
    severity: 'low',
    confidence: 'tentative',
    detail: 'Scripts loaded from untrusted third-party domains without SRI hashes create supply-chain risk.',
    evidence: `External JS sources: ${found.slice(0, 3).join('; ')}`,
  };
}
