// Passive rule: X-Content-Type-Options: nosniff absent
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status < 200 || status >= 300) return null;

  const xcto = /^X-Content-Type-Options:\s*([^\r\n]+)/im.exec(responseRaw)?.[1]?.trim() ?? '';
  if (/nosniff/i.test(xcto)) return null;

  return {
    checkId: 'x-content-type-options-missing',
    title: 'X-Content-Type-Options: nosniff header missing',
    severity: 'low',
    confidence: 'certain',
    detail: 'Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses, allowing certain content-type confusion attacks.',
    evidence: xcto ? `Header present but value is "${xcto}"` : 'X-Content-Type-Options header absent',
  };
}
