// Passive rule: AWS S3 bucket URL patterns in response
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const S3_PATTERNS = [
  /https?:\/\/[a-z0-9.\-]+\.s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com/gi,
  /https?:\/\/s3(?:\.[a-z0-9\-]+)?\.amazonaws\.com\/[a-z0-9.\-]+/gi,
  /s3:\/\/[a-z0-9.\-]+/gi,
];

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const found: string[] = [];
  for (const pat of S3_PATTERNS) {
    pat.lastIndex = 0;
    const m = body.match(pat);
    if (m) found.push(...m.slice(0, 2));
  }

  if (found.length === 0) return null;

  return {
    checkId: 'aws-s3-url-leak',
    title: 'AWS S3 bucket URL exposed in response',
    severity: 'medium',
    confidence: 'firm',
    detail: 'S3 bucket URLs in responses reveal cloud storage locations, bucket names, and may indicate misconfigured access controls.',
    evidence: `S3 URLs: ${[...new Set(found)].slice(0, 3).join(', ')}`,
  };
}
