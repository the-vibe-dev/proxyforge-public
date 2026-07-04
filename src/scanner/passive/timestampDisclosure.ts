// Passive rule: Unix epoch, x-runtime header, build timestamps in response
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const UNIX_EPOCH = /\b1[3-9]\d{8}\b/; // 10-digit unix timestamps from 2010+
const BUILD_TIMESTAMP = /(?:build|compiled|generated|version)\s*(?:at|on|date)?\s*[:=]?\s*["']?(\d{4}-\d{2}-\d{2})/i;

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const hits: string[] = [];

  if (/^X-Runtime:/im.test(responseRaw)) {
    const rt = /^X-Runtime:\s*([^\r\n]+)/im.exec(responseRaw)?.[1];
    hits.push(`X-Runtime: ${rt}`);
  }

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const ep = UNIX_EPOCH.exec(body);
  if (ep) hits.push(`Unix timestamp: ${ep[0]}`);

  const bt = BUILD_TIMESTAMP.exec(body);
  if (bt) hits.push(`Build timestamp: ${bt[1]}`);

  if (hits.length === 0) return null;

  return {
    checkId: 'timestamp-disclosure',
    title: 'Server or build timestamp disclosed',
    severity: 'info',
    confidence: 'tentative',
    detail: 'Timestamps in responses reveal server timing, framework version age, or deployment cadence, aiding fingerprinting.',
    evidence: hits.join('; '),
  };
}
