// Passive rule: Internal hostnames or RFC-1918 IPs leaked in response
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const INTERNAL_HOST = /\b(?:[a-z0-9-]+\.(?:internal|local|intranet|corp|lan))\b/i;
const PRIVATE_IP = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/;

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const hits: string[] = [];
  const h = INTERNAL_HOST.exec(body);
  if (h) hits.push(`Internal hostname: ${h[0]}`);
  const ip = PRIVATE_IP.exec(body);
  if (ip) hits.push(`Private IP: ${ip[0]}`);

  if (hits.length === 0) return null;

  return {
    checkId: 'internal-host-leaked',
    title: 'Internal hostname or private IP leaked in response',
    severity: 'medium',
    confidence: 'firm',
    detail: 'Internal network addresses or hostnames in responses reveal infrastructure topology useful for lateral movement.',
    evidence: hits.join('; '),
  };
}
