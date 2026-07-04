// Passive rule: RFC-1918 private IP addresses leaked in response body
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const PRIVATE_IP = /\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3})\b/g;

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const found: string[] = [];
  let match: RegExpExecArray | null;
  PRIVATE_IP.lastIndex = 0;
  while ((match = PRIVATE_IP.exec(body)) !== null) {
    if (!found.includes(match[1])) found.push(match[1]);
    if (found.length >= 5) break;
  }

  if (found.length === 0) return null;

  return {
    checkId: 'private-ip-leak',
    title: 'Private IP address leaked in response',
    severity: 'medium',
    confidence: 'firm',
    detail: 'Private or loopback IP addresses in responses reveal internal network topology, useful for lateral movement planning.',
    evidence: `Private IPs: ${found.join(', ')}`,
  };
}
