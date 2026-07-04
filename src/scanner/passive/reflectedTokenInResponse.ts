// Passive rule: Detect when Authorization/Bearer/token value from request appears in response body
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const authMatch = /^(?:Authorization|X-Auth-Token|X-Api-Key):\s*(.+)$/im.exec(requestRaw);
  if (!authMatch) return null;

  const tokenValue = authMatch[1].trim().replace(/^Bearer\s+/i, '');
  if (tokenValue.length < 8) return null;

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  if (!body.includes(tokenValue)) return null;

  return {
    checkId: 'reflected-token-in-response',
    title: 'Auth token reflected in response body',
    severity: 'high',
    confidence: 'firm',
    detail: 'The Authorization/token value from the request was found in the response body, potentially leaking credentials.',
    evidence: `Token value reflected: "${tokenValue.slice(0, 40)}${tokenValue.length > 40 ? '...' : ''}"`,
  };
}
