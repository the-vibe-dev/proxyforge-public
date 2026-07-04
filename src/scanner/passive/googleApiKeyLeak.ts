// Passive rule: Google API key pattern (AIza...) in response
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const GOOGLE_KEY = /AIza[0-9A-Za-z\-_]{35}/g;

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const matches = body.match(GOOGLE_KEY);
  if (!matches) return null;

  return {
    checkId: 'google-api-key-leak',
    title: 'Google API key exposed in response',
    severity: 'high',
    confidence: 'firm',
    detail: 'A Google API key (AIza prefix) was found in the response. Exposed keys can be abused to make API calls billed to the key owner.',
    evidence: `Key: ${matches[0].slice(0, 8)}... (${matches.length} match(es))`,
  };
}
