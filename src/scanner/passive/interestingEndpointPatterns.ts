// Passive rule: Interesting management/debug endpoints (/actuator/, /metrics, /healthz, etc.)
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const INTERESTING_PATHS = [
  /\/actuator(?:\/|$)/i,
  /\/metrics(?:\/|$|\?)/i,
  /\/healthz?(?:\/|$|\?)/i,
  /\/__admin(?:\/|$|\?)/i,
  /\/debug(?:\/|$|\?)/i,
  /\/console(?:\/|$|\?)/i,
  /\/management(?:\/|$|\?)/i,
  /\/env(?:\/|$|\?)/i,
  /\/info(?:\/|$|\?)/i,
];

export function check(_requestRaw: string, responseRaw: string, url?: string): PassiveCheckResult | null {
  if (!url) return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status < 200 || status >= 300) return null;

  const matched = INTERESTING_PATHS.find((p) => p.test(url));
  if (!matched) return null;

  return {
    checkId: 'interesting-endpoint',
    title: 'Interesting management or monitoring endpoint accessible',
    severity: 'low',
    confidence: 'certain',
    detail: 'Management, health-check, or monitoring endpoints can expose internal state, metrics, or allow administrative actions.',
    evidence: `Accessible endpoint: ${url}`,
  };
}
