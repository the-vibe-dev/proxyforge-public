// Passive rule: Detect /swagger.json, /openapi.yaml, /api-docs, /graphql schema exposure
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const API_DOC_PATHS = [
  /\/swagger(?:\.json|\.yaml|\.yml|-ui)?(?:\/|$|\?)/i,
  /\/openapi(?:\.json|\.yaml|\.yml)?(?:\/|$|\?)/i,
  /\/api[-_]?docs(?:\/|$|\?)/i,
  /\/graphql(?:\/|$|\?)/i,
  /\/redoc(?:\/|$|\?)/i,
  /\/v\d+\/api(?:\/|$|\?)/i,
];

export function check(_requestRaw: string, responseRaw: string, url?: string): PassiveCheckResult | null {
  if (!url) return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status < 200 || status >= 300) return null;

  const matched = API_DOC_PATHS.find((p) => p.test(url));
  if (!matched) return null;

  return {
    checkId: 'api-docs-exposure',
    title: 'API documentation or schema endpoint exposed',
    severity: 'low',
    confidence: 'certain',
    detail: 'Publicly accessible API documentation can reveal endpoints, parameters, and authentication schemes useful to attackers.',
    evidence: `URL matches API docs pattern: ${url}`,
  };
}
