// Passive rule: /graphql URL returning 200 with JSON containing data/errors keys
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(_requestRaw: string, responseRaw: string, url?: string): PassiveCheckResult | null {
  const isGraphqlUrl = url ? /\/graphql(?:\/|$|\?)/i.test(url) : false;

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const contentType = /Content-Type:\s*([^\r\n]+)/i.exec(responseRaw)?.[1] ?? '';
  const isJson = contentType.includes('json');

  const hasGraphqlShape = /["'](?:data|errors)["']\s*:/.test(body) ||
    /"__schema"/.test(body) ||
    /"__typename"/.test(body);

  if (!isGraphqlUrl && !hasGraphqlShape) return null;
  if (!isGraphqlUrl && !isJson) return null;

  const statusMatch = /HTTP\/\S+\s+(\d+)/.exec(responseRaw);
  const status = statusMatch ? parseInt(statusMatch[1], 10) : 0;
  if (status < 200 || status >= 300) return null;

  return {
    checkId: 'graphql-endpoint',
    title: 'GraphQL endpoint detected',
    severity: 'info',
    confidence: isGraphqlUrl && hasGraphqlShape ? 'certain' : 'tentative',
    detail: 'A GraphQL endpoint was identified. Introspection queries may reveal the full schema.',
    evidence: `URL: ${url ?? 'unknown'}; GraphQL response shape detected: ${hasGraphqlShape}`,
  };
}
