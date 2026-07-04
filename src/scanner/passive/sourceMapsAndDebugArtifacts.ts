// Passive rule: Detect X-SourceMap, SourceMappingURL, .map file exposure
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

export function check(_requestRaw: string, responseRaw: string, url?: string): PassiveCheckResult | null {
  const hits: string[] = [];

  if (/^X-SourceMap:/im.test(responseRaw)) hits.push('X-SourceMap header present');
  if (/^SourceMap:/im.test(responseRaw)) hits.push('SourceMap header present');
  if (/\/\/# sourceMappingURL=/i.test(responseRaw)) hits.push('sourceMappingURL comment in JS');
  if (url && /\.map(\?|$)/.test(url)) hits.push(`Source map file served: ${url}`);

  if (hits.length === 0) return null;

  return {
    checkId: 'source-map-exposure',
    title: 'Source map or debug artifact exposed',
    severity: 'low',
    confidence: 'certain',
    detail: 'Source maps expose original source code, file paths, and variable names to attackers.',
    evidence: hits.join('; '),
  };
}
