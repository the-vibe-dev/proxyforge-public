// Passive rule: eval(), Function(), setTimeout(string), document.write in response JS
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const DANGEROUS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\beval\s*\(/g, label: 'eval()' },
  { pattern: /\bnew\s+Function\s*\(/g, label: 'new Function()' },
  { pattern: /\bsetTimeout\s*\(\s*["'`]/g, label: 'setTimeout(string)' },
  { pattern: /\bsetInterval\s*\(\s*["'`]/g, label: 'setInterval(string)' },
  { pattern: /\bdocument\.write\s*\(/g, label: 'document.write()' },
];

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const contentType = /Content-Type:\s*([^\r\n]+)/i.exec(responseRaw)?.[1] ?? '';
  if (!contentType.includes('javascript') && !contentType.includes('html') && contentType !== '') return null;

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const found: string[] = [];
  for (const { pattern, label } of DANGEROUS) {
    pattern.lastIndex = 0;
    if (pattern.test(body)) found.push(label);
  }

  if (found.length === 0) return null;

  return {
    checkId: 'dangerous-js-function',
    title: 'Dangerous JavaScript function usage detected',
    severity: 'low',
    confidence: 'tentative',
    detail: 'Usage of eval(), new Function(), or string-based timers can indicate DOM-based XSS sinks or unsafe coding practices.',
    evidence: `Dangerous functions: ${found.join(', ')}`,
  };
}
