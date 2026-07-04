// Passive rule: Java stack trace patterns in response body
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const JAVA_TRACES: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\bat\s+[a-z][a-zA-Z0-9_$]*(?:\.[a-zA-Z0-9_$]+)+\s*\(/, label: 'Java at-frame' },
  { pattern: /Exception in thread\s+"[^"]+"/i, label: 'Exception in thread' },
  { pattern: /Caused by:\s*[a-zA-Z][a-zA-Z0-9_.]+Exception/i, label: 'Caused by exception' },
  { pattern: /java\.lang\.[A-Z][a-zA-Z]+Exception/, label: 'java.lang.*Exception' },
  { pattern: /org\.springframework\.[a-zA-Z]+Exception/i, label: 'Spring exception class' },
];

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const found: string[] = [];
  for (const { pattern, label } of JAVA_TRACES) {
    if (pattern.test(body)) found.push(label);
  }

  if (found.length === 0) return null;

  return {
    checkId: 'java-stack-trace-leak',
    title: 'Java stack trace leaked in response',
    severity: 'medium',
    confidence: 'firm',
    detail: 'Java exception stack traces reveal internal package structure, class names, and line numbers, aiding targeted attacks.',
    evidence: `Stack trace indicators: ${found.join(', ')}`,
  };
}
