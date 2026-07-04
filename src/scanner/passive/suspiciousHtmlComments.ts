// Passive rule: Suspicious HTML comments (TODO, DEBUG, password, admin, etc.)
export interface PassiveCheckResult {
  checkId: string;
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  confidence: 'tentative' | 'firm' | 'certain';
  detail: string;
  evidence?: string;
}

const COMMENT_PATTERN = /<!--([\s\S]{1,200}?)-->/g;
const SUSPICIOUS = /\b(?:TODO|FIXME|DEBUG|HACK|password|passwd|secret|admin|internal|remove\s*before|do\s*not\s*deploy|credentials?)\b/i;

export function check(_requestRaw: string, responseRaw: string, _url?: string): PassiveCheckResult | null {
  const contentType = /Content-Type:\s*([^\r\n]+)/i.exec(responseRaw)?.[1] ?? '';
  if (!contentType.includes('html') && contentType !== '') return null;

  const bodyStart = responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? responseRaw.slice(bodyStart + 4) : responseRaw;

  const found: string[] = [];
  let match: RegExpExecArray | null;
  COMMENT_PATTERN.lastIndex = 0;
  while ((match = COMMENT_PATTERN.exec(body)) !== null) {
    if (SUSPICIOUS.test(match[1])) {
      found.push(match[0].slice(0, 80));
      if (found.length >= 3) break;
    }
  }

  if (found.length === 0) return null;

  return {
    checkId: 'suspicious-html-comments',
    title: 'Suspicious HTML comment(s) detected',
    severity: 'medium',
    confidence: 'tentative',
    detail: 'HTML comments containing sensitive keywords (passwords, debug info, TODO notes) are visible to any user inspecting page source.',
    evidence: `Comment(s): ${found[0]}`,
  };
}
