// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.

export interface PassiveCheckResult {
  fired: boolean;
  evidence: string[];
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

function parseHeaders(responseRaw: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const lines = responseRaw.split(/\r?\n/);
  for (const line of lines) {
    if (line.trim() === '') break;
    const sep = line.indexOf(':');
    if (sep === -1) continue;
    const key = line.slice(0, sep).trim().toLowerCase();
    const val = line.slice(sep + 1).trim();
    headers[key] = val;
  }
  return headers;
}

const MIN_MAX_AGE = 31536000; // 1 year in seconds

export function check(exchange: {
  url: string;
  requestRaw: string;
  responseRaw: string;
  status?: number;
  host?: string;
}): PassiveCheckResult {
  const evidence: string[] = [];

  // Only check HTTPS exchanges
  const isHttps = exchange.url.startsWith('https://') ||
    /^Host:\s*.+/im.test(exchange.requestRaw) && exchange.url.startsWith('/');

  // More reliable: check if the request was to HTTPS
  const requestFirstLine = exchange.requestRaw.split(/\r?\n/)[0] ?? '';
  const responseFirstLine = exchange.responseRaw.split(/\r?\n/)[0] ?? '';
  const status = exchange.status ?? parseInt(/HTTP\/\S+\s+(\d+)/.exec(responseFirstLine)?.[1] ?? '0', 10);

  // Skip non-2xx (redirects, errors typically don't need HSTS)
  if (status < 200 || status >= 300) {
    return { fired: false, evidence: [], title: 'HSTS header missing on HTTPS response', severity: 'medium' };
  }

  // Skip if not HTTPS
  if (!isHttps && !exchange.url.startsWith('https://')) {
    return { fired: false, evidence: [], title: 'HSTS header missing on HTTPS response', severity: 'medium' };
  }

  const headers = parseHeaders(exchange.responseRaw);
  const hsts = headers['strict-transport-security'];

  if (!hsts) {
    evidence.push('Strict-Transport-Security header absent on HTTPS response');
    evidence.push('Without HSTS, browsers can be downgraded from HTTPS to HTTP by an attacker');
  } else {
    // Check max-age is sufficient
    const maxAgeMatch = /max-age\s*=\s*(\d+)/i.exec(hsts);
    if (!maxAgeMatch) {
      evidence.push(`HSTS header malformed — max-age not found: "${hsts}"`);
    } else {
      const maxAge = parseInt(maxAgeMatch[1], 10);
      if (maxAge < MIN_MAX_AGE) {
        evidence.push(`HSTS max-age too short: ${maxAge}s (recommended ≥${MIN_MAX_AGE}s / 1 year)`);
      }
    }
    if (!hsts.includes('includeSubDomains')) {
      evidence.push('HSTS missing includeSubDomains — subdomains vulnerable to downgrade');
    }
  }

  return {
    fired: evidence.length > 0,
    evidence,
    title: 'HSTS header missing or weak on HTTPS response',
    severity: 'medium',
  };
}
