// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.

export interface PassiveCheckResult {
  fired: boolean;
  evidence: string[];
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

// Parameter names commonly used for redirects
const REDIRECT_PARAM_NAMES = [
  'redirect', 'redirect_uri', 'redirect_url', 'return', 'returnto', 'return_url',
  'next', 'url', 'goto', 'dest', 'destination', 'target', 'rurl', 'continue',
  'forward', 'location', 'callback', 'ref', 'referer', 'r', 'go', 'path',
  'from', 'returnurl', 'back', 'backurl', 'exit', 'jump',
];

// Dangerous URL schemes / patterns that indicate open redirect / protocol injection
const DANGEROUS_SCHEMES = [
  /^javascript:/i,
  /^data:/i,
  /^vbscript:/i,
  /^\/\//,                // Protocol-relative //evil.com
  /^\\{1,2}/,             // Backslash \\evil.com
  // Note: absolute HTTP(S) URLs are handled by the cross-origin check below, not here
];

export function check(exchange: {
  url: string;
  requestRaw: string;
  responseRaw: string;
  status?: number;
  host?: string;
}): PassiveCheckResult {
  const evidence: string[] = [];
  const host = exchange.host ?? (() => {
    try { return new URL(exchange.url).hostname; } catch { return ''; }
  })();

  let searchParams: URLSearchParams;
  try {
    const parsed = new URL(exchange.url.startsWith('http') ? exchange.url : `https://example.com${exchange.url}`);
    searchParams = parsed.searchParams;
  } catch {
    return { fired: false, evidence: [], title: 'Suspicious redirect parameter', severity: 'medium' };
  }

  for (const [key, value] of searchParams.entries()) {
    const keyLower = key.toLowerCase();
    const isRedirectParam = REDIRECT_PARAM_NAMES.some((n) => keyLower === n || keyLower.includes(n));
    if (!isRedirectParam || value.length === 0) continue;

    for (const scheme of DANGEROUS_SCHEMES) {
      if (scheme.test(value)) {
        evidence.push(`Dangerous redirect parameter: "${key}=${value.slice(0, 100)}" matches scheme pattern`);
        break;
      }
    }

    // Cross-origin absolute URL: different host from the app
    if (/^https?:\/\//i.test(value)) {
      try {
        const targetHost = new URL(value).hostname;
        if (host && targetHost !== host && !targetHost.endsWith('.' + host)) {
          evidence.push(`Open redirect candidate: param "${key}" points to external host "${targetHost}" (app host: "${host}")`);
        }
      } catch {
        // malformed URL — flag as suspicious
        evidence.push(`Malformed URL in redirect param "${key}": "${value.slice(0, 80)}"`);
      }
    }
  }

  // Check Location header in response for dangerous redirect values
  const locationMatch = /^Location:\s*(.+)$/im.exec(exchange.responseRaw);
  if (locationMatch) {
    const loc = locationMatch[1].trim();
    for (const scheme of DANGEROUS_SCHEMES) {
      if (scheme.test(loc)) {
        evidence.push(`Response Location header contains dangerous redirect: "${loc.slice(0, 100)}"`);
        break;
      }
    }
  }

  return {
    fired: evidence.length > 0,
    evidence,
    title: 'Suspicious redirect parameter',
    severity: 'medium',
  };
}
