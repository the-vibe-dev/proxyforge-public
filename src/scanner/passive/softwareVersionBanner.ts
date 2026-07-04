// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.

export interface PassiveCheckResult {
  fired: boolean;
  evidence: string[];
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

// Header names that commonly disclose software versions
const VERSION_HEADERS: Array<{ header: string; pattern: RegExp }> = [
  { header: 'server', pattern: /^(apache|nginx|iis|lighttpd|litespeed|openresty|gunicorn|uvicorn|tomcat|jetty|jboss|wildfly)[^$]*/i },
  { header: 'x-powered-by', pattern: /\d+\.\d+/i },
  { header: 'x-aspnet-version', pattern: /\d+\.\d+/i },
  { header: 'x-aspnetmvc-version', pattern: /\d+\.\d+/i },
  { header: 'x-backend-server', pattern: /.+/ },
  { header: 'x-generator', pattern: /.+/ },
  { header: 'x-drupal-cache', pattern: /.+/ },
  { header: 'x-wp-total', pattern: /.+/ },
  { header: 'via', pattern: /[0-9]+\.[0-9]+\s+\S+/i },
];

// Version number extraction pattern
const VERSION_RE = /\b\d+\.\d+(?:\.\d+)*\b/;

function parseHeaders(responseRaw: string): Record<string, string> {
  const headers: Record<string, string> = {};
  const lines = responseRaw.split(/\r?\n/);
  for (const line of lines) {
    if (line.trim() === '') break; // end of headers
    const sep = line.indexOf(':');
    if (sep === -1) continue;
    const key = line.slice(0, sep).trim().toLowerCase();
    const val = line.slice(sep + 1).trim();
    headers[key] = val;
  }
  return headers;
}

export function check(exchange: {
  url: string;
  requestRaw: string;
  responseRaw: string;
  status?: number;
  host?: string;
}): PassiveCheckResult {
  const evidence: string[] = [];
  const headers = parseHeaders(exchange.responseRaw);

  for (const { header, pattern } of VERSION_HEADERS) {
    const value = headers[header];
    if (!value) continue;

    if (pattern.test(value)) {
      const versionMatch = VERSION_RE.exec(value);
      const versionStr = versionMatch ? ` (version: ${versionMatch[0]})` : '';
      evidence.push(`${header}: ${value}${versionStr} — software version disclosed`);
    }
  }

  // Also check for version in meta generator or comments in body
  const bodySection = exchange.responseRaw.split(/\r?\n\r?\n/)[1] ?? '';
  const metaGen = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i.exec(bodySection);
  if (metaGen) {
    const genValue = metaGen[1];
    if (VERSION_RE.test(genValue)) {
      evidence.push(`HTML meta generator tag discloses version: "${genValue}"`);
    }
  }

  return {
    fired: evidence.length > 0,
    evidence,
    title: 'Software version disclosure in response headers',
    severity: 'info',
  };
}
