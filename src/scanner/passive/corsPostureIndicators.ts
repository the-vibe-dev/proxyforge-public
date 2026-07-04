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

export function check(exchange: {
  url: string;
  requestRaw: string;
  responseRaw: string;
  status?: number;
  host?: string;
}): PassiveCheckResult {
  const evidence: string[] = [];
  let severity: PassiveCheckResult['severity'] = 'info';

  const headers = parseHeaders(exchange.responseRaw);
  const acao = headers['access-control-allow-origin'];
  const acac = (headers['access-control-allow-credentials'] ?? '').toLowerCase();
  const acam = headers['access-control-allow-methods'];
  const acah = headers['access-control-allow-headers'];
  const vary = (headers['vary'] ?? '').toLowerCase();
  const credentialed = acac === 'true';

  if (!acao) {
    // No CORS headers — not necessarily a problem but worth noting if request had Origin
    const hasOrigin = /\nOrigin:\s*.+/i.test(exchange.requestRaw);
    if (hasOrigin) {
      evidence.push('Request included Origin header but response has no CORS headers — CORS not configured');
    }
    return { fired: evidence.length > 0, evidence, title: 'CORS posture indicators', severity: 'info' };
  }

  // Wildcard + credentials (invalid per spec but some servers emit it)
  if (acao === '*' && credentialed) {
    evidence.push('Critical: ACAO: * combined with ACAC: true — credentials allowed with wildcard (spec violation, some browsers ignore, some expose)');
    severity = 'high';
  }

  // Wildcard without credentials (permissive but usually intentional for public APIs)
  if (acao === '*' && !credentialed) {
    evidence.push('ACAO: * (wildcard) — any origin may read response; acceptable for public APIs but flag for review');
    severity = 'low';
  }

  // null origin
  if (acao === 'null') {
    evidence.push('ACAO: null — null origin allowed; sandboxed iframes can exploit this with credentials');
    severity = credentialed ? 'high' : 'medium';
  }

  // Reflected origin with credentials
  if (credentialed && acao !== '*' && acao !== 'null') {
    // Check if it varies
    if (!vary.includes('origin')) {
      evidence.push(`ACAO reflects specific origin "${acao}" with ACAC: true but Vary: Origin not set — cache poisoning risk`);
      severity = 'medium';
    } else {
      evidence.push(`ACAO reflects origin "${acao}" with ACAC: true and Vary: Origin present — standard credentialed CORS`);
    }

    // Check if the origin looks like a wildcard-ish match (*.domain)
    if (acao && !acao.startsWith('https://') && !acao.startsWith('http://') && acao !== 'null' && acao !== '*') {
      evidence.push(`Unusual ACAO format "${acao}" — verify origin matching logic in server code`);
      severity = 'medium';
    }
  }

  // Dangerous methods allowed
  if (acam && /DELETE|PUT|PATCH/i.test(acam)) {
    evidence.push(`ACAM allows dangerous methods: ${acam}`);
    if (severity === 'info') severity = 'low';
  }

  // Sensitive headers exposed
  if (acah) {
    const sensitiveHeaders = ['authorization', 'x-api-key', 'x-auth-token', 'cookie'];
    for (const sh of sensitiveHeaders) {
      if (acah.toLowerCase().includes(sh)) {
        evidence.push(`ACAH allows sensitive header: "${sh}" in "${acah}"`);
        if (severity === 'info' || severity === 'low') severity = 'medium';
      }
    }
  }

  // Vary: Origin missing with credentialed CORS
  if (credentialed && !vary.includes('origin') && acao !== '*') {
    evidence.push('Credentialed CORS response missing Vary: Origin — may cause cache-based CORS bypass');
    if (severity === 'info') severity = 'medium';
  }

  return {
    fired: evidence.length > 0,
    evidence,
    title: 'CORS posture indicators — Access-Control-Allow-* triage',
    severity,
  };
}
