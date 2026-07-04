// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.

export interface PassiveCheckResult {
  fired: boolean;
  evidence: string[];
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

// URL path patterns that suggest debug/trace endpoints
const DEBUG_PATH_PATTERNS: RegExp[] = [
  /\/debug(?:\/|$|\?)/i,
  /\/trace(?:\/|$|\?)/i,
  /\/phpinfo(?:\/|$|\?)/i,
  /\/info\.php$/i,
  /\/test(?:\/|$|\?)/i,
  /\/status(?:\/|$|\?)/i,
  /\/_profiler\//i,
  /\/actuator(?:\/|$)/i,
  /\/metrics(?:\/|$|\?)/i,
  /\/healthz?(?:\/|$|\?)/i,
  /\/readyz?(?:\/|$|\?)/i,
  /\/__admin(?:\/|$|\?)/i,
  /\/management(?:\/|$|\?)/i,
  /\/env(?:\/|$|\?)/i,
  /\/beans(?:\/|$|\?)/i,
  /\/heapdump(?:\/|$|\?)/i,
  /\/threaddump(?:\/|$|\?)/i,
];

// Query parameter names that signal debug mode
const DEBUG_PARAM_PATTERNS: RegExp[] = [
  /\bdebug\b/i,
  /\bXDEBUG_SESSION\b/i,
  /\btrace\b/i,
  /\bprofiler\b/i,
  /\bverbose\b/i,
  /\btest_mode\b/i,
  /\bdev\b/i,
];

// Response body patterns that indicate debug output
const DEBUG_RESPONSE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /phpinfo\(\)/i, label: 'phpinfo() output' },
  { pattern: /PHP Version\s+\d+\.\d+/i, label: 'PHP version from phpinfo' },
  { pattern: /\$_SERVER\s*=/i, label: '$_SERVER superglobal in phpinfo output' },
  { pattern: /"heap":\s*\{/i, label: 'JVM heap dump JSON' },
  { pattern: /"threads":\s*\[/i, label: 'Thread dump JSON' },
  { pattern: /"beans":\s*\{/i, label: 'Spring Actuator beans endpoint' },
  { pattern: /Symfony\s+Web\s+Debug\s+Toolbar/i, label: 'Symfony debug toolbar' },
  { pattern: /django\.debug\s*=\s*true/i, label: 'Django debug mode indicator' },
  { pattern: /Werkzeug Debugger/i, label: 'Werkzeug interactive debugger' },
];

export function check(exchange: {
  url: string;
  requestRaw: string;
  responseRaw: string;
  status?: number;
  host?: string;
}): PassiveCheckResult {
  const evidence: string[] = [];

  // Check URL path
  for (const pattern of DEBUG_PATH_PATTERNS) {
    if (pattern.test(exchange.url)) {
      const status = exchange.status ?? 0;
      if (status >= 200 && status < 400) {
        evidence.push(`Debug/admin endpoint accessible: ${exchange.url} (HTTP ${status})`);
      }
      break;
    }
  }

  // Check query parameters
  try {
    const parsed = new URL(exchange.url.startsWith('http') ? exchange.url : `https://x${exchange.url}`);
    for (const [key] of parsed.searchParams.entries()) {
      for (const p of DEBUG_PARAM_PATTERNS) {
        if (p.test(key)) {
          evidence.push(`Debug query parameter detected: "${key}" in ${exchange.url}`);
          break;
        }
      }
    }
  } catch {
    // ignore parse errors
  }

  // Check response body
  const bodyStart = exchange.responseRaw.indexOf('\r\n\r\n');
  const body = bodyStart !== -1 ? exchange.responseRaw.slice(bodyStart + 4) : '';

  if (body) {
    for (const { pattern, label } of DEBUG_RESPONSE_PATTERNS) {
      if (pattern.test(body)) {
        evidence.push(`Debug output in response body: ${label}`);
      }
    }
  }

  const severity: PassiveCheckResult['severity'] = evidence.some((e) => e.includes('phpinfo') || e.includes('heap dump') || e.includes('Werkzeug'))
    ? 'high'
    : 'medium';

  return {
    fired: evidence.length > 0,
    evidence,
    title: 'Debug endpoint / debug mode detected',
    severity,
  };
}
