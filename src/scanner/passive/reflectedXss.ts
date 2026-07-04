// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.

export interface PassiveCheckResult {
  fired: boolean;
  evidence: string[];
  title: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
}

export function check(exchange: {
  url: string;
  requestRaw: string;
  responseRaw: string;
  status?: number;
  host?: string;
}): PassiveCheckResult {
  const evidence: string[] = [];

  // Extract query parameters from URL
  let searchParams: URLSearchParams;
  try {
    const parsed = new URL(exchange.url.startsWith('http') ? exchange.url : `https://example.com${exchange.url}`);
    searchParams = parsed.searchParams;
  } catch {
    return { fired: false, evidence: [], title: 'Passive reflected XSS detection', severity: 'high' };
  }

  const responseBody = exchange.responseRaw;
  const contentType = (() => {
    const match = /Content-Type:\s*([^\r\n]+)/i.exec(exchange.responseRaw);
    return match ? match[1].toLowerCase() : '';
  })();

  // Only check HTML/JavaScript responses
  const isHtmlish = contentType.includes('html') || contentType.includes('javascript') || contentType === '';
  if (!isHtmlish) {
    return { fired: false, evidence: [], title: 'Passive reflected XSS detection', severity: 'high' };
  }

  const XSS_PATTERNS = [
    /<script[^>]*>/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /data:\s*text\/html/i,
    /vbscript:/i,
    /<img[^>]+src[^>]*onerror/i,
    /<svg[^>]*onload/i,
  ];

  for (const [key, value] of searchParams.entries()) {
    if (value.length < 3) continue;

    // Check if the param value is reflected in the response
    if (!responseBody.includes(value)) continue;

    // Check if the reflected value is near an XSS pattern
    const idx = responseBody.indexOf(value);
    const surrounding = responseBody.slice(Math.max(0, idx - 200), idx + value.length + 200);

    for (const pattern of XSS_PATTERNS) {
      if (pattern.test(surrounding) || pattern.test(value)) {
        evidence.push(`Parameter "${key}" with value "${value.slice(0, 50)}" reflected near XSS pattern in response`);
        evidence.push(`Context: ...${surrounding.slice(0, 100)}...`);
        break;
      }
    }

    // Check for angle brackets in reflected value without encoding
    if ((value.includes('<') || value.includes('>')) && responseBody.includes(value)) {
      evidence.push(`Unencoded angle brackets in reflected parameter "${key}" — potential XSS sink`);
    }
  }

  // Also check POST body params
  const bodyMatch = exchange.requestRaw.split('\r\n\r\n')[1] ?? '';
  if (bodyMatch) {
    try {
      const bodyParams = new URLSearchParams(bodyMatch);
      for (const [key, value] of bodyParams.entries()) {
        if (value.length < 3) continue;
        if (!responseBody.includes(value)) continue;
        if (XSS_PATTERNS.some((p) => p.test(value))) {
          evidence.push(`POST body parameter "${key}" with XSS value reflected in response`);
        }
      }
    } catch {
      // ignore parse errors
    }
  }

  return {
    fired: evidence.length > 0,
    evidence,
    title: 'Passive reflected XSS detection',
    severity: 'high',
  };
}
