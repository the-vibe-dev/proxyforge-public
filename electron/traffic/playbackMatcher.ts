// Match incoming raw HTTP requests to canned responses for server playback.

export interface PlaybackMatchRule {
  method?: string;
  urlPattern?: string;
  headerMatch?: Record<string, string>;
  bodyContains?: string;
  responseRaw: string;
}

/** Returns the canned responseRaw for the first matching rule, or null. */
export type PlaybackMatchFn = (requestRaw: string) => string | null;

/**
 * Converts a glob pattern that supports only '*' wildcards into a RegExp.
 * A bare '*' matches any substring; the rest of the pattern is treated as
 * a literal string.
 */
function globToRegex(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  const withWild = escaped.replace(/\*/g, '.*');
  return new RegExp(`^${withWild}$`);
}

/**
 * Extracts the first request line from a raw HTTP request string.
 * Returns an object with method, path, and (for HTTP/1.1) the full URL.
 */
function parseRequestLine(requestRaw: string): {
  method: string;
  urlPath: string;
  fullLine: string;
} {
  const firstLine = requestRaw.split(/\r?\n/)[0] ?? '';
  const parts = firstLine.split(' ');
  return {
    method: (parts[0] ?? '').toUpperCase(),
    urlPath: parts[1] ?? '/',
    fullLine: firstLine,
  };
}

/**
 * Returns true when the request method (first token of the request line)
 * matches the given method (case-insensitive).
 */
export function matchesMethod(requestRaw: string, method: string): boolean {
  const { method: reqMethod } = parseRequestLine(requestRaw);
  return reqMethod === method.toUpperCase();
}

/**
 * Returns true when the URL path from the request line matches pattern.
 * Supports '*' as a wildcard; otherwise performs an exact match.
 */
export function matchesUrlPattern(requestRaw: string, pattern: string): boolean {
  const { urlPath } = parseRequestLine(requestRaw);
  if (pattern.includes('*')) {
    return globToRegex(pattern).test(urlPath);
  }
  return urlPath === pattern;
}

/**
 * Returns true when the raw request body (everything after the blank line
 * separating headers from body) contains the given substring.
 * Handles both CRLF (\r\n\r\n) and LF (\n\n) line endings.
 */
export function matchesBodyContains(requestRaw: string, substring: string): boolean {
  // Try CRLF separator first (standard HTTP), then bare LF
  const crlfSep = requestRaw.indexOf('\r\n\r\n');
  if (crlfSep !== -1) {
    const body = requestRaw.slice(crlfSep + 4);
    return body.includes(substring);
  }
  const lfSep = requestRaw.indexOf('\n\n');
  if (lfSep !== -1) {
    const body = requestRaw.slice(lfSep + 2);
    return body.includes(substring);
  }
  return false;
}

/**
 * Returns true when every header in headerMatch appears in the raw request
 * (case-insensitive key comparison, case-sensitive value comparison).
 */
function matchesHeaders(
  requestRaw: string,
  headerMatch: Record<string, string>,
): boolean {
  // Split on CRLF+CRLF (standard HTTP) or bare LF+LF
  const headerSection = requestRaw.split(/\r?\n\r?\n/)[0] ?? '';
  for (const [key, value] of Object.entries(headerMatch)) {
    const keyLower = key.toLowerCase();
    const headerLine = headerSection
      .split(/\r?\n/)
      .find((line) => line.toLowerCase().startsWith(`${keyLower}:`));
    if (!headerLine) return false;
    const actualValue = headerLine.slice(keyLower.length + 1).trim();
    if (actualValue !== value) return false;
  }
  return true;
}

/**
 * Builds a PlaybackMatchFn from an ordered list of rules.
 * Rules are evaluated in order; the first match wins.
 */
export function buildMatchFn(rules: PlaybackMatchRule[]): PlaybackMatchFn {
  return (requestRaw: string): string | null => {
    for (const rule of rules) {
      if (rule.method !== undefined && !matchesMethod(requestRaw, rule.method)) {
        continue;
      }
      if (
        rule.urlPattern !== undefined &&
        !matchesUrlPattern(requestRaw, rule.urlPattern)
      ) {
        continue;
      }
      if (
        rule.headerMatch !== undefined &&
        !matchesHeaders(requestRaw, rule.headerMatch)
      ) {
        continue;
      }
      if (
        rule.bodyContains !== undefined &&
        !matchesBodyContains(requestRaw, rule.bodyContains)
      ) {
        continue;
      }
      return rule.responseRaw;
    }
    return null;
  };
}

/**
 * Extracts the HTTP status code and status text from a raw response string.
 * Handles both HTTP/1.1 and HTTP/2 response formats.
 * Returns status=0 and empty statusText when parsing fails.
 */
export function parseResponseStatus(responseRaw: string): {
  status: number;
  statusText: string;
} {
  const firstLine = responseRaw.split(/\r?\n/)[0] ?? '';
  // HTTP/1.x: "HTTP/1.1 200 OK"
  const http1Match = firstLine.match(/^HTTP\/\S+\s+(\d{3})\s*(.*)/);
  if (http1Match) {
    return {
      status: parseInt(http1Match[1], 10),
      statusText: http1Match[2].trim(),
    };
  }
  // Fallback: look for a bare status code at the start of the first line
  const bareMatch = firstLine.match(/\b(\d{3})\b\s*(.*)/);
  if (bareMatch) {
    return {
      status: parseInt(bareMatch[1], 10),
      statusText: bareMatch[2].trim(),
    };
  }
  return { status: 0, statusText: '' };
}
