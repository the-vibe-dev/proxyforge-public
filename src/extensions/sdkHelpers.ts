/**
 * SDK helper utilities for ProxyForge extension authors.
 * These are pure functions with no external dependencies.
 */

/** Encode a UTF-8 string to base64. */
export function base64Encode(s: string): string {
  return Buffer.from(s).toString('base64');
}

/** Decode a base64 string to UTF-8. */
export function base64Decode(s: string): string {
  return Buffer.from(s, 'base64').toString('utf8');
}

/**
 * Case-insensitive lookup of a header value.
 * Returns null if the header is not present.
 */
export function extractHeader(
  headers: Record<string, string>,
  name: string,
): string | null {
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) {
      return headers[key];
    }
  }
  return null;
}

/**
 * Parse the query string from a URL and return a key/value map.
 * Duplicate keys are overwritten by their last occurrence.
 */
export function parseQueryParams(url: string): Record<string, string> {
  const result: Record<string, string> = {};
  try {
    const parsed = new URL(url);
    parsed.searchParams.forEach((value, key) => {
      result[key] = value;
    });
  } catch {
    // Bare query string (no scheme/host) — try splitting manually.
    const qIndex = url.indexOf('?');
    if (qIndex !== -1) {
      const qs = url.slice(qIndex + 1);
      for (const pair of qs.split('&')) {
        const eqIndex = pair.indexOf('=');
        if (eqIndex === -1) {
          result[decodeURIComponent(pair)] = '';
        } else {
          const k = decodeURIComponent(pair.slice(0, eqIndex));
          const v = decodeURIComponent(pair.slice(eqIndex + 1));
          result[k] = v;
        }
      }
    }
  }
  return result;
}

/** Return true if the string is valid JSON. */
export function isJson(s: string): boolean {
  try {
    JSON.parse(s);
    return true;
  } catch {
    return false;
  }
}

/** Pretty-print a JSON string with 2-space indentation. */
export function prettyJson(s: string): string {
  return JSON.stringify(JSON.parse(s), null, 2);
}

/**
 * Match a value against a simple glob pattern.
 * Supports `*` (any sequence of characters) and `?` (any single character).
 */
export function matchesPattern(value: string, pattern: string): boolean {
  // Convert glob to a regex.
  const escaped = pattern
    .split('')
    .map((ch) => {
      if (ch === '*') return '.*';
      if (ch === '?') return '.';
      return ch.replace(/[.+^${}()|[\]\\]/g, '\\$&');
    })
    .join('');
  return new RegExp(`^${escaped}$`).test(value);
}

/** Truncate a string to at most maxLen characters. */
export function truncate(s: string, maxLen: number): string {
  if (s.length <= maxLen) return s;
  return s.slice(0, maxLen);
}

const SENSITIVE_HEADER_NAMES = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-api-key',
  'x-auth-token',
  'x-access-token',
  'x-secret',
  'proxy-authorization',
  'www-authenticate',
]);

/** Return true if the header name is considered sensitive. */
export function isSensitiveHeader(name: string): boolean {
  return SENSITIVE_HEADER_NAMES.has(name.toLowerCase());
}

/**
 * Build a standardised SDK finding object for use by extension scan checks.
 *
 * @param opts - Required fields for the finding.
 * @returns A plain object suitable for returning from a `scan_check` hook.
 */
export function buildSdkFinding(opts: {
  checkId: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: number;
  detail?: string;
  evidence?: string;
}): Record<string, unknown> {
  return { ...opts, source: 'extension', timestamp: new Date().toISOString() };
}

/**
 * Return a copy of the headers map with the values of sensitive headers
 * replaced by '[REDACTED]'.
 */
export function redactSensitiveHeaders(
  headers: Record<string, string>,
): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    result[key] = isSensitiveHeader(key) ? '[REDACTED]' : value;
  }
  return result;
}
