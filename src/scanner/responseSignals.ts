// Response signal patterns used by the oracle classifier.

export const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /mysql.*error/i,
  /ora-\d{5}/i,
  /pg.*error/i,
  /sqlite.*error/i,
  /syntax error.*sql/i,
  /unclosed quotation mark/i,
  /division by zero/i,
  /you have an error in your sql/i,
  /quoted string not properly terminated/i,
  /odbc.*driver.*error/i,
  /microsoft.*sql.*server/i,
  /warning.*mysql/i,
  /supplied argument is not a valid mysql/i,
];

export const XSS_REFLECTION_PATTERNS = [
  /<script[^>]*>alert\(/i,
  /onerror\s*=\s*alert\(/i,
  /onload\s*=\s*alert\(/i,
  /<svg[^>]*onload/i,
  /javascript:alert\(/i,
];

export const SSTI_MATH_PATTERNS = [
  /\b49\b/,     // 7*7 = 49
  /\b7777777\b/, // '7'*7 in Jinja2
];

export const FILE_CONTENT_PATTERNS = [
  /root:x:0:0/,
  /bin\/bash/,
  /\[boot loader\]/i,
  /\[extensions\]/i,
  /\[386enh\]/i,
];

export const COMMAND_OUTPUT_PATTERNS = [
  /uid=\d+\([^)]+\)/,
  /gid=\d+/,
  /proxyforge_cmd_probe/,
  /proxyforge_command_probe/,
];

export const XXE_REFLECTION_PATTERNS = [
  /root:x:0:0/,
  /ENTITY.*SYSTEM/i,
];

export const NOSQL_AUTH_BYPASS_PATTERNS = [
  /\[\s*\{/,          // array of objects
  /"_id"\s*:/,
  /"__v"\s*:/,
];

export const REDIRECT_LOCATION_PATTERNS = [
  /evil\.example\.com/i,
  /javascript:/i,
  /data:text\/html/i,
];

export function matchesAnyPattern(text: string, patterns: RegExp[]): string | null {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) return match[0];
  }
  return null;
}

export function simpleBodyHash(text: string): string {
  let h = 0x811c9dc5;
  for (let i = 0; i < text.length; i++) {
    h ^= text.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}
