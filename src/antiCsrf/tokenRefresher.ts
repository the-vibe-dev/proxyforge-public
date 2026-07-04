// Pre-replay anti-CSRF token refresh hook.
// Fetches fresh tokens from their refreshUrl (or extracts them from replay
// responses) before the replay engine sends the actual request.
// No external dependencies — uses Node.js built-in http/https.

import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';
import type { AntiCsrfToken } from './index';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Minimal replay request descriptor — callers provide what they have.
 */
export interface ReplayDescriptor {
  rawRequest: string;
  targetUrl: string;
  /** Optional session cookies for the refresh GET request */
  cookies?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function extractTokenFromBody(body: string, tokenName: string): string | null {
  // Hidden input: <input type="hidden" name="csrf_token" value="XYZ">
  const inputRe = new RegExp(
    `<input[^>]+name=["']${tokenName}["'][^>]+value=["']([^"']+)["']`,
    'i',
  );
  const inputMatch = inputRe.exec(body);
  if (inputMatch) return inputMatch[1];

  // Meta tag: <meta name="csrf-token" content="XYZ">
  const metaRe = new RegExp(
    `<meta[^>]+name=["']${tokenName}["'][^>]+content=["']([^"']+)["']`,
    'i',
  );
  const metaMatch = metaRe.exec(body);
  if (metaMatch) return metaMatch[1];

  // JSON key: { "csrf_token": "XYZ" }
  const jsonRe = new RegExp(`["']${tokenName}["']\\s*:\\s*["']([^"']+)["']`);
  const jsonMatch = jsonRe.exec(body);
  if (jsonMatch) return jsonMatch[1];

  return null;
}

function extractCookieValue(setCookieHeaders: string[], cookieName: string): string | null {
  for (const header of setCookieHeaders) {
    const part = header.split(';')[0];
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    if (name.toLowerCase() === cookieName.toLowerCase()) return value;
  }
  return null;
}

async function fetchUrl(
  url: string,
  cookies?: string,
): Promise<{ body: string; setCookieHeaders: string[] }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: cookies ? { Cookie: cookies } : {},
    };

    const req = lib.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (c: Buffer) => chunks.push(c));
      res.on('end', () => {
        const body = Buffer.concat(chunks).toString('utf-8');
        const raw = res.headers['set-cookie'];
        const setCookieHeaders = Array.isArray(raw) ? raw : raw ? [raw] : [];
        resolve({ body, setCookieHeaders });
      });
    });

    req.on('error', reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Refreshes all anti-CSRF tokens for a context before a replay.
 *
 * For each token with a refreshUrl, performs a GET to that URL and extracts
 * the token from the response body or Set-Cookie header.  Tokens without a
 * refreshUrl are skipped (the replay engine must handle them inline).
 *
 * @param tokens    Tokens for the context (from getTokensForContext)
 * @param contextId The context id (informational / for logging)
 * @param replay    Replay descriptor with cookies for the refresh request
 * @returns         A map of { tokenName → freshValue } for all tokens that
 *                  could be refreshed.  Missing entries means the refresh
 *                  could not obtain a value.
 */
export async function refreshAntiCsrfTokens(
  tokens: AntiCsrfToken[],
  contextId: string,
  replay: ReplayDescriptor,
): Promise<Record<string, string>> {
  const result: Record<string, string> = {};

  await Promise.all(
    tokens.map(async (token) => {
      const url = token.refreshUrl ?? replay.targetUrl;
      try {
        const { body, setCookieHeaders } = await fetchUrl(url, replay.cookies);

        // Try cookie extraction first (cookie-to-header pattern)
        if (token.cookieName) {
          const cookieValue = extractCookieValue(setCookieHeaders, token.cookieName);
          if (cookieValue) {
            result[token.name] = cookieValue;
            return;
          }
        }

        // Fall back to body extraction
        const bodyValue = extractTokenFromBody(body, token.name);
        if (bodyValue) {
          result[token.name] = bodyValue;
        }
      } catch {
        // Network failure — token not refreshed; replay engine will proceed
        // without it and may receive a CSRF error (expected behaviour).
      }
    }),
  );

  return result;
}
