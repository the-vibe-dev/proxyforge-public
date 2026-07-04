// JSON POST authentication module.
// Posts a JSON payload to a login endpoint and extracts a token from the response.
// No external dependencies — uses Node.js built-in http/https.

import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';
import type { AuthResult } from './index';

export interface JsonAuthConfig {
  /** Full URL of the login endpoint */
  loginUrl: string;
  /**
   * Template object for the request body. Use the special placeholders
   * "{{username}}" and "{{password}}" which are substituted at runtime.
   * Example: { "email": "{{username}}", "password": "{{password}}" }
   */
  bodyTemplate: Record<string, unknown>;
  /**
   * Dot-separated path to the token in the JSON response.
   * Example: "data.accessToken" or "token"
   */
  tokenClaimPath: string;
  /** HTTP header name to populate with the token on subsequent requests */
  tokenHeaderName?: string;
}

export interface JsonAuthCredentials {
  username: string;
  password: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function substituteTemplate(
  template: Record<string, unknown>,
  creds: JsonAuthCredentials,
): Record<string, unknown> {
  const replacer = (val: unknown): unknown => {
    if (typeof val === 'string') {
      return val
        .replace(/\{\{username\}\}/g, creds.username)
        .replace(/\{\{password\}\}/g, creds.password);
    }
    if (val && typeof val === 'object' && !Array.isArray(val)) {
      return Object.fromEntries(
        Object.entries(val as Record<string, unknown>).map(([k, v]) => [k, replacer(v)]),
      );
    }
    return val;
  };
  return replacer(template) as Record<string, unknown>;
}

function resolvePath(obj: unknown, path: string): string | undefined {
  const parts = path.split('.');
  let current: unknown = obj;
  for (const part of parts) {
    if (current == null || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[part];
  }
  return typeof current === 'string' ? current : current != null ? String(current) : undefined;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Performs a JSON POST login and extracts the token at tokenClaimPath.
 * Returns an AuthResult; sessionData will contain { token: "<value>" } on success.
 */
export async function performJsonAuth(
  config: JsonAuthConfig,
  credentials: JsonAuthCredentials,
): Promise<AuthResult> {
  return new Promise((resolve) => {
    const body = JSON.stringify(substituteTemplate(config.bodyTemplate, credentials));
    const parsed = new URL(config.loginUrl);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
        Accept: 'application/json',
      },
    };

    const req = lib.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf-8');
        let parsed: unknown;
        try {
          parsed = JSON.parse(raw);
        } catch {
          resolve({ success: false, error: 'Response is not valid JSON' });
          return;
        }

        const token = resolvePath(parsed, config.tokenClaimPath);
        if (!token) {
          resolve({
            success: false,
            error: `Token not found at path "${config.tokenClaimPath}"`,
          });
          return;
        }

        const headerName = config.tokenHeaderName ?? 'Authorization';
        resolve({
          success: true,
          sessionData: { token, [headerName]: `Bearer ${token}` },
        });
      });
    });

    req.on('error', (err: Error) => {
      resolve({ success: false, error: err.message });
    });

    req.write(body);
    req.end();
  });
}
