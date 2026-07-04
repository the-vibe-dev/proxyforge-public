// Form-post authentication module.
// Performs a login via application/x-www-form-urlencoded POST.
// No external dependencies — uses Node.js built-in http/https.

import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';
import type { AuthResult } from './index';

export interface FormAuthConfig {
  /** Full URL of the login endpoint, e.g. "https://app.example.com/login" */
  loginUrl: string;
  /** HTML form field name for the username */
  usernameField: string;
  /** HTML form field name for the password */
  passwordField: string;
  /**
   * Regex that must match the response body to consider the login successful.
   * Example: "Welcome, " or "dashboard"
   */
  successRegex?: string;
  /**
   * Regex that, if matched, indicates the login failed.
   * Example: "Invalid credentials"
   */
  failureRegex?: string;
}

export interface FormAuthCredentials {
  username: string;
  password: string;
  /** Additional fields to include in the POST body */
  extra?: Record<string, string>;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function buildFormBody(
  config: FormAuthConfig,
  creds: FormAuthCredentials,
): string {
  const params = new URLSearchParams();
  params.set(config.usernameField, creds.username);
  params.set(config.passwordField, creds.password);
  if (creds.extra) {
    for (const [k, v] of Object.entries(creds.extra)) {
      params.set(k, v);
    }
  }
  return params.toString();
}

function parseCookies(headers: Record<string, string | string[] | undefined>): Record<string, string> {
  const cookies: Record<string, string> = {};
  const raw = headers['set-cookie'];
  if (!raw) return cookies;
  const list = Array.isArray(raw) ? raw : [raw];
  for (const entry of list) {
    const part = entry.split(';')[0];
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    const name = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    cookies[name] = value;
  }
  return cookies;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Performs a form-based POST login.
 * Returns an AuthResult with sessionData containing any Set-Cookie values.
 */
export async function performFormAuth(
  config: FormAuthConfig,
  credentials: FormAuthCredentials,
): Promise<AuthResult> {
  return new Promise((resolve) => {
    const body = buildFormBody(config, credentials);
    const parsed = new URL(config.loginUrl);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;

    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    };

    const req = lib.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const responseBody = Buffer.concat(chunks).toString('utf-8');
        const headers = res.headers as Record<string, string | string[] | undefined>;
        const sessionData = parseCookies(headers);

        // Check failure regex first
        if (config.failureRegex) {
          try {
            if (new RegExp(config.failureRegex).test(responseBody)) {
              resolve({ success: false, error: 'Failure regex matched response body' });
              return;
            }
          } catch {
            // ignore bad regex
          }
        }

        // Check success regex
        if (config.successRegex) {
          try {
            if (!new RegExp(config.successRegex).test(responseBody)) {
              resolve({ success: false, error: 'Success regex did not match response body' });
              return;
            }
          } catch {
            // ignore bad regex
          }
        }

        const statusOk = (res.statusCode ?? 0) < 400;
        resolve({ success: statusOk, sessionData });
      });
    });

    req.on('error', (err: Error) => {
      resolve({ success: false, error: err.message });
    });

    req.write(body);
    req.end();
  });
}
