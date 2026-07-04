// URL-encoded POST authentication module.
// Similar to formAuth but accepts pre-built body strings and raw field maps.
// Adapted from source-reference/vantix/secops/verify/ (snapshot 2026-05-26).
// No external dependencies — uses Node.js built-in http/https.

import https from 'node:https';
import http from 'node:http';
import { URL } from 'node:url';
import type { AuthResult } from './index';

export interface PostAuthConfig {
  loginUrl: string;
  successRegex?: string;
  failureRegex?: string;
}

export interface PostAuthCredentials {
  fields: Record<string, string>;
}

function doPost(loginUrl: string, body: string): Promise<{ status: number; headers: Record<string, string | string[] | undefined>; text: string }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(loginUrl);
    const isHttps = parsed.protocol === 'https:';
    const lib = isHttps ? https : http;
    const req = lib.request({
      hostname: parsed.hostname,
      port: parsed.port || (isHttps ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk.toString(); });
      res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers as Record<string, string | string[] | undefined>, text: data }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

export async function performPostAuth(
  config: PostAuthConfig,
  creds: PostAuthCredentials,
): Promise<AuthResult> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(creds.fields)) {
    params.set(k, v);
  }
  const body = params.toString();

  try {
    const resp = await doPost(config.loginUrl, body);
    const text = resp.text;

    if (config.failureRegex && new RegExp(config.failureRegex, 'i').test(text)) {
      return { success: false, error: 'Failure pattern matched in POST auth response.' };
    }
    if (config.successRegex && !new RegExp(config.successRegex, 'i').test(text)) {
      return { success: false, error: 'Success pattern not found in POST auth response.' };
    }

    const sessionData: Record<string, string> = {};
    const raw = resp.headers['set-cookie'];
    const list = Array.isArray(raw) ? raw : raw ? [raw] : [];
    for (const entry of list) {
      const [pair] = entry.split(';');
      const [name, value] = pair.split('=');
      if (name) sessionData[name.trim()] = value?.trim() ?? '';
    }

    return { success: true, sessionData };
  } catch (err) {
    return { success: false, error: String(err) };
  }
}
