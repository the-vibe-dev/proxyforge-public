// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'session-fixation',
  family: 'session-fixation',
  title: 'Session fixation',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['cookie', 'query', 'body'],
  expectedSignals: ['session-accepted', 'set-cookie-echo', 'status-delta'],
  cwe: [384],
};

const FIXED_SESSION_ID = 'pf_fixed_sid_deadbeef0001';

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'sfx-cookie-plain',
      family: 'session-fixation',
      value: `PHPSESSID=${FIXED_SESSION_ID}`,
      encoding: 'raw',
      intent: 'Inject pre-set PHPSESSID cookie to fix PHP session',
      destructiveRisk: 'none',
      expectedSignals: ['session-accepted', 'set-cookie-echo'],
    },
    {
      id: 'sfx-cookie-jsessionid',
      family: 'session-fixation',
      value: `JSESSIONID=${FIXED_SESSION_ID}`,
      encoding: 'raw',
      intent: 'Inject pre-set JSESSIONID to fix Java session',
      destructiveRisk: 'none',
      expectedSignals: ['session-accepted', 'set-cookie-echo'],
    },
    {
      id: 'sfx-cookie-aspnet',
      family: 'session-fixation',
      value: `ASP.NET_SessionId=${FIXED_SESSION_ID}`,
      encoding: 'raw',
      intent: 'Inject pre-set ASP.NET SessionId cookie',
      destructiveRisk: 'none',
      expectedSignals: ['session-accepted', 'set-cookie-echo'],
    },
    {
      id: 'sfx-query-sid',
      family: 'session-fixation',
      value: `sid=${FIXED_SESSION_ID}`,
      encoding: 'url',
      intent: 'Session ID via query parameter (URL-based sessions)',
      destructiveRisk: 'none',
      expectedSignals: ['session-accepted', 'status-delta'],
    },
    {
      id: 'sfx-body-token',
      family: 'session-fixation',
      value: `session_token=${FIXED_SESSION_ID}`,
      encoding: 'raw',
      intent: 'Session token fixed via POST body field',
      destructiveRisk: 'none',
      expectedSignals: ['session-accepted'],
    },
    {
      id: 'sfx-cookie-rails',
      family: 'session-fixation',
      value: `_session_id=${FIXED_SESSION_ID}`,
      encoding: 'raw',
      intent: 'Rails _session_id fixation attempt',
      destructiveRisk: 'none',
      expectedSignals: ['session-accepted', 'set-cookie-echo'],
    },
    {
      id: 'sfx-cookie-generic',
      family: 'session-fixation',
      value: `session=${FIXED_SESSION_ID}`,
      encoding: 'raw',
      intent: 'Generic "session" cookie fixation',
      destructiveRisk: 'none',
      expectedSignals: ['session-accepted', 'set-cookie-echo'],
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

  const setCookieHeader = resp.headers['set-cookie'] ?? '';
  const sessionCookieEchoed = setCookieHeader.includes(FIXED_SESSION_ID);
  const noNewSession = !setCookieHeader || setCookieHeader === (baseline.headers['set-cookie'] ?? '');

  if (sessionCookieEchoed) {
    // Server echoed back our fixed session ID — strong signal
    responseClass = 'expected-proof';
    confidence = 0.9;
    nextAction = 'promote-finding';
    evidence.push(`Server echoed fixed session ID ${FIXED_SESSION_ID} in Set-Cookie — session fixation confirmed`);
  } else if (noNewSession && resp.statusCode >= 200 && resp.statusCode < 300) {
    // Server did not issue a new session — may be accepting our fixed one silently
    responseClass = 'observed-value';
    confidence = 0.55;
    nextAction = 'confirm';
    evidence.push('Server returned 2xx without issuing a new session cookie — possible silent acceptance of fixed ID');
  } else if (baseline.statusCode !== resp.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.3;
    nextAction = 'continue';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('Server issued a fresh session ID; fixation not observed');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
