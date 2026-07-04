// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'clickjacking',
  family: 'clickjacking',
  title: 'Clickjacking — missing X-Frame-Options / frame-ancestors',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header'],
  expectedSignals: ['missing-x-frame-options', 'missing-csp-frame-ancestors', 'frameable'],
  cwe: [1021],
};

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  // Clickjacking is primarily a passive detection, but active probes confirm
  // framing by sending requests with various framing-related headers and
  // examining whether the server signals framing restrictions.
  return [
    {
      id: 'cj-probe-no-xfo',
      family: 'clickjacking',
      value: '',
      encoding: 'raw',
      intent: 'Check response for absent X-Frame-Options header',
      destructiveRisk: 'none',
      expectedSignals: ['missing-x-frame-options'],
    },
    {
      id: 'cj-probe-allowall-xfo',
      family: 'clickjacking',
      value: 'ALLOWALL',
      encoding: 'header-safe',
      intent: 'Detect X-Frame-Options: ALLOWALL (non-standard, frameable)',
      destructiveRisk: 'none',
      expectedSignals: ['frameable'],
    },
    {
      id: 'cj-probe-no-csp',
      family: 'clickjacking',
      value: '',
      encoding: 'raw',
      intent: 'Check Content-Security-Policy for absent frame-ancestors directive',
      destructiveRisk: 'none',
      expectedSignals: ['missing-csp-frame-ancestors'],
    },
    {
      id: 'cj-probe-csp-star',
      family: 'clickjacking',
      value: "frame-ancestors *",
      encoding: 'header-safe',
      intent: "Detect CSP frame-ancestors * (any origin can frame)",
      destructiveRisk: 'none',
      expectedSignals: ['frameable'],
    },
    {
      id: 'cj-probe-vary-framing',
      family: 'clickjacking',
      value: 'Sec-Fetch-Dest: iframe',
      encoding: 'header-safe',
      intent: 'Send Sec-Fetch-Dest: iframe to check if server applies framing policy',
      destructiveRisk: 'none',
      expectedSignals: ['frameable', 'missing-x-frame-options'],
    },
    {
      id: 'cj-probe-with-origin',
      family: 'clickjacking',
      value: 'https://attacker.example',
      encoding: 'header-safe',
      intent: 'Send cross-origin Origin header with Sec-Fetch-Mode: navigate to simulate iframe load',
      destructiveRisk: 'none',
      expectedSignals: ['frameable'],
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

  const xfo = (resp.headers['x-frame-options'] ?? '').toUpperCase();
  const csp = resp.headers['content-security-policy'] ?? '';
  const hasFrameAncestors = csp.toLowerCase().includes('frame-ancestors');
  const xfoProtects = xfo === 'DENY' || xfo === 'SAMEORIGIN';

  if (!xfoProtects && !hasFrameAncestors) {
    responseClass = 'expected-proof';
    confidence = 0.88;
    nextAction = 'promote-finding';
    evidence.push('Neither X-Frame-Options nor CSP frame-ancestors present — page is frameable');
  } else if (xfo === 'ALLOWALL') {
    responseClass = 'expected-proof';
    confidence = 0.85;
    nextAction = 'promote-finding';
    evidence.push('X-Frame-Options: ALLOWALL detected — explicit framing permission');
  } else if (hasFrameAncestors && csp.includes('frame-ancestors *')) {
    responseClass = 'observed-value';
    confidence = 0.9;
    nextAction = 'promote-finding';
    evidence.push("CSP frame-ancestors * found — any origin may frame this page");
  } else if (xfoProtects || hasFrameAncestors) {
    responseClass = 'method-or-parser-rejected';
    confidence = 0.9;
    nextAction = 'stop-negative';
    evidence.push(`Framing protection present: X-Frame-Options="${xfo}" CSP frame-ancestors=${hasFrameAncestors}`);
  } else {
    evidence.push(`Variant ${variant.id} produced no clear signal`);
    nextAction = 'continue';
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
