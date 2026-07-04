// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'host-header-injection',
  family: 'host-header',
  title: 'Host header injection',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['header'],
  expectedSignals: ['host-reflected', 'password-reset-poison', 'oast-callback-confirmed', 'redirect-with-injected-host'],
  cwe: [20, 79],
};

const ATTACKER_HOST = 'attacker.pf.example';

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const oastHost = ctx.oastBaseUrl ? new URL(ctx.oastBaseUrl).hostname : ATTACKER_HOST;
  return [
    {
      id: 'hhi-basic-replacement',
      family: 'host-header',
      value: ATTACKER_HOST,
      encoding: 'header-safe',
      intent: 'Replace Host with attacker domain — check reflection in response/links',
      destructiveRisk: 'none',
      expectedSignals: ['host-reflected'],
    },
    {
      id: 'hhi-x-forwarded-host',
      family: 'host-header',
      value: ATTACKER_HOST,
      encoding: 'header-safe',
      intent: 'X-Forwarded-Host injection — CDN/reverse-proxy host override',
      destructiveRisk: 'none',
      expectedSignals: ['host-reflected', 'redirect-with-injected-host'],
    },
    {
      id: 'hhi-x-host',
      family: 'host-header',
      value: ATTACKER_HOST,
      encoding: 'header-safe',
      intent: 'X-Host header — less common proxy override',
      destructiveRisk: 'none',
      expectedSignals: ['host-reflected'],
    },
    {
      id: 'hhi-override-duplicate',
      family: 'host-header',
      value: `legit.example, ${ATTACKER_HOST}`,
      encoding: 'header-safe',
      intent: 'Duplicate Host header to confuse parser into using last value',
      destructiveRisk: 'none',
      expectedSignals: ['host-reflected'],
    },
    {
      id: 'hhi-oast-host',
      family: 'host-header',
      value: oastHost,
      encoding: 'header-safe',
      intent: 'OAST-backed Host injection — DNS callback confirms out-of-band reflection',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed', 'host-reflected'],
    },
    {
      id: 'hhi-port-injection',
      family: 'host-header',
      value: `legit.example:8080@${ATTACKER_HOST}`,
      encoding: 'header-safe',
      intent: 'Host with @ to confuse URL parsers (auth-before-host)',
      destructiveRisk: 'none',
      expectedSignals: ['host-reflected'],
    },
    {
      id: 'hhi-password-reset',
      family: 'host-header',
      value: ATTACKER_HOST,
      encoding: 'header-safe',
      intent: 'Host injection on password-reset endpoint — poisoned reset-link delivery',
      destructiveRisk: 'none',
      expectedSignals: ['password-reset-poison', 'host-reflected'],
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

  const bodyLower = resp.bodyText.toLowerCase();
  const hostReflected = resp.bodyText.includes(ATTACKER_HOST) || bodyLower.includes('attacker.pf.example');
  const locationHeader = resp.headers['location'] ?? '';
  const redirectToAttacker = locationHeader.includes(ATTACKER_HOST);

  if (hostReflected) {
    responseClass = 'expected-proof';
    confidence = 0.88;
    nextAction = 'promote-finding';
    evidence.push(`Injected host "${ATTACKER_HOST}" reflected in response body (variant: ${variant.id})`);
  } else if (redirectToAttacker) {
    responseClass = 'expected-proof';
    confidence = 0.92;
    nextAction = 'promote-finding';
    evidence.push(`Location header redirects to attacker host: ${locationHeader}`);
  } else if (variant.requiresOast) {
    // OAST result evaluated separately by oastPayloadBroker
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.2;
    nextAction = 'continue';
    evidence.push('OAST probe dispatched — awaiting callback');
  } else {
    nextAction = 'stop-negative';
    evidence.push('Host value not reflected; server likely validates Host header');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
