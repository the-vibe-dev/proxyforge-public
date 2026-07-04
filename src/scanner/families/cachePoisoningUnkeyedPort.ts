// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'cache-poisoning-unkeyed-port',
  family: 'cache-poisoning',
  title: 'Cache poisoning via unkeyed port',
  severity: 'high',
  destructiveRisk: 'low',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header'],
  expectedSignals: ['port-reflected', 'cache-hit-poisoned'],
  cwe: [444],
};

const PF_CANARY_PORT = '12345';

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'cp-up-host-port',
      family: 'cache-poisoning',
      value: `legit.example:${PF_CANARY_PORT}`,
      encoding: 'header-safe',
      intent: 'Host header with non-standard port — check if port reflected and cache unkeyed on port',
      destructiveRisk: 'low',
      expectedSignals: ['port-reflected', 'cache-hit-poisoned'],
    },
    {
      id: 'cp-up-xfh-port',
      family: 'cache-poisoning',
      value: `legit.example:${PF_CANARY_PORT}`,
      encoding: 'header-safe',
      intent: 'X-Forwarded-Host with canary port — some CDNs unkey on X-Forwarded-Host',
      destructiveRisk: 'low',
      expectedSignals: ['port-reflected'],
    },
    {
      id: 'cp-up-host-port-zero',
      family: 'cache-poisoning',
      value: 'legit.example:0',
      encoding: 'header-safe',
      intent: 'Host:0 port — invalid port may bypass cache keying and cause redirect loop',
      destructiveRisk: 'none',
      expectedSignals: ['port-reflected'],
    },
    {
      id: 'cp-up-host-port-80',
      family: 'cache-poisoning',
      value: 'legit.example:80',
      encoding: 'header-safe',
      intent: 'Explicit :80 port — normalised away by some caches but not back-ends',
      destructiveRisk: 'none',
      expectedSignals: ['port-reflected', 'cache-hit-poisoned'],
    },
    {
      id: 'cp-up-host-port-443',
      family: 'cache-poisoning',
      value: 'legit.example:443',
      encoding: 'header-safe',
      intent: 'Explicit :443 on HTTPS — normalised away by some caches but not back-ends',
      destructiveRisk: 'none',
      expectedSignals: ['port-reflected'],
    },
    {
      id: 'cp-up-host-port-high',
      family: 'cache-poisoning',
      value: `legit.example:${PF_CANARY_PORT}`,
      encoding: 'url',
      intent: 'Host port in URL-encoded path variant for request-rewrite scenarios',
      destructiveRisk: 'none',
      expectedSignals: ['port-reflected'],
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

  const portReflected = resp.bodyText.includes(PF_CANARY_PORT);
  const cacheHeader = resp.headers['x-cache'] ?? resp.headers['cf-cache-status'] ?? '';
  const wasCached = /^HIT/i.test(cacheHeader);

  if (portReflected && wasCached) {
    responseClass = 'expected-proof';
    confidence = 0.93;
    nextAction = 'promote-finding';
    evidence.push(`Port ${PF_CANARY_PORT} reflected in cache-HIT response — unkeyed port confirmed`);
  } else if (portReflected) {
    responseClass = 'observed-value';
    confidence = 0.65;
    nextAction = 'confirm';
    evidence.push(`Port ${PF_CANARY_PORT} reflected in response for variant ${variant.id}`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('Port not reflected; cache appears to key on port or does not reflect it');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
