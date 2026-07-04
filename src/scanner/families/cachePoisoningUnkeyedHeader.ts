// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'cache-poisoning-unkeyed-header',
  family: 'cache-poisoning',
  title: 'Cache poisoning via unkeyed header',
  severity: 'high',
  destructiveRisk: 'low',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header'],
  expectedSignals: ['header-reflected', 'cache-hit-poisoned', 'xss-via-cache'],
  cwe: [444, 79],
};

const PF_CANARY = 'pf-cache-poison-001';

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'cp-uh-x-forwarded-host',
      family: 'cache-poisoning',
      value: `${PF_CANARY}.attacker.example`,
      encoding: 'header-safe',
      intent: 'X-Forwarded-Host with canary value — if reflected in cached response, cache is poisoned',
      destructiveRisk: 'low',
      expectedSignals: ['header-reflected', 'cache-hit-poisoned'],
    },
    {
      id: 'cp-uh-x-forwarded-scheme',
      family: 'cache-poisoning',
      value: `http://${PF_CANARY}.example`,
      encoding: 'header-safe',
      intent: 'X-Forwarded-Scheme override to cause http: canonical URLs in cached page',
      destructiveRisk: 'low',
      expectedSignals: ['header-reflected'],
    },
    {
      id: 'cp-uh-x-original-url',
      family: 'cache-poisoning',
      value: `/${PF_CANARY}`,
      encoding: 'header-safe',
      intent: 'X-Original-URL / X-Rewrite-URL unkeyed header reflection',
      destructiveRisk: 'low',
      expectedSignals: ['header-reflected'],
    },
    {
      id: 'cp-uh-x-host',
      family: 'cache-poisoning',
      value: `${PF_CANARY}.evil.example`,
      encoding: 'header-safe',
      intent: 'X-Host header unkeyed reflection causing poisoned host in links',
      destructiveRisk: 'low',
      expectedSignals: ['header-reflected', 'cache-hit-poisoned'],
    },
    {
      id: 'cp-uh-x-forwarded-for-xss',
      family: 'cache-poisoning',
      value: `"><script>/*${PF_CANARY}*/</script>`,
      encoding: 'raw',
      intent: 'X-Forwarded-For XSS payload — reflected without sanitisation into cached HTML',
      destructiveRisk: 'low',
      expectedSignals: ['xss-via-cache', 'header-reflected'],
    },
    {
      id: 'cp-uh-pragma-no-cache',
      family: 'cache-poisoning',
      value: 'no-cache',
      encoding: 'header-safe',
      intent: 'Pragma: no-cache to force cache miss and observe unkeyed header handling',
      destructiveRisk: 'none',
      expectedSignals: ['header-reflected'],
    },
    {
      id: 'cp-uh-accept-language',
      family: 'cache-poisoning',
      value: `${PF_CANARY}`,
      encoding: 'header-safe',
      intent: 'Accept-Language as unkeyed header — reflect locale prefix in URL/HTML',
      destructiveRisk: 'none',
      expectedSignals: ['header-reflected'],
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

  const canaryInBody = resp.bodyText.includes(PF_CANARY);
  const cacheHeader = resp.headers['x-cache'] ?? resp.headers['cf-cache-status'] ?? '';
  const wasCached = /^HIT/i.test(cacheHeader);

  if (canaryInBody && wasCached) {
    responseClass = 'expected-proof';
    confidence = 0.95;
    nextAction = 'promote-finding';
    evidence.push(`Cache poisoning confirmed: canary "${PF_CANARY}" reflected in a cache-HIT response`);
    evidence.push(`X-Cache/CF-Cache-Status: "${cacheHeader}"`);
  } else if (canaryInBody) {
    responseClass = 'observed-value';
    confidence = 0.7;
    nextAction = 'confirm';
    evidence.push(`Canary "${PF_CANARY}" reflected in response body for variant ${variant.id}`);
    evidence.push('Cache status not confirmed — re-probe without header to check poisoned cache');
  } else {
    nextAction = 'stop-negative';
    evidence.push('Canary not reflected; header appears to be keyed or not reflected');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
