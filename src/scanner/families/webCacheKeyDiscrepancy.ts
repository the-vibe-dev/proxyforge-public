// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'web-cache-key-discrepancy',
  family: 'cache-poisoning',
  title: 'Web cache key discrepancy',
  severity: 'high',
  destructiveRisk: 'low',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'header', 'path'],
  expectedSignals: ['cache-hit-poisoned', 'parameter-not-keyed', 'fat-get-accepted'],
  cwe: [444],
};

const PF_CANARY = 'pf-key-discrepancy-001';

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'ckd-query-excluded',
      family: 'cache-poisoning',
      value: `utm_canary=${PF_CANARY}`,
      encoding: 'url',
      intent: 'UTM tracking param — often excluded from cache key but reflected in response',
      destructiveRisk: 'low',
      expectedSignals: ['parameter-not-keyed', 'cache-hit-poisoned'],
    },
    {
      id: 'ckd-fat-get',
      family: 'cache-poisoning',
      value: `GET /?pf=1 HTTP/1.1\r\nContent-Length: 20\r\n\r\npf_body=${PF_CANARY}`,
      encoding: 'raw',
      intent: 'Fat GET — body on GET request; some back-ends read body, caches key only URL',
      destructiveRisk: 'low',
      expectedSignals: ['fat-get-accepted', 'cache-hit-poisoned'],
    },
    {
      id: 'ckd-fragment-param',
      family: 'cache-poisoning',
      value: `#pf_fragment=${PF_CANARY}`,
      encoding: 'url',
      intent: 'Fragment-like suffix in query — some CDNs strip fragment, back-end may process it',
      destructiveRisk: 'none',
      expectedSignals: ['parameter-not-keyed'],
    },
    {
      id: 'ckd-case-variation',
      family: 'cache-poisoning',
      value: `PF_CANARY=${PF_CANARY}`,
      encoding: 'url',
      intent: 'Uppercase parameter — cache may normalise case while back-end case-sensitive',
      destructiveRisk: 'none',
      expectedSignals: ['parameter-not-keyed'],
    },
    {
      id: 'ckd-double-slash',
      family: 'cache-poisoning',
      value: `//pf-discrepancy`,
      encoding: 'raw',
      intent: 'Double-slash path — normalised by CDN but not by back-end',
      destructiveRisk: 'none',
      expectedSignals: ['cache-hit-poisoned'],
    },
    {
      id: 'ckd-origin-vary',
      family: 'cache-poisoning',
      value: `https://${PF_CANARY}.example`,
      encoding: 'header-safe',
      intent: 'Origin header with canary domain — not keyed in Vary, affects CORS response caching',
      destructiveRisk: 'none',
      expectedSignals: ['parameter-not-keyed', 'cache-hit-poisoned'],
    },
    {
      id: 'ckd-array-param',
      family: 'cache-poisoning',
      value: `pf[canary]=${PF_CANARY}`,
      encoding: 'url',
      intent: 'PHP-style array parameter excluded from cache key',
      destructiveRisk: 'none',
      expectedSignals: ['parameter-not-keyed'],
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
    confidence = 0.92;
    nextAction = 'promote-finding';
    evidence.push(`Cache key discrepancy: canary reflected in cache-HIT (variant: ${variant.id})`);
  } else if (canaryInBody) {
    responseClass = 'observed-value';
    confidence = 0.65;
    nextAction = 'confirm';
    evidence.push(`Canary reflected without cache HIT — verify with second uncached request`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('No cache key discrepancy detected');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
