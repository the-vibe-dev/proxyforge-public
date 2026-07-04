// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'idor-numeric',
  family: 'idor',
  title: 'IDOR with numeric ID manipulation',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'path', 'json', 'body'],
  expectedSignals: ['different-resource-returned', 'status-delta', 'auth-bypass'],
  cwe: [639],
};

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const base = parseInt(ctx.baseValue, 10) || 1;
  const candidates = [
    base - 1,
    base + 1,
    base * 2,
    Math.max(1, Math.floor(base / 2)),
    1,
    2,
    100,
    0,
    -1,
    9999999,
  ].filter((v) => v !== base && v >= 0);

  const deduped = [...new Set(candidates)].slice(0, 8);

  return deduped.map((id) => ({
    id: `idor-num-${id}`,
    family: 'idor' as const,
    value: String(id),
    encoding: 'raw' as const,
    intent: `Substitute numeric ID ${base} → ${id} to probe for IDOR`,
    destructiveRisk: 'none' as const,
    expectedSignals: ['different-resource-returned', 'status-delta'],
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

  const sameStatus = resp.statusCode === baseline.statusCode;
  const bodyDiffers = resp.bodyText !== baseline.bodyText && resp.bodyText.length > 50;
  const isSuccess = resp.statusCode >= 200 && resp.statusCode < 300;
  const baselineWasSuccess = baseline.statusCode >= 200 && baseline.statusCode < 300;

  if (isSuccess && bodyDiffers && baselineWasSuccess && sameStatus) {
    responseClass = 'expected-proof';
    confidence = 0.75;
    nextAction = 'confirm';
    evidence.push(`IDOR candidate: ID ${variant.value} returned different 200 response (body length ${resp.bodyText.length} vs baseline ${baseline.bodyText.length})`);
    evidence.push('Manually verify that returned data belongs to another user/resource');
  } else if (isSuccess && !baselineWasSuccess) {
    responseClass = 'status-delta';
    confidence = 0.7;
    nextAction = 'confirm';
    evidence.push(`IDOR possible: baseline ${baseline.statusCode} → probe ${resp.statusCode} for ID ${variant.value}`);
  } else if (resp.statusCode === 403 || resp.statusCode === 401) {
    responseClass = 'method-or-parser-rejected';
    confidence = 0.8;
    nextAction = 'stop-negative';
    evidence.push(`Access correctly denied (${resp.statusCode}) for ID ${variant.value}`);
  } else if (resp.statusCode === 404) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.3;
    nextAction = 'continue';
    evidence.push(`ID ${variant.value} not found (404)`);
  } else {
    nextAction = 'continue';
    evidence.push(`No clear IDOR signal for ID ${variant.value}`);
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
