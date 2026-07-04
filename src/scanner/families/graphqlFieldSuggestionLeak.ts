// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'graphql-field-suggestion-leak',
  family: 'graphql-attack',
  title: 'GraphQL field suggestion leak (did-you-mean schema enumeration)',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['body', 'graphql'],
  expectedSignals: ['suggestion-leak', 'schema-enumerated'],
  cwe: [200],
};

// Typo variants designed to trigger "did you mean X?" suggestions
const TYPO_QUERIES = [
  { id: 'gql-sug-users', value: '{"query":"{usrs{id}}"}', intent: 'Typo "usrs" → may suggest "users"' },
  { id: 'gql-sug-admin', value: '{"query":"{admn{id}}"}', intent: 'Typo "admn" → may suggest "admin"' },
  { id: 'gql-sug-password', value: '{"query":"{user{passwrd}}"}', intent: 'Typo "passwrd" → may suggest "password"' },
  { id: 'gql-sug-email', value: '{"query":"{user{emal}}"}', intent: 'Typo "emal" → may suggest "email"' },
  { id: 'gql-sug-token', value: '{"query":"{user{tokn}}"}', intent: 'Typo "tokn" → may suggest "token" or "apiKey"' },
  { id: 'gql-sug-secret', value: '{"query":"{user{scrt}}"}', intent: 'Typo "scrt" → may suggest "secret"' },
  { id: 'gql-sug-internal', value: '{"query":"{_internl{id}}"}', intent: 'Typo "_internl" → may reveal internal types' },
];

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return TYPO_QUERIES.map((q) => ({
    id: q.id,
    family: 'graphql-attack' as const,
    value: q.value,
    encoding: 'json-string' as const,
    intent: q.intent,
    destructiveRisk: 'none' as const,
    expectedSignals: ['suggestion-leak', 'schema-enumerated'],
  }));
}

const SUGGESTION_PATTERN = /did you mean[:\s"]+([^"?,]+)/gi;

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  _baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  let responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.1;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  const suggestions: string[] = [];
  let match: RegExpExecArray | null;
  SUGGESTION_PATTERN.lastIndex = 0;
  while ((match = SUGGESTION_PATTERN.exec(resp.bodyText)) !== null) {
    suggestions.push(match[1].trim());
  }

  if (suggestions.length > 0) {
    responseClass = 'expected-proof';
    confidence = 0.85;
    nextAction = 'promote-finding';
    evidence.push(`GraphQL field suggestion leak: server suggested: ${suggestions.join(', ')}`);
    evidence.push('Schema field names enumerable via did-you-mean error messages');
  } else if (resp.bodyText.includes('"errors"') && resp.statusCode === 200) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.3;
    nextAction = 'continue';
    evidence.push('Error returned but no suggestion message in response');
  } else {
    nextAction = 'stop-negative';
    evidence.push(`No field suggestion leak for ${variant.id}`);
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
