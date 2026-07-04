import type { PayloadVariant } from '../types';

export const META = {
  id: 'http-insecure-methods',
  family: 'mass-assignment' as const,
  name: 'HTTP Insecure Methods Accepted',
  description: 'Detects servers accepting dangerous HTTP methods: PUT, DELETE, TRACE, CONNECT, PATCH, OPTIONS.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['header'],
};

const PROBES = [
  { value: 'PUT', intent: 'PUT method — allows arbitrary file upload or resource replacement', signals: ['insecure-method'] },
  { value: 'DELETE', intent: 'DELETE method — allows resource deletion without proper authorization check', signals: ['insecure-method'] },
  { value: 'TRACE', intent: 'TRACE method — echoes request headers enabling credential theft via XST', signals: ['insecure-method', 'trace-enabled'] },
  { value: 'CONNECT', intent: 'CONNECT method — enables server as proxy for pivoting attacks', signals: ['insecure-method'] },
  { value: 'PATCH', intent: 'PATCH method — may allow partial resource modification bypassing validation', signals: ['insecure-method'] },
  { value: 'OPTIONS', intent: 'OPTIONS method — reveals all accepted methods via Allow header', signals: ['insecure-method'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `insecure-method-${i + 1}`,
    family: 'mass-assignment' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
