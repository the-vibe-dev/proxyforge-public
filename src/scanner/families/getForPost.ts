import type { PayloadVariant } from '../types';

export const META = {
  id: 'get-for-post',
  family: 'mass-assignment' as const,
  name: 'GET Semantics on POST Endpoint',
  description: 'Tests whether POST-only endpoints accept GET and other read-method verbs, bypassing CSRF or body validation.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['header'],
};

const PROBES = [
  { value: 'GET', intent: 'GET verb on POST endpoint — may bypass CSRF token requirement', signals: ['method-accepted'] },
  { value: 'HEAD', intent: 'HEAD verb on POST endpoint — detects action execution without response body', signals: ['method-accepted'] },
  { value: 'OPTIONS', intent: 'OPTIONS verb to enumerate allowed methods and detect misconfiguration', signals: ['method-accepted'] },
  { value: 'TRACE', intent: 'TRACE verb — reveals request headers including auth tokens via response body', signals: ['method-accepted', 'trace-enabled'] },
  { value: 'PUT', intent: 'PUT verb on POST endpoint — may allow unauthenticated resource creation', signals: ['method-accepted'] },
  { value: 'PATCH', intent: 'PATCH verb on POST endpoint — may allow partial updates without proper auth', signals: ['method-accepted'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `get-for-post-${i + 1}`,
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
