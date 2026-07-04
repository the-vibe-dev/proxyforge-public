import type { PayloadVariant } from '../types';

export const META = {
  id: 'bypass-auth-verb',
  family: 'mass-assignment' as const,
  name: 'Auth Bypass via Alternate HTTP Verb',
  description: 'Tests authentication bypass on POST auth endpoints by substituting read-only or alternate verbs.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['header'],
};

const PROBES = [
  { value: 'HEAD', intent: 'HEAD verb on auth endpoint — may execute action without body validation', signals: ['auth-bypassed'] },
  { value: 'OPTIONS', intent: 'OPTIONS on auth endpoint — may return 200 without triggering auth middleware', signals: ['auth-bypassed'] },
  { value: 'GET', intent: 'GET on POST-only auth endpoint — body params ignored, may skip CSRF check', signals: ['auth-bypassed'] },
  { value: 'TRACE', intent: 'TRACE on auth endpoint — echoes request; some middleware skips auth for TRACE', signals: ['auth-bypassed', 'trace-enabled'] },
  { value: 'PUT', intent: 'PUT on auth endpoint — may create session resource without credentials', signals: ['auth-bypassed'] },
  { value: 'PATCH', intent: 'PATCH on auth endpoint — partial update semantics may bypass full auth flow', signals: ['auth-bypassed'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `bypass-auth-verb-${i + 1}`,
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
