import type { PayloadVariant } from '../types';

export const META = {
  id: 'api-versioning-mismatch',
  family: 'mass-assignment' as const,
  name: 'API Versioning Bypass',
  description: 'Probes alternative API version prefixes and internal path segments to bypass version-based access controls.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['path'],
};

const PROBES = [
  { value: '/api/v1/users', intent: 'Probe v1 API prefix — older versions may lack authorization controls', signals: ['version-bypass'] },
  { value: '/api/v2/users', intent: 'Probe v2 API prefix — test parallel version with different ACL', signals: ['version-bypass'] },
  { value: '/v1/users', intent: 'Probe /v1/ without /api/ prefix — alternate routing', signals: ['version-bypass'] },
  { value: '/admin/users', intent: 'Probe /admin/ prefix — administrative endpoint exposure', signals: ['admin-endpoint-exposed'] },
  { value: '/internal/users', intent: 'Probe /internal/ prefix — internal-only endpoint bypass', signals: ['internal-endpoint-exposed'] },
  { value: '/_admin/users', intent: 'Probe /_admin/ prefix — underscore-prefixed admin routing', signals: ['admin-endpoint-exposed'] },
  { value: '/api/v0/users', intent: 'Probe v0 legacy prefix — pre-release APIs may have no auth', signals: ['version-bypass'] },
  { value: '/api/latest/users', intent: 'Probe /api/latest/ alias — may bypass version-specific middleware', signals: ['version-bypass'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `api-version-${i + 1}`,
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
