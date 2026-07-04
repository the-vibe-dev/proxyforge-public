// SSRF active check family (non-OAST).
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant, MutationContext } from '../types';

export const META = {
  id: 'ssrf',
  family: 'ssrf' as const,
  name: 'Server-Side Request Forgery',
  description: 'Detects SSRF via cloud metadata and loopback URL probes.',
  defaultRisk: 'low' as const,
  insertionPointKinds: ['query', 'body', 'json', 'header', 'path'],
};

const SSRF_PROBES = [
  { value: 'http://169.254.169.254/latest/meta-data/', intent: 'AWS IMDSv1 metadata endpoint', signals: ['ssrf-response'] },
  { value: 'http://metadata.google.internal/computeMetadata/v1/', intent: 'GCP metadata endpoint', signals: ['ssrf-response'] },
  { value: 'http://169.254.169.254/metadata/instance', intent: 'Azure IMDS endpoint', signals: ['ssrf-response'] },
  { value: 'http://127.0.0.1/', intent: 'Loopback address SSRF', signals: ['ssrf-response'] },
  { value: 'http://localhost/', intent: 'localhost SSRF', signals: ['ssrf-response'] },
  { value: 'http://0.0.0.0/', intent: 'INADDR_ANY SSRF', signals: ['ssrf-response'] },
  { value: 'http://[::1]/', intent: 'IPv6 loopback SSRF', signals: ['ssrf-response'] },
  { value: 'http://192.168.1.1/', intent: 'Private network probe (RFC1918)', signals: ['ssrf-response'] },
  { value: 'http://10.0.0.1/', intent: 'Internal 10.x network probe', signals: ['ssrf-response'] },
  { value: 'http://2130706433/', intent: 'Decimal notation for 127.0.0.1', signals: ['ssrf-response'] },
];

export function variants(ctx?: MutationContext): PayloadVariant[] {
  return SSRF_PROBES.map((probe, i) => ({
    id: `ssrf-${i + 1}`,
    family: 'ssrf' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
