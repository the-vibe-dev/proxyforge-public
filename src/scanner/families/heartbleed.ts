import type { PayloadVariant } from '../types';

export const META = {
  id: 'heartbleed',
  family: 'ssrf' as const,
  name: 'Heartbleed (CVE-2014-0160)',
  description: 'CVE-2014-0160 detection markers — transport-level TLS heartbeat extension requires out-of-band verification; these probes act as version and banner markers.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['header'],
};

const PROBES = [
  { value: 'OpenSSL/1.0.1', intent: 'OpenSSL 1.0.1 version banner — affected range for Heartbleed', signals: ['heartbleed-response'] },
  { value: 'OpenSSL/1.0.1a', intent: 'OpenSSL 1.0.1a version banner — affected range for Heartbleed', signals: ['heartbleed-response'] },
  { value: 'OpenSSL/1.0.1f', intent: 'OpenSSL 1.0.1f version banner — highest-risk Heartbleed version', signals: ['heartbleed-response'] },
  { value: 'OpenSSL/1.0.2-beta', intent: 'OpenSSL 1.0.2-beta version banner — also affected by Heartbleed', signals: ['heartbleed-response'] },
  { value: 'TLS-HEARTBEAT-REQUEST', intent: 'Heartbeat extension request marker — signals TLS heartbeat extension negotiated', signals: ['heartbleed-response'] },
  { value: 'HEARTBLEED-PROBE-64KB', intent: 'Oversized heartbeat payload marker — 64KB overread attempt indicator', signals: ['heartbleed-response'] },
  { value: 'CVE-2014-0160-CHECK', intent: 'CVE reference marker for passive banner detection correlation', signals: ['heartbleed-response'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `heartbleed-${i + 1}`,
    family: 'ssrf' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
