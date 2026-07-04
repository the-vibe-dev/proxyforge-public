// SSTI (Server-Side Template Injection) active check family.
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant } from '../types';

export const META = {
  id: 'ssti',
  family: 'ssti' as const,
  name: 'Server-Side Template Injection',
  description: 'Detects SSTI via math expression probes evaluated by template engines.',
  defaultRisk: 'low' as const,
  insertionPointKinds: ['query', 'body', 'json', 'path'],
};

const SSTI_PROBES = [
  { value: '{{7*7}}', intent: 'Jinja2/Twig arithmetic — expect 49', signals: ['ssti-math-result'] },
  { value: '${7*7}', intent: 'FreeMarker/EL arithmetic — expect 49', signals: ['ssti-math-result'] },
  { value: '<%= 7*7 %>', intent: 'ERB/JSP arithmetic — expect 49', signals: ['ssti-math-result'] },
  { value: '#{7*7}', intent: 'Ruby ERB interpolation — expect 49', signals: ['ssti-math-result'] },
  { value: '{{7*\'7\'}}', intent: 'Twig-specific string multiplication — expect 7777777', signals: ['ssti-math-result'] },
  { value: '${"freemarker".length()}', intent: 'FreeMarker method call — expect 10', signals: ['ssti-math-result'] },
  { value: '{{ self.__init__.__globals__.__builtins__ }}', intent: 'Jinja2 globals access — expect dict or error', signals: ['ssti-math-result', 'error-disclosure'] },
  { value: '{{config}}', intent: 'Flask/Jinja2 config object leak', signals: ['ssti-math-result'] },
  { value: '*{7*7}', intent: 'Thymeleaf SSTI arithmetic', signals: ['ssti-math-result'] },
  { value: '#set($x=7*7)$x', intent: 'Velocity template arithmetic — expect 49', signals: ['ssti-math-result'] },
];

export function variants(): PayloadVariant[] {
  return SSTI_PROBES.map((probe, i) => ({
    id: `ssti-${i + 1}`,
    family: 'ssti' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
