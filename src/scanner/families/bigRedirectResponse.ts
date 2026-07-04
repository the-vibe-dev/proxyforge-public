import type { PayloadVariant } from '../types';

export const META = {
  id: 'big-redirect-response',
  family: 'open-redirect' as const,
  name: 'Big Redirect / 200 with Location',
  description: 'Detects 200 responses with Location header (redirect-in-200) or 30x responses with unexpectedly large bodies.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'header', 'path'],
};

const PROBES = [
  { value: '', intent: 'Empty probe — observe if baseline response has Location header in 200', signals: ['redirect-in-200'] },
  { value: 'https://evil.example/', intent: 'Inject external URL — test if Location header reflects attacker URL in 200', signals: ['redirect-in-200', 'open-redirect'] },
  { value: '//evil.example/', intent: 'Protocol-relative URL — tests protocol-stripped redirect reflection', signals: ['redirect-in-200', 'open-redirect'] },
  { value: '/relative-redirect', intent: 'Relative URL injection — large 30x body may leak internal state', signals: ['redirect-in-200'] },
  { value: 'javascript:alert(1)', intent: 'javascript: URI in redirect target — bypasses scheme check for XSS', signals: ['redirect-in-200', 'xss-reflected'] },
  { value: 'data:text/html,<script>alert(1)</script>', intent: 'data: URI redirect — tests data URI acceptance in Location header', signals: ['redirect-in-200', 'xss-reflected'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `big-redirect-${i + 1}`,
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
