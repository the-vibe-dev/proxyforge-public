// Open redirect active check family.
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant } from '../types';

export const META = {
  id: 'open-redirect',
  family: 'open-redirect' as const,
  name: 'Open Redirect',
  description: 'Detects open redirect vulnerabilities via external URL injection.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'path'],
};

const REDIRECT_PROBES = [
  { value: 'https://evil.example.com/', intent: 'Absolute HTTPS redirect to external host', signals: ['redirect-location'] },
  { value: '//evil.example.com/', intent: 'Protocol-relative redirect — inherits current scheme', signals: ['redirect-location'] },
  { value: '/\\evil.example.com/', intent: 'Backslash redirect for IE/Edge parsing differences', signals: ['redirect-location'] },
  { value: 'javascript:alert(1)', intent: 'javascript: URI for XSS via redirect', signals: ['redirect-location'] },
  { value: 'https:evil.example.com/', intent: 'https: without slashes — browser may follow', signals: ['redirect-location'] },
  { value: '//evil.example.com%2f', intent: 'URL-encoded slash after host to bypass filter', signals: ['redirect-location'] },
  { value: '\\\\evil.example.com/', intent: 'Double backslash — Windows UNC path style', signals: ['redirect-location'] },
  { value: 'https://evil.example.com%23.target.com/', intent: 'Fragment injection to confuse parsers', signals: ['redirect-location'] },
  { value: 'https://target.com@evil.example.com/', intent: 'Credentials-before-host URL trick', signals: ['redirect-location'] },
  { value: 'data:text/html,<script>alert(1)</script>', intent: 'data: URI for XSS via redirect', signals: ['redirect-location'] },
];

export function variants(): PayloadVariant[] {
  return REDIRECT_PROBES.map((probe, i) => ({
    id: `redir-${i + 1}`,
    family: 'open-redirect' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
