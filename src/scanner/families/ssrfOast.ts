// SSRF via OAST (DNS/HTTP callback) active check family.
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant, MutationContext } from '../types';

export const META = {
  id: 'ssrf-oast',
  family: 'ssrf-oast' as const,
  name: 'SSRF (OAST)',
  description: 'Detects blind SSRF via out-of-band DNS/HTTP callback probes.',
  defaultRisk: 'low' as const,
  insertionPointKinds: ['query', 'body', 'json', 'header', 'path'],
};

export function variants(ctx: MutationContext): PayloadVariant[] {
  if (!ctx.oastBaseUrl || !ctx.oastToken) return [];
  const base = `http://${ctx.oastToken}.${ctx.oastBaseUrl}/`;
  return [
    {
      id: 'ssrf-oast-1', family: 'ssrf-oast' as const,
      value: base,
      encoding: 'raw' as const,
      intent: 'HTTP OAST callback via injected URL',
      requiresOast: true, requiresBrowser: false,
      destructiveRisk: 'none' as const,
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'ssrf-oast-2', family: 'ssrf-oast' as const,
      value: `https://${ctx.oastToken}.${ctx.oastBaseUrl}/`,
      encoding: 'raw' as const,
      intent: 'HTTPS OAST callback — tests TLS handshake to OAST server',
      requiresOast: true, requiresBrowser: false,
      destructiveRisk: 'none' as const,
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'ssrf-oast-3', family: 'ssrf-oast' as const,
      value: `//dc.${ctx.oastToken}.${ctx.oastBaseUrl}/`,
      encoding: 'raw' as const,
      intent: 'Protocol-relative OAST URL — triggers DNS resolution',
      requiresOast: true, requiresBrowser: false,
      destructiveRisk: 'none' as const,
      expectedSignals: ['oast-callback-confirmed'],
    },
  ];
}
