// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'password-reset-token-leak',
  family: 'session-fixation',
  title: 'Password reset token leakage',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body', 'header'],
  expectedSignals: ['token-in-referrer', 'token-in-response', 'token-predictable', 'token-reusable'],
  cwe: [640, 200],
};

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'prt-referrer-leak',
      family: 'session-fixation',
      value: 'Referer: https://legit.example/reset?token=CAPTURED_TOKEN',
      encoding: 'header-safe',
      intent: 'Check if reset token leaks in Referer header to third-party resources',
      destructiveRisk: 'none',
      expectedSignals: ['token-in-referrer'],
    },
    {
      id: 'prt-token-in-url',
      family: 'session-fixation',
      value: 'token=pf_probe_reset_00000001',
      encoding: 'url',
      intent: 'Token in URL query string — check if server logs / Referer expose it',
      destructiveRisk: 'none',
      expectedSignals: ['token-in-referrer'],
    },
    {
      id: 'prt-weak-token',
      family: 'session-fixation',
      value: 'token=000001',
      encoding: 'url',
      intent: 'Predictably short/sequential reset token — brute-force feasibility probe',
      destructiveRisk: 'none',
      expectedSignals: ['token-predictable'],
    },
    {
      id: 'prt-reuse-token',
      family: 'session-fixation',
      value: 'token=pf_probe_reset_00000001',
      encoding: 'url',
      intent: 'Re-submit the same token twice to check for single-use enforcement',
      destructiveRisk: 'none',
      expectedSignals: ['token-reusable'],
    },
    {
      id: 'prt-host-poison',
      family: 'session-fixation',
      value: 'attacker.pf.example',
      encoding: 'header-safe',
      intent: 'Host header poison on reset request — token embedded in email link sent to attacker domain',
      destructiveRisk: 'none',
      expectedSignals: ['token-in-response'],
    },
    {
      id: 'prt-response-contains-token',
      family: 'session-fixation',
      value: '',
      encoding: 'raw',
      intent: 'Check if reset response body inadvertently includes the token',
      destructiveRisk: 'none',
      expectedSignals: ['token-in-response'],
    },
    {
      id: 'prt-no-expiry',
      family: 'session-fixation',
      value: 'token=pf_probe_reset_old_00000001',
      encoding: 'url',
      intent: 'Submit an old-format token to check for missing expiry enforcement',
      destructiveRisk: 'none',
      expectedSignals: ['token-reusable'],
    },
  ];
}

const TOKEN_PATTERN = /[a-f0-9]{32,}|[A-Za-z0-9\-_]{32,}/;

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  let responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.1;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  if (variant.id === 'prt-response-contains-token' || variant.id === 'prt-host-poison') {
    const tokenMatch = TOKEN_PATTERN.exec(resp.bodyText);
    if (tokenMatch) {
      responseClass = 'expected-proof';
      confidence = 0.8;
      nextAction = 'promote-finding';
      evidence.push(`Reset token-like value found in response body: "${tokenMatch[0].slice(0, 20)}..."`);
    } else {
      nextAction = 'stop-negative';
      evidence.push('No token-like value in response body');
    }
  } else if (variant.id === 'prt-reuse-token' || variant.id === 'prt-no-expiry') {
    if (resp.statusCode >= 200 && resp.statusCode < 400) {
      responseClass = 'expected-proof';
      confidence = 0.85;
      nextAction = 'promote-finding';
      evidence.push(`Token accepted on second submission (${resp.statusCode}) — no single-use enforcement`);
    } else {
      responseClass = 'method-or-parser-rejected';
      confidence = 0.9;
      nextAction = 'stop-negative';
      evidence.push(`Token rejected (${resp.statusCode}) — single-use or expiry enforced`);
    }
  } else if (baseline.statusCode !== resp.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.4;
    nextAction = 'continue';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'continue';
    evidence.push('No clear leakage signal from this variant');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
