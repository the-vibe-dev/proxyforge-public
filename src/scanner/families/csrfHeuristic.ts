// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'csrf-heuristic',
  family: 'csrf',
  title: 'CSRF token absence / bypass heuristic',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['body', 'header', 'query'],
  expectedSignals: ['csrf-token-absent', 'origin-not-checked', 'state-change-without-token'],
  cwe: [352],
};

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'csrf-no-token',
      family: 'csrf',
      value: '',
      encoding: 'raw',
      intent: 'Remove CSRF token entirely from state-changing request',
      destructiveRisk: 'none',
      expectedSignals: ['csrf-token-absent', 'state-change-without-token'],
    },
    {
      id: 'csrf-empty-token',
      family: 'csrf',
      value: '_token=&',
      encoding: 'raw',
      intent: 'Submit empty CSRF token value',
      destructiveRisk: 'none',
      expectedSignals: ['csrf-token-absent'],
    },
    {
      id: 'csrf-wrong-token',
      family: 'csrf',
      value: '_token=pf_invalid_csrf_00000000',
      encoding: 'raw',
      intent: 'Submit an invalid CSRF token — server should reject 403',
      destructiveRisk: 'none',
      expectedSignals: ['state-change-without-token'],
    },
    {
      id: 'csrf-origin-null',
      family: 'csrf',
      value: 'null',
      encoding: 'header-safe',
      intent: 'Origin: null — sandboxed context bypass',
      destructiveRisk: 'none',
      expectedSignals: ['origin-not-checked'],
    },
    {
      id: 'csrf-referer-stripped',
      family: 'csrf',
      value: '',
      encoding: 'header-safe',
      intent: 'Strip Referer header — servers validating only Referer may allow cross-origin',
      destructiveRisk: 'none',
      expectedSignals: ['origin-not-checked'],
    },
    {
      id: 'csrf-custom-header-absent',
      family: 'csrf',
      value: '',
      encoding: 'header-safe',
      intent: 'Remove X-CSRF-Token / X-Requested-With from AJAX request',
      destructiveRisk: 'none',
      expectedSignals: ['csrf-token-absent', 'state-change-without-token'],
    },
    {
      id: 'csrf-json-content-type',
      family: 'csrf',
      value: 'application/json',
      encoding: 'header-safe',
      intent: 'Switch Content-Type to application/json to bypass form-origin CSRF guards',
      destructiveRisk: 'none',
      expectedSignals: ['state-change-without-token'],
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

  const stateChangeAccepted = resp.statusCode >= 200 && resp.statusCode < 400;
  const baselineWasSuccess = baseline.statusCode >= 200 && baseline.statusCode < 400;

  if (stateChangeAccepted && baselineWasSuccess) {
    // Same success code without token — potential CSRF
    responseClass = 'expected-proof';
    confidence = 0.75;
    nextAction = 'confirm';
    evidence.push(`State-changing request succeeded (${resp.statusCode}) without CSRF token (variant: ${variant.id})`);
    evidence.push('Manual confirmation required: verify the action was actually performed');
  } else if (resp.statusCode === 403 || resp.statusCode === 400) {
    // Server correctly rejected — not vulnerable
    responseClass = 'method-or-parser-rejected';
    confidence = 0.9;
    nextAction = 'stop-negative';
    evidence.push(`Server returned ${resp.statusCode} — CSRF protection appears active for ${variant.id}`);
  } else {
    evidence.push('Ambiguous response; further testing required');
    nextAction = 'continue';
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
