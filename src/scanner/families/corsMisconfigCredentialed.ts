// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'cors-misconfig-credentialed',
  family: 'cors-misconfig',
  title: 'CORS credentialed misconfiguration',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header'],
  expectedSignals: ['acao-wildcard', 'acao-reflected', 'acac-true-with-wildcard', 'null-origin-allowed'],
  cwe: [942, 346],
};

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'cors-cred-attacker-origin',
      family: 'cors-misconfig',
      value: 'https://attacker.pf.example',
      encoding: 'header-safe',
      intent: 'Arbitrary attacker Origin — check if server reflects it in ACAO with ACAC: true',
      destructiveRisk: 'none',
      expectedSignals: ['acao-reflected', 'acac-true-with-wildcard'],
    },
    {
      id: 'cors-cred-null-origin',
      family: 'cors-misconfig',
      value: 'null',
      encoding: 'header-safe',
      intent: 'Origin: null — sandboxed iframe bypass for credentialed CORS',
      destructiveRisk: 'none',
      expectedSignals: ['null-origin-allowed'],
    },
    {
      id: 'cors-cred-subdomain',
      family: 'cors-misconfig',
      value: 'https://attacker.pf.legit-origin.example',
      encoding: 'header-safe',
      intent: 'Subdomain of trusted origin — checks for over-permissive origin matching (suffix match)',
      destructiveRisk: 'none',
      expectedSignals: ['acao-reflected'],
    },
    {
      id: 'cors-cred-prefix-bypass',
      family: 'cors-misconfig',
      value: 'https://legit.example.attacker.pf.example',
      encoding: 'header-safe',
      intent: 'Origin containing trusted domain as prefix — regex bypass',
      destructiveRisk: 'none',
      expectedSignals: ['acao-reflected'],
    },
    {
      id: 'cors-cred-http-downgrade',
      family: 'cors-misconfig',
      value: 'http://legit.example',
      encoding: 'header-safe',
      intent: 'HTTP version of trusted HTTPS origin — protocol downgrade CORS bypass',
      destructiveRisk: 'none',
      expectedSignals: ['acao-reflected'],
    },
    {
      id: 'cors-cred-wildcard-check',
      family: 'cors-misconfig',
      value: '*',
      encoding: 'header-safe',
      intent: 'Wildcard origin with credentialed request — check for ACAO: * + ACAC: true (invalid but some servers emit it)',
      destructiveRisk: 'none',
      expectedSignals: ['acao-wildcard', 'acac-true-with-wildcard'],
    },
    {
      id: 'cors-cred-unicode-bypass',
      family: 'cors-misconfig',
      value: 'https://legit․example',
      encoding: 'header-safe',
      intent: 'Unicode dot lookalike (U+2024) in origin to bypass origin validation',
      destructiveRisk: 'none',
      expectedSignals: ['acao-reflected'],
    },
  ];
}

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  _baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  let responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.1;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  const acao = resp.headers['access-control-allow-origin'] ?? '';
  const acac = (resp.headers['access-control-allow-credentials'] ?? '').toLowerCase();
  const credentialed = acac === 'true';

  if (acao === '*' && credentialed) {
    responseClass = 'expected-proof';
    confidence = 0.97;
    nextAction = 'promote-finding';
    evidence.push('CORS misconfiguration: ACAO: * with ACAC: true (browsers will reject, but server is misconfigured)');
  } else if (acao.includes('attacker.pf.example') && credentialed) {
    responseClass = 'expected-proof';
    confidence = 0.95;
    nextAction = 'promote-finding';
    evidence.push(`Critical CORS: arbitrary origin reflected (${acao}) with credentials allowed`);
  } else if (acao === 'null' && credentialed) {
    responseClass = 'expected-proof';
    confidence = 0.9;
    nextAction = 'promote-finding';
    evidence.push('CORS null origin allowed with credentials — sandboxed iframe attack possible');
  } else if (acao && credentialed && acao !== '' && acao !== 'null') {
    // Some form of reflective CORS with credentials
    const injectedOrigin = variant.value;
    if (acao.includes(new URL(injectedOrigin.startsWith('http') ? injectedOrigin : 'https://x').hostname)) {
      responseClass = 'expected-proof';
      confidence = 0.85;
      nextAction = 'promote-finding';
      evidence.push(`Attacker-controlled origin suffix/prefix matched and reflected: ${acao}`);
    } else {
      responseClass = 'observed-value';
      confidence = 0.5;
      nextAction = 'confirm';
      evidence.push(`ACAO: ${acao} with credentials — verify attacker control of reflected origin`);
    }
  } else if (acao) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.2;
    nextAction = 'continue';
    evidence.push(`ACAO present (${acao}) but no credentials — lower risk`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('No CORS headers; endpoint does not appear to implement CORS');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
