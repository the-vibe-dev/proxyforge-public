// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'mass-assignment',
  family: 'mass-assignment',
  title: 'Mass assignment — extra field injection',
  severity: 'high',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['json', 'body', 'query'],
  expectedSignals: ['privileged-field-accepted', 'role-escalated', 'status-delta', 'extra-field-in-response'],
  cwe: [915],
};

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'ma-role-admin',
      family: 'mass-assignment',
      value: ',"role":"admin"',
      encoding: 'json-string',
      intent: 'Inject role=admin into update payload',
      destructiveRisk: 'none',
      expectedSignals: ['role-escalated', 'extra-field-in-response'],
    },
    {
      id: 'ma-is-admin',
      family: 'mass-assignment',
      value: ',"isAdmin":true',
      encoding: 'json-string',
      intent: 'Inject isAdmin=true boolean flag',
      destructiveRisk: 'none',
      expectedSignals: ['privileged-field-accepted'],
    },
    {
      id: 'ma-balance',
      family: 'mass-assignment',
      value: ',"balance":999999,"credit":999999',
      encoding: 'json-string',
      intent: 'Inject financial fields balance/credit into user update',
      destructiveRisk: 'none',
      expectedSignals: ['privileged-field-accepted', 'extra-field-in-response'],
    },
    {
      id: 'ma-verified',
      family: 'mass-assignment',
      value: ',"verified":true,"emailVerified":true,"phoneVerified":true',
      encoding: 'json-string',
      intent: 'Inject email/phone verification bypass fields',
      destructiveRisk: 'none',
      expectedSignals: ['privileged-field-accepted'],
    },
    {
      id: 'ma-price',
      family: 'mass-assignment',
      value: ',"price":0.01,"discount":99,"total":0',
      encoding: 'json-string',
      intent: 'Inject price manipulation fields on order endpoints',
      destructiveRisk: 'none',
      expectedSignals: ['privileged-field-accepted', 'extra-field-in-response'],
    },
    {
      id: 'ma-ownership',
      family: 'mass-assignment',
      value: ',"userId":1,"ownerId":1,"accountId":1',
      encoding: 'json-string',
      intent: 'Inject ownership fields to attempt IDOR via mass assignment',
      destructiveRisk: 'none',
      expectedSignals: ['privileged-field-accepted'],
    },
    {
      id: 'ma-nested-role',
      family: 'mass-assignment',
      value: ',"user":{"role":"admin","isAdmin":true}',
      encoding: 'json-string',
      intent: 'Nested object role injection for deeply structured APIs',
      destructiveRisk: 'none',
      expectedSignals: ['role-escalated'],
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

  const body = resp.bodyText.toLowerCase();
  const injectedFields = ['admin', 'isadmin', 'verified', 'balance', 'credit', 'price', 'discount', 'userid', 'ownerid'];
  const acceptedFields = injectedFields.filter((f) => body.includes(f) && !baseline.bodyText.toLowerCase().includes(f));

  if (acceptedFields.length > 0) {
    responseClass = 'expected-proof';
    confidence = 0.8;
    nextAction = 'promote-finding';
    evidence.push(`Mass assignment: injected fields present in response: ${acceptedFields.join(', ')}`);
  } else if (resp.statusCode === 200 && baseline.statusCode === 200 && resp.bodyText !== baseline.bodyText) {
    responseClass = 'observed-value';
    confidence = 0.4;
    nextAction = 'confirm';
    evidence.push('Response body changed after extra-field injection — manual verification recommended');
  } else if (resp.statusCode === 400 || resp.statusCode === 422) {
    responseClass = 'method-or-parser-rejected';
    confidence = 0.7;
    nextAction = 'stop-negative';
    evidence.push(`${resp.statusCode} — server rejected extra fields (strict validation)`);
  } else {
    nextAction = 'continue';
    evidence.push(`No clear mass assignment signal for ${variant.id}`);
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
