// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'graphql-introspection',
  family: 'graphql-attack',
  title: 'GraphQL introspection active probe',
  severity: 'medium',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['body', 'query', 'graphql'],
  expectedSignals: ['schema-exposed', 'types-list-returned', 'status-delta'],
  cwe: [200],
};

const INTROSPECTION_QUERY = `{"query":"{__schema{types{name}}}"}`;
const FULL_INTROSPECTION = `{"query":"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name}}}}"}`;

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return [
    {
      id: 'gql-intro-basic',
      family: 'graphql-attack',
      value: INTROSPECTION_QUERY,
      encoding: 'json-string',
      intent: 'Minimal __schema query to detect introspection availability',
      destructiveRisk: 'none',
      expectedSignals: ['schema-exposed', 'types-list-returned'],
    },
    {
      id: 'gql-intro-full',
      family: 'graphql-attack',
      value: FULL_INTROSPECTION,
      encoding: 'json-string',
      intent: 'Full introspection query — dumps complete schema types, mutations, directives',
      destructiveRisk: 'none',
      expectedSignals: ['schema-exposed'],
    },
    {
      id: 'gql-intro-get',
      family: 'graphql-attack',
      value: 'query=%7B__schema%7Btypes%7Bname%7D%7D%7D',
      encoding: 'url',
      intent: 'Introspection via GET request query param (some CDNs/GW allow GET for queries)',
      destructiveRisk: 'none',
      expectedSignals: ['schema-exposed', 'types-list-returned'],
    },
    {
      id: 'gql-intro-fragment',
      family: 'graphql-attack',
      value: `{"query":"fragment PF on __Schema { types { name } } { ...PF }"}`,
      encoding: 'json-string',
      intent: 'Introspection via fragment to bypass naive block-if-introspection checks',
      destructiveRisk: 'none',
      expectedSignals: ['schema-exposed'],
    },
    {
      id: 'gql-intro-alias-bypass',
      family: 'graphql-attack',
      value: `{"query":"{ pfschema: __schema { types { name } } }"}`,
      encoding: 'json-string',
      intent: 'Aliased __schema to bypass keyword blockers that reject "__schema"',
      destructiveRisk: 'none',
      expectedSignals: ['schema-exposed'],
    },
    {
      id: 'gql-intro-type-name',
      family: 'graphql-attack',
      value: `{"query":"{ __typename }"}`,
      encoding: 'json-string',
      intent: '__typename probe — minimum viable introspection signal',
      destructiveRisk: 'none',
      expectedSignals: ['types-list-returned'],
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

  const body = resp.bodyText;
  const hasData = body.includes('"data"');
  const hasSchema = body.includes('"__schema"') || body.includes('"types"');
  const hasTypename = body.includes('"__typename"');
  const hasError = body.includes('"errors"');

  if (hasData && hasSchema) {
    responseClass = 'expected-proof';
    confidence = 0.95;
    nextAction = 'promote-finding';
    evidence.push('GraphQL introspection enabled — full schema returned');
    if (body.length > 5000) evidence.push(`Schema size: ~${Math.round(body.length / 1024)}KB`);
  } else if (hasData && hasTypename) {
    responseClass = 'observed-value';
    confidence = 0.7;
    nextAction = 'confirm';
    evidence.push('__typename returned — GraphQL endpoint confirmed, introspection may be partial');
  } else if (hasError && body.toLowerCase().includes('introspection')) {
    responseClass = 'method-or-parser-rejected';
    confidence = 0.9;
    nextAction = 'stop-negative';
    evidence.push('Introspection explicitly disabled by server policy');
  } else if (resp.statusCode === 200 && hasData) {
    responseClass = 'observed-value';
    confidence = 0.5;
    nextAction = 'confirm';
    evidence.push('GraphQL data response but schema not obviously exposed');
  } else {
    nextAction = 'continue';
    evidence.push(`No introspection signal (status: ${resp.statusCode}, variant: ${variant.id})`);
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
