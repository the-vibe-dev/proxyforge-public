// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'env-file-exposure',
  family: 'cve-named',
  title: '.env file / secrets file exposure',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['path'],
  expectedSignals: ['secrets-exposed', 'env-file-returned', 'status-delta'],
  cwe: [200, 312],
};

const ENV_PATHS = [
  { id: 'env-root', value: '/.env', intent: 'Root .env file' },
  { id: 'env-local', value: '/.env.local', intent: '.env.local override file' },
  { id: 'env-production', value: '/.env.production', intent: '.env.production secrets' },
  { id: 'env-development', value: '/.env.development', intent: '.env.development config' },
  { id: 'env-staging', value: '/.env.staging', intent: '.env.staging config' },
  { id: 'env-backup', value: '/.env.bak', intent: '.env.bak backup file' },
  { id: 'env-old', value: '/.env.old', intent: '.env.old stale secrets' },
  { id: 'env-example', value: '/.env.example', intent: '.env.example template (may reveal key names)' },
  { id: 'env-secret', value: '/.env.secret', intent: '.env.secret extended secrets file' },
];

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return ENV_PATHS.slice(0, 8).map((p) => ({
    id: p.id,
    family: 'cve-named' as const,
    value: p.value,
    encoding: 'url' as const,
    intent: p.intent,
    destructiveRisk: 'none' as const,
    expectedSignals: ['env-file-returned', 'secrets-exposed'],
  }));
}

const SECRET_PATTERNS = [
  /^[A-Z_]+=.+$/m,                  // KEY=VALUE pattern
  /DB_PASSWORD\s*=/i,
  /SECRET_KEY\s*=/i,
  /API_KEY\s*=/i,
  /DATABASE_URL\s*=/i,
  /AWS_ACCESS_KEY_ID\s*=/i,
  /STRIPE_SECRET\s*=/i,
];

export function classify(
  resp: ScannerResponseInput,
  variant: PayloadVariant,
  _baseline: ScannerResponseInput,
): OracleClassification {
  const evidence: string[] = [];
  let responseClass: OracleClassification['responseClass'] = 'neutral-or-not-parsed';
  let confidence = 0.1;
  let nextAction: OracleClassification['nextAction'] = 'continue';

  if (resp.statusCode !== 200) {
    nextAction = 'stop-negative';
    evidence.push(`${resp.statusCode} — env file not found at ${variant.value}`);
    return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
  }

  const contentType = (resp.headers['content-type'] ?? '').toLowerCase();
  const isTextLike = contentType.includes('text') || contentType.includes('plain') || contentType.includes('octet');
  const matchedSecret = SECRET_PATTERNS.find((p) => p.test(resp.bodyText));

  if (matchedSecret) {
    responseClass = 'expected-proof';
    confidence = 0.97;
    nextAction = 'promote-finding';
    evidence.push(`Secrets exposed: env file at ${variant.value} contains KEY=VALUE entries`);
    evidence.push('Immediate rotation of exposed secrets required');
  } else if (isTextLike && resp.bodyText.length > 10) {
    responseClass = 'observed-value';
    confidence = 0.65;
    nextAction = 'confirm';
    evidence.push(`Env file returned with text content at ${variant.value} — manual review for secrets`);
  } else if (resp.statusCode === 200) {
    responseClass = 'observed-value';
    confidence = 0.45;
    nextAction = 'confirm';
    evidence.push(`200 response at ${variant.value} — verify if env content`);
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
