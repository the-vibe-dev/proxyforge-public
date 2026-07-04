// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'deserialization-java',
  family: 'deserialization',
  title: 'Java deserialization gadget chains',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['body', 'cookie', 'header'],
  expectedSignals: ['oast-callback-confirmed', 'error-disclosure', 'timing-delta', 'status-delta'],
  cwe: [502],
};

// Java serialization magic bytes: 0xACED 0x0005 (base64: rO0AB...)
const JAVA_SER_MAGIC_B64 = 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwABRgAKbG9hZEZhY3RvcnhwP0AAAAAAAAh3CAAAABAAAAAAAAx4';

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const oastHost = ctx.oastBaseUrl ? new URL(ctx.oastBaseUrl).hostname : 'oast.pf.example';
  return [
    {
      id: 'deser-java-magic-bytes',
      family: 'deserialization',
      value: JAVA_SER_MAGIC_B64,
      encoding: 'raw',
      intent: 'Java serialized object magic bytes (rO0...) in body — triggers deserialisation errors',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure', 'status-delta'],
    },
    {
      id: 'deser-java-commons-collections-oast',
      family: 'deserialization',
      value: `rO0OAST:${oastHost}:CC3.1-gadget`,
      encoding: 'raw',
      intent: 'CommonsCollections 3.1 gadget chain — DNS callback confirms RCE gadget fire',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-java-spring-oast',
      family: 'deserialization',
      value: `rO0OAST:${oastHost}:Spring-gadget`,
      encoding: 'raw',
      intent: 'Spring Framework gadget chain — OAST-confirmed DNS/HTTP callback',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-java-groovy-oast',
      family: 'deserialization',
      value: `rO0OAST:${oastHost}:Groovy-gadget`,
      encoding: 'raw',
      intent: 'Groovy ConvertedClosure gadget chain — OAST callback confirms execution',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'deser-java-b64-wrapped',
      family: 'deserialization',
      value: Buffer.from(JAVA_SER_MAGIC_B64).toString('base64'),
      encoding: 'raw',
      intent: 'Base64-wrapped Java serialized bytes — for endpoints that base64-decode before deserializing',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure'],
    },
    {
      id: 'deser-java-viewstate',
      family: 'deserialization',
      value: '/wEyNjY2NjYAAAA=',
      encoding: 'raw',
      intent: 'JSF ViewState-style serialized payload for Java EE targets',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure', 'status-delta'],
    },
    {
      id: 'deser-java-timing-probe',
      family: 'deserialization',
      value: `rO0ABX${Buffer.alloc(8192, 0x41).toString('base64').slice(0, 32)}`,
      encoding: 'raw',
      intent: 'Oversized serialized payload to detect excessive deserialisation time (timing oracle)',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['timing-delta'],
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
  const javaError = body.includes('classnotfound') || body.includes('invalidclassexception') ||
    body.includes('java.io') || body.includes('deserializ') || body.includes('java.lang');
  const timingDelta = resp.responseTimeMs - baseline.responseTimeMs;

  if (variant.requiresOast) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.2;
    nextAction = 'continue';
    evidence.push('OAST probe sent — awaiting DNS/HTTP callback');
  } else if (javaError) {
    responseClass = 'parser-error';
    confidence = 0.75;
    nextAction = 'confirm';
    evidence.push('Java deserialization error fragment in response — gadget chain may be viable');
  } else if (timingDelta > 3000) {
    responseClass = 'timing-delta';
    confidence = 0.6;
    nextAction = 'confirm';
    evidence.push(`Timing delta ${timingDelta}ms — possible slow deserialisation`);
  } else if (resp.statusCode !== baseline.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.4;
    nextAction = 'continue';
    evidence.push(`Status changed ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('No Java deserialization signal');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
