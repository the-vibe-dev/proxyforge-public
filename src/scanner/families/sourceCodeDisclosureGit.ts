// Adapted from source-reference/vantix/secops/skills/ patterns.
// Rewritten in TypeScript. No runtime dependency on the vendored source.
import type { FamilyMetadata, OracleClassification, PayloadVariant, ProbeContext, ScannerResponseInput } from '../types';

export const META: FamilyMetadata = {
  id: 'source-code-disclosure-git',
  family: 'cve-named',
  title: 'Git source code disclosure (/.git/ exposure)',
  severity: 'critical',
  destructiveRisk: 'none',
  requiresOast: false,
  requiresBrowser: false,
  insertionPointKinds: ['path'],
  expectedSignals: ['git-objects-exposed', 'source-code-accessible', 'config-exposed'],
  cwe: [200, 538],
};

const GIT_PATHS = [
  { id: 'git-head', value: '/.git/HEAD', intent: '.git/HEAD ref pointer — confirms git repo exposed' },
  { id: 'git-config', value: '/.git/config', intent: '.git/config — remote URL, credentials may be present' },
  { id: 'git-packed-refs', value: '/.git/packed-refs', intent: '.git/packed-refs — branch/tag hash list for reconstruction' },
  { id: 'git-logs-head', value: '/.git/logs/HEAD', intent: '.git/logs/HEAD — commit history reconstruction aid' },
  { id: 'git-description', value: '/.git/description', intent: '.git/description — repository name disclosure' },
  { id: 'git-index', value: '/.git/index', intent: '.git/index binary — file tree reconstruction signal' },
  { id: 'git-commit-obj', value: '/.git/objects/info/packs', intent: '.git/objects/info/packs — packfile listing for clone reconstruction' },
  { id: 'git-gitignore', value: '/.gitignore', intent: '.gitignore — reveals internal path structure' },
];

export function variants(_ctx: ProbeContext): PayloadVariant[] {
  return GIT_PATHS.map((p) => ({
    id: p.id,
    family: 'cve-named' as const,
    value: p.value,
    encoding: 'url' as const,
    intent: p.intent,
    destructiveRisk: 'none' as const,
    expectedSignals: ['git-objects-exposed', 'source-code-accessible'],
  }));
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

  if (resp.statusCode !== 200) {
    nextAction = 'stop-negative';
    evidence.push(`${resp.statusCode} — git path not accessible: ${variant.value}`);
    return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
  }

  const body = resp.bodyText;
  const isGitHead = variant.id === 'git-head' && (body.startsWith('ref: ') || /^[0-9a-f]{40}/.test(body));
  const isGitConfig = variant.id === 'git-config' && body.includes('[core]');
  const isPackedRefs = variant.id === 'git-packed-refs' && body.includes('refs/');
  const isGitLogs = variant.id === 'git-logs-head' && body.includes('commit');
  const isGitIndex = variant.id === 'git-index' && (body.startsWith('DIRC') || resp.bodyText.charCodeAt(0) === 68);
  const isPacks = variant.id === 'git-commit-obj' && body.includes('.pack');
  const isGitIgnore = variant.id === 'git-gitignore' && body.length > 0;

  const isGitContent = isGitHead || isGitConfig || isPackedRefs || isGitLogs || isGitIndex || isPacks;

  if (isGitContent) {
    responseClass = 'expected-proof';
    confidence = 0.97;
    nextAction = 'promote-finding';
    evidence.push(`Git source disclosure confirmed: ${variant.value} is accessible and contains git data`);
    if (isGitConfig && body.includes('password')) {
      evidence.push('WARNING: Git config contains credentials');
      confidence = 0.99;
    }
  } else if (isGitIgnore) {
    responseClass = 'observed-value';
    confidence = 0.6;
    nextAction = 'confirm';
    evidence.push('.gitignore exposed — internal path structure revealed');
  } else if (resp.statusCode === 200 && body.length > 5) {
    responseClass = 'observed-value';
    confidence = 0.5;
    nextAction = 'confirm';
    evidence.push(`200 at git path ${variant.value} — content verification required`);
  }

  return { payloadVariantId: variant.id, responseClass, confidence, evidence, nextAction };
}
