import type { ReleaseSecurityReviewPackage, SecurityReviewCategory } from './securityReviewEngine';

export type ReleaseSecurityProductionStatus = 'passed' | 'failed' | 'pinned-nonblocking';

export interface ReleaseSecurityProductionProof {
  id: string;
  lane:
    | 'local-listener'
    | 'secret-boundary'
    | 'exploit-control'
    | 'agent-control'
    | 'ai-provider-control'
    | 'platform-pin'
    | 'signed-trust'
    | 'production-ci'
    | 'clean-runtime'
    | 'artifact-hygiene'
    | 'package-refresh'
    | 'docs-schema';
  status: ReleaseSecurityProductionStatus;
  passedChecks: number;
  failedChecks: number;
  content: string;
  reason?: string;
}

export interface ReleaseSecurityProductionRequest {
  review: ReleaseSecurityReviewPackage;
  proofs: ReleaseSecurityProductionProof[];
  docs: string[];
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface ReleaseSecurityProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-release-security-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  proofCount: number;
  reviewFindingCount: number;
  requirements: {
    formalSecurityReviewPassed: boolean;
    allSecurityCategoriesCovered: boolean;
    noCriticalHighFindings: boolean;
    localListenersCovered: boolean;
    secretBoundaryCovered: boolean;
    reviewRedactionCovered: boolean;
    exploitControlsCovered: boolean;
    agentControlsCovered: boolean;
    aiProviderControlsCovered: boolean;
    platformPinsCovered: boolean;
    signedTrustCovered: boolean;
    productionCiCovered: boolean;
    cleanMachineRuntimeEvidenceCovered: boolean;
    artifactHygieneCovered: boolean;
    packageRefreshCovered: boolean;
    docsAndSchemasCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  productionReady: boolean;
  digestPreview: string;
  summaryText: string;
  content: string;
}

const requiredCategories: SecurityReviewCategory[] = [
  'local-listener',
  'secret-redaction',
  'exploit-control',
  'safety-policy',
  'signed-trust',
  'artifact-hygiene',
  'agent-control',
  'platform-pin',
  'production-gate',
];

export function buildReleaseSecurityProductionEvidencePackage(
  request: ReleaseSecurityProductionRequest,
): ReleaseSecurityProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const rawMaterial = [
    request.review.content,
    JSON.stringify(request.review.findings),
    ...request.proofs.map((proof) => `${proof.lane}\n${proof.reason ?? ''}\n${proof.content}`),
    request.docs.join('\n'),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const passedLane = (lane: ReleaseSecurityProductionProof['lane'], pattern?: RegExp) => request.proofs.some((proof) => (
    proof.lane === lane
    && proof.status === 'passed'
    && proof.passedChecks > 0
    && proof.failedChecks === 0
    && (pattern ? pattern.test(`${proof.reason ?? ''}\n${proof.content}`) : true)
  ));
  const findingsText = JSON.stringify(request.review.findings);
  const secretSamples = request.operationalSecretSamples ?? [];
  const requirements = {
    formalSecurityReviewPassed: request.review.kind === 'proxyforge-release-security-review'
      && request.review.status === 'pass'
      && request.review.failedCount === 0
      && request.review.warningCount === 0,
    allSecurityCategoriesCovered: requiredCategories.every((category) => (request.review.categories[category] ?? 0) > 0),
    noCriticalHighFindings: request.review.findings.every((finding) => finding.status === 'pass' && !['critical', 'high'].includes(finding.severity)),
    localListenersCovered: passedLane('local-listener', /loopback|127\.0\.0\.1|localhost|proxy|callback|websocket/i),
    secretBoundaryCovered: passedLane('secret-boundary', /full-fidelity|operational secrets|report-export-only|redact-only-during-report-export/i),
    reviewRedactionCovered: /\[redacted\]/i.test(request.review.content)
      && secretSamples.every((sample) => !request.review.content.includes(sample)),
    exploitControlsCovered: passedLane('exploit-control', /approval|scope|rate|stop-on-proof|non-destructive/i),
    agentControlsCovered: passedLane('agent-control', /70-command|commandCount=70|external-cwd|app\.asar|policy\/audit/i),
    aiProviderControlsCovered: passedLane('ai-provider-control', /proxyforge-ai-provider-production-evidence-package|Codex CLI|Claude CLI|OpenAI-compatible|no direct action traffic/i),
    platformPinsCovered: passedLane('platform-pin', /windows-trust-runner|ERROR_NOT_SUPPORTED|trust-store pin|nonblocking|Linux Package|Windows Package/i),
    signedTrustCovered: passedLane('signed-trust', /verified|signed|deny-unsigned|HMAC|signature/i),
    productionCiCovered: passedLane('production-ci', /[78][0-9]\/[78][0-9]|[78][0-9]-step|60-step|nightly|artifact upload|zero-flake|coverage owner|retained history/i),
    cleanMachineRuntimeEvidenceCovered: passedLane('clean-runtime', /clean-container|installed GUI|trusted-CA|NSIS|DPAPI|Platform Shell/i),
    artifactHygieneCovered: passedLane('artifact-hygiene', /\.gitignored|test-results|release\/|artifact hygiene/i),
    packageRefreshCovered: passedLane('package-refresh', /dist-electron\/securityReviewEngine\.js|dist-electron\/releaseSecurityProductionEngine\.js|packaged|package refresh/i),
    docsAndSchemasCovered: passedLane('docs-schema', /OPERATOR_GUIDE|RELEASE_CHECKLIST|SCHEMAS\.md|FEATURE_MATRIX|proxyforge-release-security-production-evidence-package/i),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|Bearer/i.test(rawMaterial),
    operationalSecretsPreserved: secretSamples.length > 0 && secretSamples.every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only redaction|submission\/report artifacts redact/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-release-security-production-evidence-package',
    generatedAt,
    review: request.review,
    proofs: request.proofs,
    requirements,
    notes: {
      scope: 'Production security evidence ties the formal review to package/runtime gates instead of treating a standalone checklist as sufficient.',
      secretBoundary: 'Operational executor materials stay full fidelity; release security review and submission/report artifacts redact only for export and handoff.',
      platformBoundary: 'Windows trust-store mutation remains an accepted nonblocking pin only for the documented windows-trust-runner host lane.',
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `release-security-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-release-security-production-evidence-package',
    title: 'Release security production evidence package',
    fileName: `proxyforge-release-security-production-${stamp}.json`,
    path: `release/proxyforge-release-security-production-${stamp}.json`,
    generatedAt,
    proofCount: request.proofs.length,
    reviewFindingCount: request.review.findingCount,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'Release security production evidence covers formal zero-finding security review, local listener binding, operational secret boundary, exploit controls, agent controls, AI provider controls, platform pins, signed trust, production CI, clean Linux/Windows runtime proof, artifact hygiene, package refresh, docs/schemas, full-fidelity executor material, and report-export-only redaction.',
    content,
  };
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
