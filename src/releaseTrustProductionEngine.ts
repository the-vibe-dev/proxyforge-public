export type ReleaseTrustPolicyStatus = 'approved' | 'pinned' | 'blocked' | string;

export interface ReleaseTrustSbomComponent {
  name: string;
  version: string;
  packagePath?: string;
  integrity?: string;
  license?: string;
  development?: boolean;
}

export interface ReleaseTrustSbom {
  kind: 'proxyforge-release-trust-sbom';
  format: 'spdx-json-lite' | 'cyclonedx-json-lite' | string;
  generatedFrom: 'package-lock.json' | string;
  rootPackage: {
    name: string;
    version: string;
  };
  lockfileVersion: number;
  componentCount: number;
  components: ReleaseTrustSbomComponent[];
}

export interface ReleaseTrustArtifactDigest {
  path: string;
  sha256: string;
  sizeBytes: number;
  source: 'source' | 'lockfile' | 'build' | 'script' | 'docs' | 'workflow' | 'release-artifact' | string;
  required: boolean;
  status: 'present' | 'missing' | 'pinned-nonblocking' | string;
}

export interface ReleaseTrustProvenanceStatement {
  kind: 'proxyforge-release-provenance-v1';
  builderId: string;
  sourceRef: string;
  sourceCommit: string;
  buildCommand: string;
  verificationCommands: string[];
  materials: ReleaseTrustArtifactDigest[];
  subjectDigests: ReleaseTrustArtifactDigest[];
  attestationFormat: 'slsa-provenance-lite' | string;
  signed: boolean;
  signingKeyId?: string;
  signingState: ReleaseTrustPolicyStatus;
  retentionDays: number;
}

export interface ReleaseTrustPolicy {
  packageManager: 'npm' | string;
  lockfileFrozen: boolean;
  installCommand: string;
  auditCommand: string;
  sbomCommand: string;
  checksumCommand: string;
  provenanceCommand: string;
  licenseReviewStatus: ReleaseTrustPolicyStatus;
  dependencyReviewStatus: ReleaseTrustPolicyStatus;
  unsignedArtifactPolicy: string;
  signingState: ReleaseTrustPolicyStatus;
  notarizationState: ReleaseTrustPolicyStatus;
  verificationCommand: string;
  releaseArtifactRetentionDays: number;
}

export interface ReleaseTrustProductionRequest {
  sbom: ReleaseTrustSbom;
  artifactDigests: ReleaseTrustArtifactDigest[];
  provenance: ReleaseTrustProvenanceStatement;
  policy: ReleaseTrustPolicy;
  docs: string[];
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface ReleaseTrustProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-release-trust-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  componentCount: number;
  artifactDigestCount: number;
  requirements: {
    sbomGeneratedFromLockfile: boolean;
    dependencyIntegrityCovered: boolean;
    licenseReviewCovered: boolean;
    packageLockFrozenCovered: boolean;
    sourceChecksumsCovered: boolean;
    buildChecksumsCovered: boolean;
    docsAndAgentChecksumsCovered: boolean;
    workflowChecksumsCovered: boolean;
    provenanceStatementCovered: boolean;
    provenanceLinksMaterialsAndSubjects: boolean;
    signingStatePinned: boolean;
    notarizationStatePinned: boolean;
    verificationCommandsCovered: boolean;
    releaseArtifactRetentionCovered: boolean;
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

const requiredSourcePaths = [
  /package\.json$/,
  /package-lock\.json$/,
  /scripts\/proxyforge-agent\.mjs$/,
];

const requiredBuildPaths = [
  /dist\/index\.html$/,
  /dist-electron\/main\.js$/,
  /dist-electron\/headlessRunner\.js$/,
];

const requiredDocsPaths = [
  /docs\/INSTALL_LINUX_WINDOWS\.md$/,
  /docs\/OPERATOR_GUIDE\.md$/,
  /docs\/agents\/SCHEMAS\.md$/,
];

const requiredWorkflowPaths = [
  /\.github\/workflows\/nightly-full-suite\.yml$/,
];

export function buildReleaseTrustProductionEvidencePackage(
  request: ReleaseTrustProductionRequest,
): ReleaseTrustProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const docsText = request.docs.join('\n');
  const componentText = JSON.stringify(request.sbom.components);
  const artifactText = request.artifactDigests.map((artifact) => `${artifact.path} ${artifact.sha256} ${artifact.status}`).join('\n');
  const provenanceText = JSON.stringify(request.provenance);
  const policyText = JSON.stringify(request.policy);
  const rawMaterial = [
    JSON.stringify(request.sbom),
    artifactText,
    provenanceText,
    policyText,
    docsText,
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const presentArtifacts = request.artifactDigests.filter((artifact) => artifact.status === 'present');
  const hasPresentPath = (patterns: RegExp[]) => patterns.every((pattern) => presentArtifacts.some((artifact) => (
    pattern.test(artifact.path)
    && /^[a-f0-9]{64}$/i.test(artifact.sha256)
    && artifact.sizeBytes > 0
  )));
  const materialPaths = new Set(request.provenance.materials.map((artifact) => artifact.path));
  const subjectPaths = new Set(request.provenance.subjectDigests.map((artifact) => artifact.path));
  const presentRequiredPaths = request.artifactDigests
    .filter((artifact) => artifact.required && artifact.status === 'present')
    .map((artifact) => artifact.path);
  const requirements = {
    sbomGeneratedFromLockfile: request.sbom.kind === 'proxyforge-release-trust-sbom'
      && request.sbom.generatedFrom === 'package-lock.json'
      && request.sbom.lockfileVersion >= 2
      && request.sbom.componentCount === request.sbom.components.length
      && request.sbom.componentCount > 0,
    dependencyIntegrityCovered: request.sbom.components.length > 0
      && request.sbom.components.every((component) => /^sha(256|384|512)-/i.test(component.integrity ?? '')),
    licenseReviewCovered: /approved|manual|review|allowlist|deny/i.test(`${request.policy.licenseReviewStatus} ${docsText}`)
      && /license/i.test(rawMaterial),
    packageLockFrozenCovered: request.policy.packageManager === 'npm'
      && request.policy.lockfileFrozen
      && /npm ci/i.test(request.policy.installCommand),
    sourceChecksumsCovered: hasPresentPath(requiredSourcePaths),
    buildChecksumsCovered: hasPresentPath(requiredBuildPaths),
    docsAndAgentChecksumsCovered: hasPresentPath(requiredDocsPaths),
    workflowChecksumsCovered: hasPresentPath(requiredWorkflowPaths),
    provenanceStatementCovered: request.provenance.kind === 'proxyforge-release-provenance-v1'
      && /slsa|provenance/i.test(request.provenance.attestationFormat)
      && Boolean(request.provenance.builderId)
      && Boolean(request.provenance.sourceCommit)
      && request.provenance.verificationCommands.length >= 4,
    provenanceLinksMaterialsAndSubjects: presentRequiredPaths.every((artifactPath) => materialPaths.has(artifactPath) || subjectPaths.has(artifactPath))
      && request.provenance.subjectDigests.some((artifact) => /dist-electron\/headlessRunner\.js|dist\/index\.html/.test(artifact.path)),
    signingStatePinned: request.provenance.signed
      || /signed|cosign|notar|internal|local|pinned|operator|required/i.test(`${request.provenance.signingState} ${request.policy.signingState} ${request.policy.unsignedArtifactPolicy}`),
    notarizationStatePinned: /notar|windows|mac|linux|internal|pinned|not applicable|operator/i.test(`${request.policy.notarizationState} ${docsText}`),
    verificationCommandsCovered: /release:trust|release-trust/i.test(request.policy.verificationCommand)
      && request.provenance.verificationCommands.some((command) => /npm ci/i.test(command))
      && request.provenance.verificationCommands.some((command) => /npm run build/i.test(command))
      && request.provenance.verificationCommands.some((command) => /test:ci:fast/i.test(command)),
    releaseArtifactRetentionCovered: request.policy.releaseArtifactRetentionDays >= 30
      && request.provenance.retentionDays >= 30,
    docsAndSchemasCovered: /INSTALL_LINUX_WINDOWS|OPERATOR_GUIDE|SCHEMAS\.md|proxyforge-release-trust-production-evidence-package|SBOM|checksums|provenance|report-export-only/i.test(docsText),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|Bearer/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only redaction|submission\/report artifacts redact/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-release-trust-production-evidence-package',
    generatedAt,
    sbom: request.sbom,
    artifactDigests: request.artifactDigests,
    provenance: request.provenance,
    policy: request.policy,
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    notes: {
      trustBoundary: 'Release trust evidence must be generated from the exact package-lock, build outputs, scripts, docs, workflow files, and release artifacts being promoted.',
      signingBoundary: 'Unsigned local/internal artifacts are permitted only when explicitly pinned; external distribution must attach the operator-selected signer/notary evidence.',
      secretBoundary: 'Operational executor materials stay full fidelity; submission/report artifacts redact only during export.',
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `release-trust-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-release-trust-production-evidence-package',
    title: 'Release trust production evidence package',
    fileName: `proxyforge-release-trust-production-${stamp}.json`,
    path: `release/proxyforge-release-trust-production-${stamp}.json`,
    generatedAt,
    componentCount: request.sbom.componentCount,
    artifactDigestCount: request.artifactDigests.length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'Release trust production evidence covers package-lock-derived SBOM, dependency integrity, license/dependency review policy, source/build/docs/workflow SHA-256 checksums, SLSA-lite provenance, signing/notarization state pins, verification commands, artifact retention, full-fidelity executor material, and report-export-only redaction.',
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
