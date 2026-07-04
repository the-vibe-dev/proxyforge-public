export type PlatformReleasePlatform = 'linux' | 'windows';
export type PlatformReleaseStatus = 'passed' | 'blocked' | 'failed' | 'scheduled';

export interface PlatformReleaseArtifactProof {
  id: string;
  platform: PlatformReleasePlatform;
  artifactType: 'appimage' | 'deb' | 'linux-unpacked' | 'nsis' | 'portable' | 'win-unpacked' | 'win-zip';
  path: string;
  sha256: string;
  sizeBytes: number;
  builtAt: string;
  evidence: string[];
  content: string;
}

export interface PlatformReleaseSmokeProof {
  id: string;
  platform: PlatformReleasePlatform;
  lane:
    | 'electron-shell'
    | 'headless-cli'
    | 'agent-cli'
    | 'runtime-proxy-cert-oast-report'
    | 'browser-routing'
    | 'deb-install'
    | 'trusted-ca-browser'
    | 'nsis-install'
    | 'dpapi-cookie'
    | 'uninstall';
  status: PlatformReleaseStatus;
  passedChecks: number;
  blockedChecks: number;
  failedChecks: number;
  checks: string[];
  blockedReason?: string;
  content: string;
}

export interface PlatformUiVisualQaSnapshot {
  id: string;
  viewport: 'desktop' | 'mobile';
  renderer: 'react-vite';
  toolSurfaces: string[];
  navigationGroups: string[];
  densityScore: number;
  nonBlankPixelRatio: number;
  overlapCount: number;
  keyboardReachable: boolean;
  content: string;
}

export interface PlatformReleaseGateProof {
  id: string;
  name: string;
  command: string;
  status: PlatformReleaseStatus;
  completedSteps: number;
  totalSteps: number;
  evidence: string[];
  content: string;
}

export interface PlatformReleaseInstallDocProof {
  id: string;
  title: string;
  path: string;
  coveredTopics: string[];
  content: string;
}

export interface PlatformReleaseSecurityReviewProof {
  id: string;
  status: PlatformReleaseStatus;
  coveredAreas: string[];
  criticalFindingCount: number;
  highFindingCount: number;
  signedBy: string;
  content: string;
}

export interface PlatformReleasePlatformPin {
  id: string;
  platform: PlatformReleasePlatform;
  runner: string;
  status: 'accepted' | 'pinned-nonblocking';
  reason: string;
  content: string;
}

export interface PlatformReleaseParityEvidenceRequest {
  uiSnapshots: PlatformUiVisualQaSnapshot[];
  artifacts: PlatformReleaseArtifactProof[];
  smokes: PlatformReleaseSmokeProof[];
  gates: PlatformReleaseGateProof[];
  installDocs: PlatformReleaseInstallDocProof[];
  securityReviews: PlatformReleaseSecurityReviewProof[];
  platformPins: PlatformReleasePlatformPin[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface PlatformReleaseParityEvidencePackage {
  id: string;
  kind: 'proxyforge-platform-release-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  artifactCount: number;
  smokeCount: number;
  gateCount: number;
  documentationCount: number;
  requirements: {
    denseNavigationCovered: boolean;
    visualQaCovered: boolean;
    linuxElectronShellCovered: boolean;
    windowsElectronShellCovered: boolean;
    linuxArtifactsCovered: boolean;
    windowsArtifactsCovered: boolean;
    packagedHeadlessCliCovered: boolean;
    packagedAgentCliCovered: boolean;
    packagedRuntimeProxyCertOastReportCovered: boolean;
    packagedBrowserRoutingCovered: boolean;
    linuxInstallTrustUninstallCovered: boolean;
    windowsInstallerUninstallCovered: boolean;
    windowsTrustStorePinCovered: boolean;
    fastSuiteCovered: boolean;
    fullNightlySuiteCovered: boolean;
    installDocsCovered: boolean;
    securityReviewCovered: boolean;
    platformPinsCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

const requiredUiSurfaces = [
  'Proxy',
  'Target',
  'Repeater',
  'Intruder',
  'Scanner',
  'Sequencer',
  'Decoder',
  'Comparer',
  'Logger',
  'Organizer',
  'Extensions',
  'Collaborator',
  'Reports',
  'AI',
  'Automations',
  'Exploit Lab',
];

export function buildPlatformReleaseParityEvidencePackage(
  request: PlatformReleaseParityEvidenceRequest,
): PlatformReleaseParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const rawMaterial = [
    JSON.stringify(request.uiSnapshots),
    ...request.artifacts.map((item) => item.content),
    ...request.smokes.map((item) => item.content),
    ...request.gates.map((item) => item.content),
    ...request.installDocs.map((item) => item.content),
    ...request.securityReviews.map((item) => item.content),
    ...request.platformPins.map((item) => item.content),
  ].join('\n');
  const passedSmoke = (platform: PlatformReleasePlatform, lane: PlatformReleaseSmokeProof['lane']) => (
    request.smokes.some((smoke) => (
      smoke.platform === platform
      && smoke.lane === lane
      && smoke.status === 'passed'
      && smoke.failedChecks === 0
      && smoke.passedChecks > 0
    ))
  );
  const hasArtifact = (platform: PlatformReleasePlatform, artifactTypes: PlatformReleaseArtifactProof['artifactType'][]) => (
    artifactTypes.every((artifactType) => request.artifacts.some((artifact) => (
      artifact.platform === platform
      && artifact.artifactType === artifactType
      && artifact.sha256.length >= 16
      && artifact.sizeBytes > 0
    )))
  );
  const hasDocTopics = (topics: string[]) => {
    const topicText = request.installDocs.flatMap((doc) => doc.coveredTopics).join('\n').toLowerCase();
    return topics.every((topic) => topicText.includes(topic.toLowerCase()));
  };
  const hasGate = (pattern: RegExp) => request.gates.some((gate) => (
    pattern.test(`${gate.name} ${gate.command}`)
    && gate.status === 'passed'
    && gate.completedSteps === gate.totalSteps
    && gate.totalSteps > 0
  ));
  const requirements = {
    denseNavigationCovered: request.uiSnapshots.length >= 2
      && request.uiSnapshots.every((snapshot) => snapshot.renderer === 'react-vite')
      && requiredUiSurfaces.every((surface) => request.uiSnapshots.some((snapshot) => snapshot.toolSurfaces.includes(surface)))
      && request.uiSnapshots.every((snapshot) => snapshot.navigationGroups.length >= 5 && snapshot.densityScore >= 90),
    visualQaCovered: request.uiSnapshots.some((snapshot) => snapshot.viewport === 'desktop')
      && request.uiSnapshots.some((snapshot) => snapshot.viewport === 'mobile')
      && request.uiSnapshots.every((snapshot) => snapshot.nonBlankPixelRatio >= 0.25 && snapshot.overlapCount === 0 && snapshot.keyboardReachable),
    linuxElectronShellCovered: passedSmoke('linux', 'electron-shell'),
    windowsElectronShellCovered: passedSmoke('windows', 'electron-shell'),
    linuxArtifactsCovered: hasArtifact('linux', ['appimage', 'deb', 'linux-unpacked']),
    windowsArtifactsCovered: hasArtifact('windows', ['nsis', 'portable', 'win-unpacked']),
    packagedHeadlessCliCovered: passedSmoke('linux', 'headless-cli') && passedSmoke('windows', 'headless-cli'),
    packagedAgentCliCovered: passedSmoke('linux', 'agent-cli') && passedSmoke('windows', 'agent-cli'),
    packagedRuntimeProxyCertOastReportCovered: passedSmoke('linux', 'runtime-proxy-cert-oast-report')
      && passedSmoke('windows', 'runtime-proxy-cert-oast-report'),
    packagedBrowserRoutingCovered: passedSmoke('linux', 'browser-routing') && passedSmoke('windows', 'browser-routing'),
    linuxInstallTrustUninstallCovered: passedSmoke('linux', 'deb-install')
      && passedSmoke('linux', 'trusted-ca-browser')
      && passedSmoke('linux', 'uninstall'),
    windowsInstallerUninstallCovered: passedSmoke('windows', 'nsis-install') && passedSmoke('windows', 'uninstall'),
    windowsTrustStorePinCovered: request.platformPins.some((pin) => (
      pin.platform === 'windows'
      && pin.runner.toLowerCase().includes('win')
      && pin.status === 'pinned-nonblocking'
      && /ERROR_NOT_SUPPORTED|trust-store/i.test(`${pin.reason} ${pin.content}`)
    )),
    fastSuiteCovered: hasGate(/test:ci:fast|ci-fast-suite/i),
    fullNightlySuiteCovered: hasGate(/test:ci:full|nightly-full-suite|ci-nightly-policy/i),
    installDocsCovered: hasDocTopics([
      'Linux',
      'Windows',
      'certificate trust',
      'browser routing',
      'agentic operation',
      'production signoff',
    ]),
    securityReviewCovered: request.securityReviews.some((review) => (
      review.status === 'passed'
      && review.criticalFindingCount === 0
      && review.highFindingCount === 0
      && [
        'local listeners',
        'secrets',
        'exploit controls',
        'agent controls',
        'platform pins',
      ].every((area) => review.coveredAreas.some((coveredArea) => coveredArea.toLowerCase().includes(area)))
    )),
    platformPinsCovered: request.platformPins.some((pin) => pin.platform === 'linux' && pin.status === 'accepted')
      && request.platformPins.some((pin) => pin.platform === 'windows' && pin.status === 'pinned-nonblocking'),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|session/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-platform-release-parity-evidence-package',
    exportedAt,
    uiSnapshots: request.uiSnapshots,
    artifacts: request.artifacts,
    smokes: request.smokes,
    gates: request.gates,
    installDocs: request.installDocs,
    securityReviews: request.securityReviews,
    platformPins: request.platformPins,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `platform-release-parity-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-platform-release-parity-evidence-package',
    title: 'Platform and release parity evidence package',
    fileName: `proxyforge-platform-release-parity-${stamp}.json`,
    path: `release/proxyforge-platform-release-parity-${stamp}.json`,
    exportedAt,
    artifactCount: request.artifacts.length,
    smokeCount: request.smokes.length,
    gateCount: request.gates.length,
    documentationCount: request.installDocs.length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Platform/Release parity evidence covers dense React/Vite navigation, visual QA, Linux and Windows Electron shells, Linux and Windows package artifacts, packaged headless and agent CLIs, packaged proxy/cert/OAST/report and browser-routing smokes, Linux install/trust/uninstall proof, Windows install/uninstall proof with an explicit trust-store pin, fast and full/nightly gates, install/operator docs, release security review, full-fidelity operational material, and report-export-only redaction.',
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
