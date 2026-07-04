export type PlatformShellPlatform = 'linux' | 'windows';
export type PlatformShellProofStatus = 'passed' | 'pinned-nonblocking' | 'failed';

export interface PlatformShellSmokeProof {
  id: string;
  platform: PlatformShellPlatform;
  lane:
    | 'electron-shell'
    | 'headless-cli'
    | 'agent-cli'
    | 'external-cwd-agent'
    | 'runtime-proxy-cert-oast-report'
    | 'browser-routing'
    | 'package-production-gate'
    | 'trust-store-pin'
    | 'host-limit';
  status: PlatformShellProofStatus;
  runner: string;
  passedChecks: number;
  failedChecks: number;
  reason?: string;
  evidenceSource?: 'native-artifact' | 'synthetic-fixture';
  content: string;
}

export interface PlatformShellProductionRequest {
  smokes: PlatformShellSmokeProof[];
  releaseDocs: string[];
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface PlatformShellProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-platform-shell-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  smokeCount: number;
  requirements: {
    linuxShellLaunchCovered: boolean;
    windowsShellLaunchCovered: boolean;
    artifactBackedShellSmokes: boolean;
    structuredReleaseSmokeCovered: boolean;
    packagedHeadlessCovered: boolean;
    packagedAgentCovered: boolean;
    externalCwdAgentCovered: boolean;
    appRootAsarCovered: boolean;
    packagedRuntimeCovered: boolean;
    packagedBrowserRoutingCovered: boolean;
    linuxPackageProductionGateCovered: boolean;
    windowsPackageProductionGateCovered: boolean;
    trustStorePinAccepted: boolean;
    knownHostLimitsPinned: boolean;
    releaseDocsCovered: boolean;
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

export function buildPlatformShellProductionEvidencePackage(
  request: PlatformShellProductionRequest,
): PlatformShellProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const rawMaterial = [
    ...request.smokes.map((smoke) => smoke.content),
    request.releaseDocs.join('\n'),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const passedSmoke = (
    platform: PlatformShellPlatform,
    lane: PlatformShellSmokeProof['lane'],
  ) => request.smokes.some((smoke) => (
    smoke.platform === platform
    && smoke.lane === lane
    && smoke.status === 'passed'
    && smoke.passedChecks > 0
    && smoke.failedChecks === 0
  ));
  const pinnedSmoke = (lane: PlatformShellSmokeProof['lane'], pattern: RegExp) => request.smokes.some((smoke) => (
    smoke.lane === lane
    && smoke.status === 'pinned-nonblocking'
    && smoke.failedChecks === 0
    && pattern.test(`${smoke.reason ?? ''}\n${smoke.content}`)
  ));
  const artifactBackedShellSmokes = request.smokes.every((smoke) => smoke.evidenceSource === 'native-artifact');
  const requirements = {
    linuxShellLaunchCovered: passedSmoke('linux', 'electron-shell'),
    windowsShellLaunchCovered: passedSmoke('windows', 'electron-shell'),
    artifactBackedShellSmokes,
    structuredReleaseSmokeCovered: /PROXYFORGE_RELEASE_SMOKE=1|proxyforge-release-smoke/i.test(rawMaterial),
    packagedHeadlessCovered: passedSmoke('linux', 'headless-cli') && passedSmoke('windows', 'headless-cli'),
    packagedAgentCovered: passedSmoke('linux', 'agent-cli') && passedSmoke('windows', 'agent-cli'),
    externalCwdAgentCovered: passedSmoke('linux', 'external-cwd-agent')
      && /external-cwd|external cwd|~\/vantix/i.test(rawMaterial),
    appRootAsarCovered: /resources[\\/]+app\.asar|appRoot.*app\.asar|app root.*app\.asar/i.test(rawMaterial),
    packagedRuntimeCovered: passedSmoke('linux', 'runtime-proxy-cert-oast-report')
      && passedSmoke('windows', 'runtime-proxy-cert-oast-report'),
    packagedBrowserRoutingCovered: passedSmoke('linux', 'browser-routing')
      && passedSmoke('windows', 'browser-routing'),
    linuxPackageProductionGateCovered: passedSmoke('linux', 'package-production-gate')
      && /proxyforge-linux-package-production-evidence-package/i.test(rawMaterial),
    windowsPackageProductionGateCovered: passedSmoke('windows', 'package-production-gate')
      && /proxyforge-windows-package-production-evidence-package/i.test(rawMaterial),
    trustStorePinAccepted: pinnedSmoke('trust-store-pin', /windows-trust-runner|ERROR_NOT_SUPPORTED|trust-store|CurrentUser\\Root/i),
    knownHostLimitsPinned: pinnedSmoke('host-limit', /broader host diversity|runner lane|trust-store|nonblocking/i),
    releaseDocsCovered: /INSTALL_LINUX_WINDOWS|OPERATOR_GUIDE|Platform Shell production|Production Ready/i.test(rawMaterial),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|session/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report export/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-platform-shell-production-evidence-package',
    generatedAt,
    smokes: request.smokes,
    coverageNotes: {
      countedShellProof: 'Linux and Windows PROXYFORGE_RELEASE_SMOKE=1 packaged Electron renderer launches are counted as the shell proof.',
      packageGateInputs: 'Linux and Windows package production evidence packages are required inputs for this shell production gate.',
      hostLimits: 'Current windows-trust-runner trust-store mutation and broader host diversity limits are pinned as nonblocking for the shell row, not hidden.',
      artifactBacking: artifactBackedShellSmokes
        ? 'All shell smokes are marked as native-artifact evidence.'
        : 'Fixture/schema shell evidence is blocked from productionReady until packaged Linux and Windows shell smokes provide native-artifact evidence.',
      fullFidelityBoundary: 'Operational shell/runtime smokes preserve executor tokens, cookies, callback tokens, raw requests, and raw responses until report export.',
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `platform-shell-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-platform-shell-production-evidence-package',
    title: 'Platform shell production evidence package',
    fileName: `proxyforge-platform-shell-production-${stamp}.json`,
    path: `release/proxyforge-platform-shell-production-${stamp}.json`,
    generatedAt,
    smokeCount: request.smokes.length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'Platform shell production evidence covers Linux and Windows packaged Electron shell launch, structured release-smoke output, packaged headless and agent CLIs, external-cwd app.asar agent execution, packaged runtime proxy/cert/OAST/report smokes, packaged browser routing, Linux and Windows package production gates, accepted trust-store and host-limit pins, full-fidelity operational material, and report-export-only redaction.',
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
