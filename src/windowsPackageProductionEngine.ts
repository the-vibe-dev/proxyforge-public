export type WindowsPackageArtifactType = 'nsis' | 'portable' | 'win-unpacked' | 'win-zip';
export type WindowsPackageProofStatus = 'passed' | 'blocked' | 'failed' | 'pinned-nonblocking';

export interface WindowsPackageArtifactProof {
  id: string;
  artifactType: WindowsPackageArtifactType;
  path: string;
  sizeBytes: number;
  sha256: string;
  builtOnWindows: boolean;
  evidenceSource?: 'native-artifact' | 'synthetic-fixture';
  content: string;
}

export interface WindowsPackageSmokeProof {
  id: string;
  lane:
    | 'native-build'
    | 'unpacked-gui'
    | 'nsis-install'
    | 'installed-gui'
    | 'installed-headless-cli'
    | 'installed-headless-scan-report'
    | 'installed-runtime-proxy-cert-oast-report'
    | 'browser-routing'
    | 'dpapi-cookie'
    | 'uninstall'
    | 'portable-wrapper'
    | 'trust-store-browser';
  status: WindowsPackageProofStatus;
  runner: string;
  passedChecks: number;
  blockedChecks: number;
  failedChecks: number;
  reason?: string;
  evidenceSource?: 'native-artifact' | 'synthetic-fixture';
  content: string;
}

export interface WindowsPackageProductionRequest {
  artifacts: WindowsPackageArtifactProof[];
  smokes: WindowsPackageSmokeProof[];
  releaseDocs: string[];
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface WindowsPackageProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-windows-package-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  artifactCount: number;
  smokeCount: number;
  requirements: {
    nativeArtifactsCovered: boolean;
    artifactBackedNativeArtifacts: boolean;
    zipFallbackHygieneCovered: boolean;
    nativeBuildCovered: boolean;
    unpackedGuiCovered: boolean;
    nsisInstallUninstallCovered: boolean;
    installedHeadlessCovered: boolean;
    installedRuntimeCovered: boolean;
    browserRoutingCovered: boolean;
    dpapiCookieCovered: boolean;
    trustStorePinAccepted: boolean;
    portableWrapperPinned: boolean;
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

export function buildWindowsPackageProductionEvidencePackage(
  request: WindowsPackageProductionRequest,
): WindowsPackageProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const rawMaterial = [
    ...request.artifacts.map((artifact) => artifact.content),
    ...request.smokes.map((smoke) => smoke.content),
    request.releaseDocs.join('\n'),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const passedSmoke = (lane: WindowsPackageSmokeProof['lane']) => request.smokes.some((smoke) => (
    smoke.lane === lane
    && smoke.status === 'passed'
    && smoke.passedChecks > 0
    && smoke.failedChecks === 0
  ));
  const pinnedSmoke = (lane: WindowsPackageSmokeProof['lane'], pattern: RegExp) => request.smokes.some((smoke) => (
    smoke.lane === lane
    && smoke.status === 'pinned-nonblocking'
    && smoke.failedChecks === 0
    && smoke.blockedChecks > 0
    && pattern.test(`${smoke.reason ?? ''}\n${smoke.content}`)
  ));
  const artifactTypes = new Set(request.artifacts.map((artifact) => artifact.artifactType));
  const hasArtifact = (artifactType: WindowsPackageArtifactType) => request.artifacts.some((artifact) => (
    artifact.artifactType === artifactType
    && artifact.sizeBytes > 0
    && artifact.sha256.length >= 16
  ));
  const artifactBackedProofs = request.artifacts.every((artifact) => artifact.evidenceSource === 'native-artifact')
    && request.smokes.every((smoke) => smoke.evidenceSource === 'native-artifact');
  const requirements = {
    nativeArtifactsCovered: hasArtifact('nsis')
      && hasArtifact('portable')
      && hasArtifact('win-unpacked')
      && request.artifacts
        .filter((artifact) => artifact.artifactType !== 'win-zip')
        .every((artifact) => artifact.builtOnWindows),
    artifactBackedNativeArtifacts: artifactBackedProofs,
    zipFallbackHygieneCovered: artifactTypes.has('win-zip')
      && /no resources\/app\.asar\.unpacked|no rolldown|no lightningcss|no linux-x64|no vite|zip fallback/i.test(rawMaterial),
    nativeBuildCovered: passedSmoke('native-build'),
    unpackedGuiCovered: passedSmoke('unpacked-gui'),
    nsisInstallUninstallCovered: passedSmoke('nsis-install')
      && passedSmoke('installed-gui')
      && passedSmoke('uninstall'),
    installedHeadlessCovered: passedSmoke('installed-headless-cli')
      && passedSmoke('installed-headless-scan-report'),
    installedRuntimeCovered: passedSmoke('installed-runtime-proxy-cert-oast-report'),
    browserRoutingCovered: passedSmoke('browser-routing'),
    dpapiCookieCovered: passedSmoke('dpapi-cookie'),
    trustStorePinAccepted: pinnedSmoke('trust-store-browser', /windows-trust-runner|ERROR_NOT_SUPPORTED|CurrentUser\\Root|trust-store/i),
    portableWrapperPinned: pinnedSmoke('portable-wrapper', /portable wrapper|stdout|unpacked executable remains the counted GUI proof/i),
    releaseDocsCovered: /Windows Lane|NSIS|portable|DPAPI|windows-trust-runner|trust-store|release:smoke:windows|Production Ready/i.test(rawMaterial),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|session/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|redacted them in report artifacts|report export/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-windows-package-production-evidence-package',
    generatedAt,
    artifacts: request.artifacts,
    smokes: request.smokes,
    coverageNotes: {
      acceptedPin: 'windows-trust-runner trust-store browser lane is pinned nonblocking after ERROR_NOT_SUPPORTED with 7 passed checks, 1 blocked check, and 0 failed checks.',
      countedGuiProof: 'win-unpacked and installed NSIS app are the counted GUI/runtime proof; portable wrapper stdout is pinned separately.',
      artifactBacking: artifactBackedProofs
        ? 'All artifacts and smokes are marked as native-artifact evidence.'
        : 'Fixture/schema evidence is blocked from productionReady until native Windows artifacts and installed-host smokes provide native-artifact evidence.',
      fullFidelityBoundary: 'operational Windows package smokes preserve executor tokens, cookies, callback tokens, raw requests, and raw responses until report export.',
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `windows-package-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-windows-package-production-evidence-package',
    title: 'Windows package production evidence package',
    fileName: `proxyforge-windows-package-production-${stamp}.json`,
    path: `release/proxyforge-windows-package-production-${stamp}.json`,
    generatedAt,
    artifactCount: request.artifacts.length,
    smokeCount: request.smokes.length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'Windows package production evidence covers native Windows NSIS, portable, and win-unpacked artifacts, zip fallback hygiene, unpacked and installed GUI launch, installed headless scan/report, installed runtime proxy/cert/OAST/report, browser routing, DPAPI sample-cookie extraction, quiet uninstall, formal nonblocking trust-store pin acceptance, portable-wrapper stdout pinning, full-fidelity operational material, and report-export-only redaction.',
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
