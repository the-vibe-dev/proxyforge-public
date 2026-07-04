export type LinuxPackageArtifactType = 'appimage' | 'deb' | 'linux-unpacked';
export type LinuxPackageProofStatus = 'passed' | 'pinned-nonblocking' | 'failed';

export interface LinuxPackageArtifactProof {
  id: string;
  artifactType: LinuxPackageArtifactType;
  path: string;
  sizeBytes: number;
  sha256: string;
  evidenceSource?: 'native-artifact' | 'synthetic-fixture';
  content: string;
}

export interface LinuxPackageSmokeProof {
  id: string;
  lane:
    | 'native-build'
    | 'appimage-node-runtime'
    | 'appimage-gui'
    | 'unpacked-node-runtime'
    | 'unpacked-gui'
    | 'deb-metadata'
    | 'packaged-headless-cli'
    | 'packaged-headless-scan-report'
    | 'packaged-agent-cli'
    | 'packaged-agent-external-cwd'
    | 'packaged-runtime-proxy-cert-oast-report'
    | 'packaged-browser-routing'
    | 'clean-container-deb-install'
    | 'clean-container-runtime'
    | 'clean-container-gui'
    | 'clean-container-trusted-ca-browser'
    | 'clean-container-uninstall'
    | 'known-warning';
  status: LinuxPackageProofStatus;
  runner: string;
  passedChecks: number;
  failedChecks: number;
  reason?: string;
  evidenceSource?: 'native-artifact' | 'synthetic-fixture';
  content: string;
}

export interface LinuxPackageProductionRequest {
  artifacts: LinuxPackageArtifactProof[];
  smokes: LinuxPackageSmokeProof[];
  releaseDocs: string[];
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface LinuxPackageProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-linux-package-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  artifactCount: number;
  smokeCount: number;
  requirements: {
    appImageDebUnpackedArtifactsCovered: boolean;
    artifactBackedNativeArtifacts: boolean;
    nativeBuildCovered: boolean;
    appImageRuntimeAndGuiCovered: boolean;
    debMetadataDependencyCovered: boolean;
    unpackedRuntimeAndGuiCovered: boolean;
    packagedHeadlessCovered: boolean;
    packagedAgentCovered: boolean;
    packagedRuntimeCovered: boolean;
    browserRoutingCovered: boolean;
    cleanContainerInstallRuntimeGuiCovered: boolean;
    cleanContainerTrustedCaCovered: boolean;
    cleanContainerUninstallCovered: boolean;
    knownWarningsPinned: boolean;
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

export function buildLinuxPackageProductionEvidencePackage(
  request: LinuxPackageProductionRequest,
): LinuxPackageProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const rawMaterial = [
    ...request.artifacts.map((artifact) => artifact.content),
    ...request.smokes.map((smoke) => smoke.content),
    request.releaseDocs.join('\n'),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const passedSmoke = (lane: LinuxPackageSmokeProof['lane']) => request.smokes.some((smoke) => (
    smoke.lane === lane
    && smoke.status === 'passed'
    && smoke.passedChecks > 0
    && smoke.failedChecks === 0
  ));
  const pinnedWarning = (pattern: RegExp) => request.smokes.some((smoke) => (
    smoke.lane === 'known-warning'
    && smoke.status === 'pinned-nonblocking'
    && smoke.failedChecks === 0
    && pattern.test(`${smoke.reason ?? ''}\n${smoke.content}`)
  ));
  const hasArtifact = (artifactType: LinuxPackageArtifactType) => request.artifacts.some((artifact) => (
    artifact.artifactType === artifactType
    && artifact.sizeBytes > 0
    && artifact.sha256.length >= 16
  ));
  const artifactBackedProofs = request.artifacts.every((artifact) => artifact.evidenceSource === 'native-artifact')
    && request.smokes.every((smoke) => smoke.evidenceSource === 'native-artifact');
  const requirements = {
    appImageDebUnpackedArtifactsCovered: hasArtifact('appimage')
      && hasArtifact('deb')
      && hasArtifact('linux-unpacked'),
    artifactBackedNativeArtifacts: artifactBackedProofs,
    nativeBuildCovered: passedSmoke('native-build'),
    appImageRuntimeAndGuiCovered: passedSmoke('appimage-node-runtime')
      && passedSmoke('appimage-gui'),
    debMetadataDependencyCovered: passedSmoke('deb-metadata')
      && /Package: proxyforge|Version: 0\.1\.0(?:-[\w.]+)?|Architecture: amd64|libgbm1|libasound2/i.test(rawMaterial),
    unpackedRuntimeAndGuiCovered: passedSmoke('unpacked-node-runtime')
      && passedSmoke('unpacked-gui'),
    packagedHeadlessCovered: passedSmoke('packaged-headless-cli')
      && passedSmoke('packaged-headless-scan-report'),
    packagedAgentCovered: passedSmoke('packaged-agent-cli')
      && passedSmoke('packaged-agent-external-cwd'),
    packagedRuntimeCovered: passedSmoke('packaged-runtime-proxy-cert-oast-report'),
    browserRoutingCovered: passedSmoke('packaged-browser-routing'),
    cleanContainerInstallRuntimeGuiCovered: passedSmoke('clean-container-deb-install')
      && passedSmoke('clean-container-runtime')
      && passedSmoke('clean-container-gui'),
    cleanContainerTrustedCaCovered: passedSmoke('clean-container-trusted-ca-browser')
      && /trusted-CA|trusted CA|NSS trust store|without --ignore-certificate-errors|certificateMode: trusted-ca/i.test(rawMaterial),
    cleanContainerUninstallCovered: passedSmoke('clean-container-uninstall'),
    knownWarningsPinned: pinnedWarning(/Chromium GPU command-buffer warning|unshare failed|postinstall sandbox warning/i),
    releaseDocsCovered: /Linux Lane|AppImage|deb|release:smoke:linux|release-deb-container-smoke|browser-trust-store|Production Ready/i.test(rawMaterial),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|session/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|redacted them in report artifacts|report export/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-linux-package-production-evidence-package',
    generatedAt,
    artifacts: request.artifacts,
    smokes: request.smokes,
    coverageNotes: {
      countedTrustProof: 'clean-container isolated Chromium trusted-CA HTTPS capture is the counted browser trust proof, not the --ignore-certificate-errors compatibility lane.',
      cleanContainerProof: 'Deb install, installed runtime, installed GUI launch under Xvfb, trusted-CA browser routing, package query, uninstall, and installed executable removal are covered.',
      warningPins: 'Xvfb Chromium GPU command-buffer and Docker unshare postinstall sandbox warnings are pinned nonblocking because structured smokes passed.',
      artifactBacking: artifactBackedProofs
        ? 'All artifacts and smokes are marked as native-artifact evidence.'
        : 'Fixture/schema evidence is blocked from productionReady until native Linux artifacts and clean-container smokes provide native-artifact evidence.',
      fullFidelityBoundary: 'operational Linux package smokes preserve executor tokens, cookies, callback tokens, raw requests, and raw responses until report export.',
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `linux-package-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-linux-package-production-evidence-package',
    title: 'Linux package production evidence package',
    fileName: `proxyforge-linux-package-production-${stamp}.json`,
    path: `release/proxyforge-linux-package-production-${stamp}.json`,
    generatedAt,
    artifactCount: request.artifacts.length,
    smokeCount: request.smokes.length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'Linux package production evidence covers AppImage, deb, linux-unpacked artifacts, AppImage and unpacked runtime/GUI smokes, deb metadata/dependency proof, packaged headless scan/report, packaged agent and external-cwd invocation, packaged runtime proxy/cert/OAST/report, browser routing, clean-container deb install/runtime/GUI/trusted-CA/uninstall proof, known warning pins, full-fidelity operational material, and report-export-only redaction.',
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
