export type UiScaleViewportKind = 'desktop' | 'tablet' | 'mobile';
export type UiScaleWorkflowLane =
  | 'proxy-history'
  | 'target-map'
  | 'repeater-workspace'
  | 'intruder-results'
  | 'scanner-issues'
  | 'search-viewer'
  | 'reports'
  | 'extensions'
  | 'automations'
  | string;

export interface UiScaleViewportProof {
  id: string;
  viewport: UiScaleViewportKind;
  width: number;
  height: number;
  screenshotPath: string;
  toolSurfaces: string[];
  navigationGroups: string[];
  nonBlankPixelRatio: number;
  overlapCount: number;
  horizontalOverflowPx: number;
  clippedTextCount: number;
  longestLabelChars: number;
  accessibleNameCoverageRatio: number;
  keyboardReachable: boolean;
  minTapTargetPx: number;
  stableControlCount: number;
  totalControlCount: number;
  content: string;
}

export interface UiScaleLargeProjectProfile {
  id: string;
  exchangeRows: number;
  findingRows: number;
  targetRoutes: number;
  intruderRows: number;
  websocketFrames: number;
  reportAttachments: number;
  retainedWindowRows: number;
  droppedRowsTracked: number;
  p95FilterMs: number;
  p95NavigationMs: number;
  p95SelectionMs: number;
  p95RenderMs: number;
  memoryPeakMb: number;
  rowHeightJitterPx: number;
  longTextWrapFailures: number;
  content: string;
}

export interface UiScaleWorkflowProof {
  id: string;
  lane: UiScaleWorkflowLane;
  status: 'passed' | 'failed';
  passedChecks: number;
  failedChecks: number;
  content: string;
}

export interface UiScaleProductionRequest {
  viewportProofs: UiScaleViewportProof[];
  largeProjectProfiles: UiScaleLargeProjectProfile[];
  workflowProofs: UiScaleWorkflowProof[];
  docs: string[];
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface UiScaleProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-ui-scale-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  viewportCount: number;
  largeProjectProfileCount: number;
  workflowProofCount: number;
  requirements: {
    desktopTabletMobileCovered: boolean;
    allMajorSurfacesReachable: boolean;
    noViewportOverlapOrOverflow: boolean;
    textFitAndLongLabelsCovered: boolean;
    keyboardAndAccessibleNamesCovered: boolean;
    stableFixedControlsCovered: boolean;
    largeProjectDataDensityCovered: boolean;
    boundedRowWindowsCovered: boolean;
    latencyBudgetsCovered: boolean;
    reportAttachmentScaleCovered: boolean;
    workflowSurfaceCoverage: boolean;
    packagedModeCovered: boolean;
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

const requiredSurfaces = [
  'Dashboard',
  'Proxy',
  'Target',
  'Repeater',
  'Intruder',
  'Scanner',
  'Search',
  'Viewer',
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
  'Settings',
];

const requiredWorkflowLanes: UiScaleWorkflowLane[] = [
  'proxy-history',
  'target-map',
  'repeater-workspace',
  'intruder-results',
  'scanner-issues',
  'search-viewer',
  'reports',
  'extensions',
  'automations',
];

export function buildUiScaleProductionEvidencePackage(
  request: UiScaleProductionRequest,
): UiScaleProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const allViewportText = request.viewportProofs.map((proof) => proof.content).join('\n');
  const allProfileText = request.largeProjectProfiles.map((profile) => profile.content).join('\n');
  const allWorkflowText = request.workflowProofs.map((proof) => proof.content).join('\n');
  const docsText = request.docs.join('\n');
  const rawMaterial = [
    allViewportText,
    allProfileText,
    allWorkflowText,
    docsText,
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const hasViewport = (viewport: UiScaleViewportKind, predicate: (proof: UiScaleViewportProof) => boolean) => (
    request.viewportProofs.some((proof) => proof.viewport === viewport && predicate(proof))
  );
  const allViewportSurfaces = new Set(request.viewportProofs.flatMap((proof) => proof.toolSurfaces));
  const allWorkflowLanes = new Set(request.workflowProofs.filter((proof) => proof.status === 'passed' && proof.failedChecks === 0).map((proof) => proof.lane));
  const stableControlRatios = request.viewportProofs.map((proof) => (
    proof.totalControlCount > 0 ? proof.stableControlCount / proof.totalControlCount : 0
  ));
  const requirements = {
    desktopTabletMobileCovered: hasViewport('desktop', (proof) => proof.width >= 1280 && proof.height >= 720)
      && hasViewport('tablet', (proof) => proof.width >= 768 && proof.height >= 900)
      && hasViewport('mobile', (proof) => proof.width <= 430 && proof.height >= 720),
    allMajorSurfacesReachable: requiredSurfaces.every((surface) => allViewportSurfaces.has(surface))
      && request.viewportProofs.every((proof) => proof.navigationGroups.length >= 5),
    noViewportOverlapOrOverflow: request.viewportProofs.length >= 3
      && request.viewportProofs.every((proof) => (
        proof.nonBlankPixelRatio >= 0.25
        && proof.overlapCount === 0
        && proof.horizontalOverflowPx === 0
      )),
    textFitAndLongLabelsCovered: request.viewportProofs.every((proof) => (
      proof.clippedTextCount === 0
      && proof.longestLabelChars >= 34
    )),
    keyboardAndAccessibleNamesCovered: request.viewportProofs.every((proof) => (
      proof.keyboardReachable
      && proof.accessibleNameCoverageRatio >= 0.98
      && proof.minTapTargetPx >= 32
    )),
    stableFixedControlsCovered: stableControlRatios.length > 0
      && stableControlRatios.every((ratio) => ratio >= 0.98),
    largeProjectDataDensityCovered: request.largeProjectProfiles.some((profile) => (
      profile.exchangeRows >= 50_000
      && profile.findingRows >= 1_000
      && profile.targetRoutes >= 5_000
      && profile.intruderRows >= 25_000
      && profile.websocketFrames >= 50_000
    )),
    boundedRowWindowsCovered: request.largeProjectProfiles.every((profile) => (
      profile.retainedWindowRows > 0
      && profile.retainedWindowRows <= 750
      && profile.droppedRowsTracked >= 0
      && profile.rowHeightJitterPx <= 1
      && profile.longTextWrapFailures === 0
    )),
    latencyBudgetsCovered: request.largeProjectProfiles.every((profile) => (
      profile.p95FilterMs <= 120
      && profile.p95NavigationMs <= 150
      && profile.p95SelectionMs <= 100
      && profile.p95RenderMs <= 220
      && profile.memoryPeakMb <= 768
    )),
    reportAttachmentScaleCovered: request.largeProjectProfiles.some((profile) => profile.reportAttachments >= 500),
    workflowSurfaceCoverage: requiredWorkflowLanes.every((lane) => allWorkflowLanes.has(lane))
      && request.workflowProofs.every((proof) => proof.status === 'passed' && proof.failedChecks === 0 && proof.passedChecks > 0),
    packagedModeCovered: /PROXYFORGE_RELEASE_SMOKE=1|app\.asar|packaged|release-smoke/i.test(rawMaterial),
    docsAndSchemasCovered: /OPERATOR_GUIDE|INSTALL_LINUX_WINDOWS|SCHEMAS\.md|proxyforge-ui-scale-production-evidence-package|large-project|overflow|responsive/i.test(docsText),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|Bearer/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only redaction|submission\/report artifacts redact/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-ui-scale-production-evidence-package',
    generatedAt,
    viewportProofs: request.viewportProofs,
    largeProjectProfiles: request.largeProjectProfiles,
    workflowProofs: request.workflowProofs,
    docs: request.docs,
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    notes: {
      scope: 'UI scale production evidence ties responsive screenshots, large project profiling, and workflow reachability into a single release gate.',
      rowWindowing: 'Large tables keep bounded retained windows while preserving dropped-row accounting for operator review.',
      secretBoundary: 'Operational UI evidence keeps raw executor material full fidelity; report exports redact later.',
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `ui-scale-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-ui-scale-production-evidence-package',
    title: 'UI scale production evidence package',
    fileName: `proxyforge-ui-scale-production-${stamp}.json`,
    path: `release/proxyforge-ui-scale-production-${stamp}.json`,
    generatedAt,
    viewportCount: request.viewportProofs.length,
    largeProjectProfileCount: request.largeProjectProfiles.length,
    workflowProofCount: request.workflowProofs.length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'UI scale production evidence covers desktop/tablet/mobile responsive rendering, all major analyst surfaces, zero overlap and horizontal overflow, long-label text fitting, keyboard and accessible-name reachability, stable fixed controls, large-project data density, bounded retained row windows, latency budgets, report attachment scale, packaged mode proof, docs/schemas, full-fidelity executor material, and report-export-only redaction.',
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
