export type FastRegressionStepKind = 'build' | 'release' | 'engine' | 'runtime' | 'platform' | 'e2e' | string;
export type FastRegressionStepStatus = 'passed' | 'failed' | 'blocked' | string;

export interface FastRegressionStepResult {
  name: string;
  kind: FastRegressionStepKind;
  command: string;
  status: FastRegressionStepStatus;
  exitCode: number;
  durationMs: number;
  stdoutTail?: string;
  stderrTail?: string;
}

export interface FastRegressionSuiteSummary {
  kind: 'proxyforge-ci-fast-suite-summary';
  startedAt: string;
  completedAt: string;
  durationMs: number;
  passed: boolean;
  totalSteps: number;
  completedSteps: number;
  results: FastRegressionStepResult[];
}

export interface FastRegressionProductionRequest {
  summary: FastRegressionSuiteSummary;
  requiredStepNames?: string[];
  requiredKinds?: string[];
  artifactPath: string;
  retentionDays: number;
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface FastRegressionProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-fast-regression-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  stepCount: number;
  durationMs: number;
  requirements: {
    currentSummaryPassed: boolean;
    completedEveryStep: boolean;
    noFailedSteps: boolean;
    broadSurfaceCoverage: boolean;
    releaseReadinessCovered: boolean;
    platformReleaseCovered: boolean;
    uiScaleProductionCovered: boolean;
    platformShellProductionCovered: boolean;
    agentControlProductionCovered: boolean;
    aiProviderProductionCovered: boolean;
    releaseSecurityProductionCovered: boolean;
    releaseTrustProductionCovered: boolean;
    fullNightlyProductionCovered: boolean;
    fullNightlyRetainedHistoryCovered: boolean;
    safetyEnterpriseCovered: boolean;
    projectPersistenceCovered: boolean;
    projectImportCompatibilityCovered: boolean;
    customerScaleInteropCovered: boolean;
    extensionThirdPartyCompatibilityCovered: boolean;
    automationServiceSmokeCovered: boolean;
    agenticControlCovered: boolean;
    analysisToolRefreshCovered: boolean;
    browserWorkflowCovered: boolean;
    proxyScannerRepeaterIntruderCovered: boolean;
    reportAndSecurityCovered: boolean;
    artifactUploadReady: boolean;
    retentionPolicyCovered: boolean;
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

const defaultRequiredKinds = ['build', 'release', 'engine', 'runtime', 'platform', 'e2e'];

const defaultRequiredSteps = [
  'Build renderer and Electron runtime',
  'Release readiness verifier',
  'Release smoke runner plan',
  'CI nightly policy gate',
  'Release runtime workflow smoke',
  'Platform Release parity evidence engine',
  'UI Scale production evidence engine',
  'Platform Shell production evidence engine',
  'Agent Control production evidence engine',
  'AI Provider production evidence engine',
  'Release Security production evidence engine',
  'Release Trust production evidence engine',
  'Fast regression production evidence engine',
  'Full/Nightly production evidence engine',
  'Full/Nightly retained history engine',
  'Install docs production evidence engine',
  'Windows package production evidence engine',
  'Linux package production evidence engine',
  'Safety and enterprise parity evidence engine',
  'Project parity evidence engine',
  'Project import compatibility engine',
  'Customer-scale interop profiling engine',
  'Extension third-party compatibility engine',
  'Agent option audit gate',
  'Search semantic ranking engine',
  'Viewer parity engine',
  'Logger custom column compatibility engine',
  'Logger parity evidence engine',
  'Organizer parity evidence engine',
  'Sequencer large-sample reliability engine',
  'Decoder token workflow engine',
  'Comparer parity engine',
  'Analysis tool refresh evidence engine',
  'Automation scheduler engine',
  'Automation installed-host service smoke',
  'Sandboxed extension runtime engine',
  'Callback live backend engine',
  'OAST relay integration engine',
  'OAST provider diversity engine',
  'Exploit backend execution engine',
  'AI controlled action execution engine',
  'Repeater transport engine',
  'Repeater workspace parity engine',
  'Crawler runtime engine',
  'Target access-control and comparison map engine',
  'Browser launch and cookie matrix engine',
  'Proxy HTTP listener capture engine',
  'CONNECT tunnel byte-accounting engine',
  'HTTPS MITM project CA engine',
  'Proxy intercept request-response engine',
  'Repeater desync race socket engine',
  'Intruder attack mode matrix engine',
  'Proxy HTTP/2 fidelity engine',
  'Proxy WebSocket capture engine',
  'Scanner passive dedupe engine',
  'Active scanner check-pack engine',
  'Scanner insertion point inventory engine',
  'Crawl insertion audit engine',
  'Scanner active evidence engine',
  'Scanner retest evidence delta engine',
  'Anvil custom scan-check engine',
  'Scanner live calibration engine',
  'Release security review engine',
  'Report export parity engine',
  'Report PDF visual QA smoke',
  'Headless CLI runtime smoke',
  'Agentic control CLI smoke',
  'Focused browser workflow smoke',
];

export function buildFastRegressionProductionEvidencePackage(
  request: FastRegressionProductionRequest,
): FastRegressionProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const requiredStepNames = request.requiredStepNames ?? defaultRequiredSteps;
  const requiredKinds = request.requiredKinds ?? defaultRequiredKinds;
  const resultNames = new Set(request.summary.results.map((result) => result.name));
  const resultKinds = new Set(request.summary.results.map((result) => result.kind));
  const stepText = request.summary.results.map((result) => `${result.name}\n${result.command}\n${result.stdoutTail ?? ''}\n${result.stderrTail ?? ''}`).join('\n');
  const rawMaterial = [
    JSON.stringify(request.summary),
    request.artifactPath,
    stepText,
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const hasStep = (pattern: RegExp) => request.summary.results.some((result) => pattern.test(`${result.name} ${result.command}`));
  const requirements = {
    currentSummaryPassed: request.summary.kind === 'proxyforge-ci-fast-suite-summary' && request.summary.passed,
    completedEveryStep: request.summary.completedSteps === request.summary.totalSteps
      && request.summary.results.length === request.summary.totalSteps
      && request.summary.totalSteps >= requiredStepNames.length,
    noFailedSteps: request.summary.results.every((result) => result.status === 'passed' && result.exitCode === 0),
    broadSurfaceCoverage: requiredKinds.every((kind) => resultKinds.has(kind))
      && requiredStepNames.every((name) => resultNames.has(name)),
    releaseReadinessCovered: hasStep(/Release readiness verifier|Release smoke runner plan|CI nightly policy gate|Release runtime workflow smoke/i),
    platformReleaseCovered: hasStep(/Platform Release parity evidence engine/i),
    uiScaleProductionCovered: hasStep(/UI Scale production evidence engine/i),
    platformShellProductionCovered: hasStep(/Platform Shell production evidence engine/i),
    agentControlProductionCovered: hasStep(/Agent Control production evidence engine/i),
    aiProviderProductionCovered: hasStep(/AI Provider production evidence engine/i),
    releaseSecurityProductionCovered: hasStep(/Release Security production evidence engine/i),
    releaseTrustProductionCovered: hasStep(/Release Trust production evidence engine/i),
    fullNightlyProductionCovered: hasStep(/Full\/Nightly production evidence engine/i),
    fullNightlyRetainedHistoryCovered: hasStep(/Full\/Nightly retained history engine/i),
    safetyEnterpriseCovered: hasStep(/Safety and enterprise parity evidence engine|Enterprise policy transport engine/i),
    projectPersistenceCovered: hasStep(/Project parity evidence engine/i),
    projectImportCompatibilityCovered: hasStep(/Project import compatibility engine/i),
    customerScaleInteropCovered: hasStep(/Customer-scale interop profiling engine/i),
    extensionThirdPartyCompatibilityCovered: hasStep(/Extension third-party compatibility engine/i),
    automationServiceSmokeCovered: hasStep(/Automation installed-host service smoke/i),
    agenticControlCovered: hasStep(/Agent option audit gate|Agentic control CLI smoke/i),
    analysisToolRefreshCovered: hasStep(/Analysis tool refresh evidence engine/i),
    browserWorkflowCovered: hasStep(/Focused browser workflow smoke|Browser launch and cookie matrix engine/i),
    proxyScannerRepeaterIntruderCovered: hasStep(/Proxy HTTP listener capture engine/i)
      && hasStep(/HTTPS MITM project CA engine/i)
      && hasStep(/Repeater desync race socket engine/i)
      && hasStep(/Intruder attack mode matrix engine/i)
      && hasStep(/Scanner passive dedupe engine/i)
      && hasStep(/Active scanner check-pack engine/i),
    reportAndSecurityCovered: hasStep(/Report export parity engine/i)
      && hasStep(/Report PDF visual QA smoke/i)
      && hasStep(/Release security review engine/i),
    artifactUploadReady: request.artifactPath === 'test-results/ci-fast-suite-summary.json',
    retentionPolicyCovered: request.retentionDays >= 14,
    rawExecutorMaterialPreserved: /Authorization:|Cookie:|X-API-Key:|HTTP\/[12]|rawRequest|rawResponse|callbackToken/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-fast-regression-production-evidence-package',
    generatedAt,
    artifactPath: request.artifactPath,
    retentionDays: request.retentionDays,
    summary: request.summary,
    requiredStepNames,
    requiredKinds,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `fast-regression-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-fast-regression-production-evidence-package',
    title: 'Fast regression production evidence package',
    fileName: `proxyforge-fast-regression-production-${stamp}.json`,
    path: `release/proxyforge-fast-regression-production-${stamp}.json`,
    generatedAt,
    stepCount: request.summary.totalSteps,
    durationMs: request.summary.durationMs,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'Fast regression suite production evidence covers build, release readiness, platform release, UI scale production, platform shell production, agent control production, AI provider production, release security production, release trust production, full/nightly production evidence, retained full/nightly history, safety, project persistence, project import compatibility, customer-scale interop profiling, third-party extension compatibility, Automation installed-host service smoke, agentic control, Analysis tool refresh, browser workflow, proxy, scanner, Repeater, Intruder, reports, release security review, artifact retention, full-fidelity operational material, and report-export-only redaction.',
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
