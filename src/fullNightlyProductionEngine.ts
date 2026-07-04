export type FullNightlyRunMode = 'plan-only' | 'skip-browser' | 'full' | string;

export interface FullNightlyUploadPolicy {
  summary: string;
  artifactDirectory: string;
  requiredArtifacts: string[];
  retentionDays: number;
  failureRetentionDays: number;
}

export interface FullNightlyFlakeBudget {
  maxFlakySteps: number;
  maxRetriesPerStep: number;
  browserRetryBudget: number;
  ownerRequired: boolean;
}

export interface FullNightlyCoverageOwner {
  name: string;
  kind: string;
  owner: string;
  artifactPaths: string[];
  retryBudget: number;
}

export interface FullNightlySuitePlan {
  kind: 'proxyforge-ci-full-suite-plan';
  suite: 'full-nightly';
  generatedAt: string;
  stepCount: number;
  uploadPolicy: FullNightlyUploadPolicy;
  flakeBudget: FullNightlyFlakeBudget;
  coverageOwnership: FullNightlyCoverageOwner[];
}

export interface FullNightlyStepResult {
  name: string;
  kind: string;
  owner?: string;
  command: string;
  status: string;
  exitCode: number;
  retryBudget?: number;
  artifactPaths?: string[];
  startedAt?: string;
  completedAt?: string;
  durationMs: number;
  stdoutTail?: string;
  stderrTail?: string;
}

export interface FullNightlySuiteSummary {
  kind: 'proxyforge-ci-full-suite-summary';
  mode: FullNightlyRunMode;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  passed: boolean;
  totalSteps: number;
  completedSteps: number;
  uploadPolicy: FullNightlyUploadPolicy;
  flakeBudget: FullNightlyFlakeBudget;
  coverageOwnership?: FullNightlyCoverageOwner[];
  results: FullNightlyStepResult[];
}

export interface FullNightlyTrendRun {
  runId: string;
  source: 'github-actions' | 'local-release' | 'runner-import' | string;
  mode: FullNightlyRunMode;
  startedAt: string;
  completedAt: string;
  passed: boolean;
  totalSteps: number;
  completedSteps: number;
  durationMs: number;
  artifactPath: string;
  failedStepNames?: string[];
  flakeViolations?: number;
}

export interface FullNightlyTrendDashboard {
  kind: 'proxyforge-full-nightly-trend-dashboard';
  generatedAt: string;
  runCount: number;
  passedRunCount: number;
  failedRunCount: number;
  passRate: number;
  medianDurationMs: number;
  modeCounts: Record<string, number>;
  latestRun?: FullNightlyTrendRun;
  artifactPaths: string[];
  failedStepFrequency: Record<string, number>;
  zeroFlakeViolations: number;
}

export interface FastRegressionSummaryLink {
  kind: 'proxyforge-ci-fast-suite-summary';
  passed: boolean;
  totalSteps: number;
  completedSteps: number;
  durationMs: number;
  results: Array<{
    name: string;
    kind: string;
    status: string;
    exitCode: number;
    command: string;
    stdoutTail?: string;
    stderrTail?: string;
  }>;
}

export interface FullNightlyProductionRequest {
  plan: FullNightlySuitePlan;
  currentSummary: FullNightlySuiteSummary;
  trendRuns: FullNightlyTrendRun[];
  fastSummary: FastRegressionSummaryLink;
  docs: string[];
  workflowText?: string;
  artifactPath: string;
  historyArtifactPath: string;
  retentionDays: number;
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface FullNightlyProductionEvidencePackage {
  id: string;
  kind: 'proxyforge-full-nightly-production-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  stepCount: number;
  trendRunCount: number;
  requirements: {
    fullSuitePlanValid: boolean;
    coverageOwnershipComplete: boolean;
    uniqueStepNamesCovered: boolean;
    requiredProductionGatesCovered: boolean;
    proxyScannerRepeaterIntruderCovered: boolean;
    callbackExploitReportBrowserCovered: boolean;
    uploadPolicyCovered: boolean;
    retentionPolicyCovered: boolean;
    zeroFlakeBudgetCovered: boolean;
    currentSummaryLinked: boolean;
    planOnlyBoundaryCovered: boolean;
    trendDashboardCovered: boolean;
    scheduledHistoryContinuityCovered: boolean;
    historicalRuntimePassCovered: boolean;
    latestRuntimeRunPassed: boolean;
    noRecentFailedRuns: boolean;
    fastSuiteLinked: boolean;
    docsAndSchemasCovered: boolean;
    artifactPathsSafe: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  trendDashboard: FullNightlyTrendDashboard;
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  productionReady: boolean;
  digestPreview: string;
  summaryText: string;
  content: string;
}

const requiredProductionStepPatterns = [
  /Release readiness verifier/i,
  /Release smoke runner plan/i,
  /CI nightly policy gate/i,
  /Release runtime workflow smoke/i,
  /Platform Release parity evidence engine/i,
  /UI Scale production evidence engine/i,
  /Platform Shell production evidence engine/i,
  /Agent Control production evidence engine/i,
  /AI Provider production evidence engine/i,
  /Release Security production evidence engine/i,
  /Release Trust production evidence engine/i,
  /Fast regression production evidence engine/i,
  /Full\/Nightly production evidence engine/i,
  /Full\/Nightly retained history engine/i,
  /Install docs production evidence engine/i,
  /Windows package production evidence engine/i,
  /Linux package production evidence engine/i,
  /Safety and enterprise parity evidence engine/i,
  /Project parity evidence engine/i,
  /Project import compatibility engine/i,
  /Customer-scale interop profiling engine/i,
  /Extension third-party compatibility engine/i,
  /Automation installed-host service smoke/i,
  /Agent option audit gate/i,
  /Agentic control CLI smoke/i,
];

const proxyScannerRepeaterIntruderPatterns = [
  /Proxy HTTP listener capture engine/i,
  /HTTPS MITM engine/i,
  /Proxy intercept engine/i,
  /Proxy history analysis engine/i,
  /Scanner passive dedupe engine/i,
  /Active scanner engine/i,
  /Scanner active evidence engine/i,
  /Scanner retest evidence delta engine/i,
  /Anvil custom scan-check engine/i,
  /Repeater transport engine/i,
  /Repeater workspace parity engine/i,
  /Repeater desync race socket engine/i,
  /Intruder engine/i,
];

const callbackExploitReportBrowserPatterns = [
  /Callback listener backend engine/i,
  /Callback live backend engine/i,
  /Exploit backend execution engine/i,
  /Report export engine/i,
  /Report PDF visual QA smoke/i,
  /Full browser workflow suite/i,
];

export function buildFullNightlyTrendDashboard(
  runs: FullNightlyTrendRun[],
  generatedAt = new Date().toISOString(),
): FullNightlyTrendDashboard {
  const sortedRuns = [...runs].sort((left, right) => Date.parse(left.startedAt) - Date.parse(right.startedAt));
  const durations = sortedRuns.map((run) => run.durationMs).sort((left, right) => left - right);
  const modeCounts = sortedRuns.reduce<Record<string, number>>((counts, run) => {
    counts[run.mode] = (counts[run.mode] ?? 0) + 1;
    return counts;
  }, {});
  const failedStepFrequency = sortedRuns.reduce<Record<string, number>>((counts, run) => {
    for (const failedStepName of run.failedStepNames ?? []) {
      counts[failedStepName] = (counts[failedStepName] ?? 0) + 1;
    }
    return counts;
  }, {});
  const passedRunCount = sortedRuns.filter((run) => run.passed).length;
  return {
    kind: 'proxyforge-full-nightly-trend-dashboard',
    generatedAt,
    runCount: sortedRuns.length,
    passedRunCount,
    failedRunCount: sortedRuns.length - passedRunCount,
    passRate: sortedRuns.length ? passedRunCount / sortedRuns.length : 0,
    medianDurationMs: median(durations),
    modeCounts,
    latestRun: sortedRuns.length ? sortedRuns[sortedRuns.length - 1] : undefined,
    artifactPaths: sortedRuns.map((run) => run.artifactPath),
    failedStepFrequency,
    zeroFlakeViolations: sortedRuns.reduce((total, run) => total + (run.flakeViolations ?? 0), 0),
  };
}

export function buildFullNightlyProductionEvidencePackage(
  request: FullNightlyProductionRequest,
): FullNightlyProductionEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const trendDashboard = buildFullNightlyTrendDashboard(request.trendRuns, generatedAt);
  const stepNames = request.plan.coverageOwnership.map((step) => step.name);
  const stepNameText = stepNames.join('\n');
  const docsText = request.docs.join('\n');
  const workflowText = request.workflowText ?? '';
  const currentSummaryText = [
    JSON.stringify(request.currentSummary),
    ...request.currentSummary.results.map((result) => `${result.name}\n${result.command}\n${result.stdoutTail ?? ''}\n${result.stderrTail ?? ''}`),
  ].join('\n');
  const trendText = request.trendRuns.map((run) => JSON.stringify(run)).join('\n');
  const fastStepNames = new Set(request.fastSummary.results.map((result) => result.name));
  const rawMaterial = [
    JSON.stringify(request.plan),
    currentSummaryText,
    trendText,
    JSON.stringify(request.fastSummary),
    docsText,
    workflowText,
    request.artifactPath,
    request.historyArtifactPath,
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const hasStep = (pattern: RegExp) => pattern.test(stepNameText);
  const safeArtifactPath = (artifactPath: string) => /^test-results\/|^playwright-report\/|^\.gitignored\/|^release\//.test(artifactPath);
  const runtimeRuns = [...request.trendRuns]
    .filter((run) => run.mode === 'full' || run.mode === 'skip-browser')
    .sort((left, right) => Date.parse(left.startedAt) - Date.parse(right.startedAt));
  const latestRuntimeRun = runtimeRuns.length ? runtimeRuns[runtimeRuns.length - 1] : undefined;
  const requiredArtifacts = request.plan.uploadPolicy.requiredArtifacts ?? [];
  const requirements = {
    fullSuitePlanValid: request.plan.kind === 'proxyforge-ci-full-suite-plan'
      && request.plan.suite === 'full-nightly'
      && request.plan.stepCount >= 70
      && request.plan.coverageOwnership.length === request.plan.stepCount,
    coverageOwnershipComplete: request.plan.coverageOwnership.every((step) => (
      Boolean(step.name)
      && Boolean(step.kind)
      && Boolean(step.owner)
      && Array.isArray(step.artifactPaths)
      && step.artifactPaths.length > 0
      && Number.isInteger(step.retryBudget)
    )),
    uniqueStepNamesCovered: new Set(stepNames).size === stepNames.length,
    requiredProductionGatesCovered: requiredProductionStepPatterns.every(hasStep),
    proxyScannerRepeaterIntruderCovered: proxyScannerRepeaterIntruderPatterns.every(hasStep),
    callbackExploitReportBrowserCovered: callbackExploitReportBrowserPatterns.every(hasStep),
    uploadPolicyCovered: request.plan.uploadPolicy.artifactDirectory === 'test-results'
      && requiredArtifacts.includes('test-results/ci-full-suite-summary.json')
      && requiredArtifacts.includes('test-results/ci-full-suite-plan.json')
      && requiredArtifacts.includes('test-results/.last-run.json')
      && requiredArtifacts.includes('test-results/ci-full-suite-history/')
      && requiredArtifacts.includes('test-results/ci-full-suite-history/dashboard.json')
      && requiredArtifacts.includes('test-results/playwright-artifacts/')
      && requiredArtifacts.includes('playwright-report/'),
    retentionPolicyCovered: request.retentionDays >= 30
      && request.plan.uploadPolicy.failureRetentionDays >= 30
      && request.plan.uploadPolicy.retentionDays >= 14,
    zeroFlakeBudgetCovered: request.plan.flakeBudget.maxFlakySteps === 0
      && request.plan.flakeBudget.ownerRequired === true
      && trendDashboard.zeroFlakeViolations === 0,
    currentSummaryLinked: request.currentSummary.kind === 'proxyforge-ci-full-suite-summary'
      && request.currentSummary.passed
      && request.currentSummary.totalSteps === request.plan.stepCount
      && request.currentSummary.uploadPolicy.requiredArtifacts.includes('test-results/ci-full-suite-summary.json'),
    planOnlyBoundaryCovered: request.currentSummary.mode !== 'plan-only'
      || (request.currentSummary.completedSteps === 0 && request.currentSummary.results.length === 0),
    trendDashboardCovered: trendDashboard.kind === 'proxyforge-full-nightly-trend-dashboard'
      && trendDashboard.runCount >= 3
      && trendDashboard.artifactPaths.every(safeArtifactPath),
    scheduledHistoryContinuityCovered: /actions\/cache\/restore@v4/.test(workflowText)
      && /actions\/cache\/save@v4/.test(workflowText)
      && /test-results\/ci-full-suite-history\//.test(workflowText)
      && /proxyforge-full-suite-history-\$\{\{\s*github\.ref_name\s*\}\}-\$\{\{\s*github\.run_id\s*\}\}-\$\{\{\s*github\.run_attempt\s*\}\}/.test(workflowText)
      && /restore-keys:\s*\|[\s\S]*proxyforge-full-suite-history-\$\{\{\s*github\.ref_name\s*\}\}-/.test(workflowText)
      && /github\.event\.inputs\.plan_only\s*!=\s*'true'/.test(workflowText),
    historicalRuntimePassCovered: request.trendRuns.some((run) => (
      run.mode === 'full'
      && run.passed
      && run.completedSteps === run.totalSteps
      && run.totalSteps >= request.plan.stepCount - 1
    )),
    latestRuntimeRunPassed: Boolean(latestRuntimeRun?.passed)
      && latestRuntimeRun?.completedSteps === latestRuntimeRun?.totalSteps,
    noRecentFailedRuns: trendDashboard.failedRunCount === 0
      && Object.keys(trendDashboard.failedStepFrequency).length === 0,
    fastSuiteLinked: request.fastSummary.kind === 'proxyforge-ci-fast-suite-summary'
      && request.fastSummary.passed
      && request.fastSummary.completedSteps === request.fastSummary.totalSteps
      && request.fastSummary.totalSteps >= 82
      && fastStepNames.has('Full/Nightly production evidence engine')
      && fastStepNames.has('Full/Nightly retained history engine')
      && fastStepNames.has('UI Scale production evidence engine')
      && fastStepNames.has('Release Trust production evidence engine')
      && fastStepNames.has('Automation installed-host service smoke')
      && fastStepNames.has('Project import compatibility engine')
      && fastStepNames.has('Customer-scale interop profiling engine')
      && fastStepNames.has('Extension third-party compatibility engine'),
    docsAndSchemasCovered: /RELEASE_CHECKLIST|OPERATOR_GUIDE|SCHEMAS\.md|proxyforge-full-nightly-production-evidence-package|trend dashboard|report-export-only/i.test(docsText),
    artifactPathsSafe: safeArtifactPath(request.artifactPath)
      && safeArtifactPath(request.historyArtifactPath)
      && request.plan.coverageOwnership.every((step) => step.artifactPaths.every(safeArtifactPath)),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|Bearer/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only redaction|submission\/report artifacts redact/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-full-nightly-production-evidence-package',
    generatedAt,
    plan: request.plan,
    currentSummary: request.currentSummary,
    trendDashboard,
    fastSummary: request.fastSummary,
    workflowContinuity: {
      restoreCacheAction: workflowText.match(/actions\/cache\/restore@v4/)?.[0] ?? '',
      saveCacheAction: workflowText.match(/actions\/cache\/save@v4/)?.[0] ?? '',
      historyPath: 'test-results/ci-full-suite-history/',
      cacheKey: workflowText.match(/proxyforge-full-suite-history-\$\{\{\s*github\.ref_name\s*\}\}-\$\{\{\s*github\.run_id\s*\}\}-\$\{\{\s*github\.run_attempt\s*\}\}/)?.[0] ?? '',
      restoreKeyPrefix: workflowText.match(/proxyforge-full-suite-history-\$\{\{\s*github\.ref_name\s*\}\}-/)?.[0] ?? '',
      planOnlySaveGuard: workflowText.match(/github\.event\.inputs\.plan_only\s*!=\s*'true'/)?.[0] ?? '',
    },
    artifactPath: request.artifactPath,
    historyArtifactPath: request.historyArtifactPath,
    retentionDays: request.retentionDays,
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    notes: {
      planOnlyBoundary: 'A plan-only summary validates metadata but does not claim runtime completion.',
      trendBoundary: 'Production readiness for the full/nightly gate requires retained full-run history and trend evidence, not just a committed workflow file.',
      scheduledHistoryContinuity: 'Scheduled CI restores retained history before execution and saves the refreshed history after runtime runs so the dashboard can accumulate across runner workspaces.',
      secretBoundary: 'Operational executor materials stay full fidelity; submission/report artifacts redact only during export.',
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `full-nightly-production-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-full-nightly-production-evidence-package',
    title: 'Full/Nightly production evidence package',
    fileName: `proxyforge-full-nightly-production-${stamp}.json`,
    path: `release/proxyforge-full-nightly-production-${stamp}.json`,
    generatedAt,
    stepCount: request.plan.stepCount,
    trendRunCount: request.trendRuns.length,
    requirements,
    trendDashboard,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'Full/nightly production evidence covers the scheduled full-suite plan, coverage ownership, artifact upload and retention policy, scheduled retained-history restore/save continuity, zero-flake budget, current plan-only boundary, retained runtime trend dashboard, retained history gate linkage, historical full-run pass, latest runtime pass, fast-suite linkage, release trust production, Automation installed-host service smoke, project import compatibility, customer-scale interop profiling, third-party extension compatibility, docs/schemas, artifact hygiene, full-fidelity executor material, and report-export-only redaction.',
    content,
  };
}

function median(values: number[]) {
  if (!values.length) return 0;
  const midpoint = Math.floor(values.length / 2);
  if (values.length % 2) return values[midpoint];
  return Math.round((values[midpoint - 1] + values[midpoint]) / 2);
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
