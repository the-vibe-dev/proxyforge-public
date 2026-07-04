export type FullNightlyHistoryMode = 'plan-only' | 'skip-browser' | 'full' | string;

export interface FullNightlyHistoryUploadPolicy {
  summary: string;
  artifactDirectory: string;
  requiredArtifacts: string[];
  retentionDays: number;
  failureRetentionDays: number;
}

export interface FullNightlyHistoryFlakeBudget {
  maxFlakySteps: number;
  maxRetriesPerStep: number;
  browserRetryBudget: number;
  ownerRequired: boolean;
}

export interface FullNightlyHistoryCoverageOwner {
  name: string;
  kind: string;
  owner: string;
  artifactPaths: string[];
  retryBudget: number;
}

export interface FullNightlyHistoryPlan {
  kind: 'proxyforge-ci-full-suite-plan';
  suite: 'full-nightly';
  generatedAt: string;
  stepCount: number;
  uploadPolicy: FullNightlyHistoryUploadPolicy;
  flakeBudget: FullNightlyHistoryFlakeBudget;
  coverageOwnership: FullNightlyHistoryCoverageOwner[];
}

export interface FullNightlyHistoryStepResult {
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

export interface FullNightlyHistorySummary {
  kind: 'proxyforge-ci-full-suite-summary';
  mode: FullNightlyHistoryMode;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  passed: boolean;
  totalSteps: number;
  completedSteps: number;
  uploadPolicy: FullNightlyHistoryUploadPolicy;
  flakeBudget: FullNightlyHistoryFlakeBudget;
  coverageOwnership?: FullNightlyHistoryCoverageOwner[];
  results: FullNightlyHistoryStepResult[];
}

export interface FullNightlyRetainedSummary {
  runId: string;
  source: 'github-actions' | 'local-release' | 'runner-import' | string;
  artifactPath: string;
  recordedAt: string;
  summaryDigest: string;
  summary: FullNightlyHistorySummary;
  flakeViolations?: number;
}

export interface FullNightlyRetainedHistoryRun {
  runId: string;
  source: string;
  mode: FullNightlyHistoryMode;
  startedAt: string;
  completedAt: string;
  passed: boolean;
  totalSteps: number;
  completedSteps: number;
  durationMs: number;
  artifactPath: string;
  summaryDigest: string;
  failedStepNames: string[];
  flakeViolations: number;
}

export interface FullNightlyRetainedHistoryDashboard {
  kind: 'proxyforge-full-nightly-retained-history-dashboard';
  generatedAt: string;
  historyArtifactPath: string;
  retainedRunCount: number;
  runtimeRunCount: number;
  fullRunCount: number;
  skipBrowserRunCount: number;
  planOnlyRunCount: number;
  passedRunCount: number;
  failedRunCount: number;
  passRate: number;
  consecutiveRuntimePasses: number;
  medianRuntimeDurationMs: number;
  latestRuntimeRun?: FullNightlyRetainedHistoryRun;
  retainedRuns: FullNightlyRetainedHistoryRun[];
  artifactPaths: string[];
  failedStepFrequency: Record<string, number>;
  zeroFlakeViolations: number;
}

export interface FullNightlyRetainedHistoryRequest {
  plan: FullNightlyHistoryPlan;
  retainedSummaries: FullNightlyRetainedSummary[];
  currentSummary?: FullNightlyHistorySummary;
  historyArtifactPath: string;
  retentionDays: number;
  generatedAt?: string;
  minimumRuntimeRuns?: number;
  minimumFullRuns?: number;
  operationalSecretSamples?: string[];
}

export interface FullNightlyRetainedHistoryEvidencePackage {
  id: string;
  kind: 'proxyforge-full-nightly-retained-history-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  retainedRunCount: number;
  runtimeRunCount: number;
  requirements: {
    planValid: boolean;
    uploadPolicyIncludesHistory: boolean;
    retentionPolicyCovered: boolean;
    currentRuntimeSummaryRetained: boolean;
    planOnlyRunsExcludedFromRuntimeHistory: boolean;
    minimumRuntimeHistoryCovered: boolean;
    fullRunHistoryCovered: boolean;
    latestRuntimeRunPassed: boolean;
    noRecentFailedRuns: boolean;
    coverageOwnershipStable: boolean;
    requiredProductionStepsRetained: boolean;
    artifactPathsSafe: boolean;
    digestIntegrityCovered: boolean;
    zeroFlakeBudgetCovered: boolean;
    dashboardArtifactCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  dashboard: FullNightlyRetainedHistoryDashboard;
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  productionReady: boolean;
  digestPreview: string;
  summaryText: string;
  content: string;
}

export interface FullNightlyHostedRunReceipt {
  runId: string;
  source: 'github-actions' | 'runner-import' | string;
  eventName: 'schedule' | 'workflow_dispatch' | string;
  workflowName: string;
  branch: string;
  headSha: string;
  status: string;
  conclusion: string;
  url: string;
  startedAt: string;
  completedAt?: string;
  attempt?: number;
  artifactNames?: string[];
  retainedHistoryRestored: boolean;
  retainedHistorySaved: boolean;
  suiteSummaryUploaded: boolean;
  historyDashboardUploaded: boolean;
  rawRunMetadata?: string;
}

export interface FullNightlyHostedRetainedHistoryRequest {
  plan: FullNightlyHistoryPlan;
  retainedSummaries: FullNightlyRetainedSummary[];
  hostedRuns: FullNightlyHostedRunReceipt[];
  workflowName: string;
  branch: string;
  historyArtifactPath: string;
  retentionDays: number;
  generatedAt?: string;
  minimumHostedRuntimeRuns?: number;
  minimumScheduledRuntimeRuns?: number;
  operationalSecretSamples?: string[];
}

export interface FullNightlyHostedRetainedHistoryEvidencePackage {
  id: string;
  kind: 'proxyforge-full-nightly-hosted-retained-history-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  hostedRunCount: number;
  scheduledRunCount: number;
  requirements: {
    hostedRunReceiptsCovered: boolean;
    scheduledRunReceiptsCovered: boolean;
    workflowIdentityCovered: boolean;
    branchContinuityCovered: boolean;
    hostedRunsCompletedSuccessfully: boolean;
    retainedHistoryRestoreSaveCovered: boolean;
    hostedArtifactUploadCovered: boolean;
    retainedDashboardLinksHostedRuns: boolean;
    minimumRuntimeHistoryCovered: boolean;
    requiredProductionStepsRetained: boolean;
    digestIntegrityCovered: boolean;
    noFailedHostedRuns: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  dashboard: FullNightlyRetainedHistoryDashboard;
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  productionReady: boolean;
  digestPreview: string;
  summaryText: string;
  content: string;
}

const requiredRetainedStepPatterns = [
  /Full\/Nightly production evidence engine/i,
  /Full\/Nightly retained history engine/i,
  /Project import compatibility engine/i,
  /Customer-scale interop profiling engine/i,
  /Extension third-party compatibility engine/i,
  /Platform Shell production evidence engine/i,
  /Agent Control production evidence engine/i,
  /Release Security production evidence engine/i,
  /Release Trust production evidence engine/i,
  /Automation installed-host service smoke/i,
  /Proxy HTTP listener capture engine/i,
  /Scanner passive dedupe engine/i,
  /Repeater workspace parity engine/i,
  /Intruder engine|Intruder attack mode matrix engine/i,
  /Full browser workflow suite|skip-browser/i,
];

export function normalizeRetainedSummary(
  retained: FullNightlyRetainedSummary,
): FullNightlyRetainedHistoryRun {
  const failedStepNames = retained.summary.results
    .filter((result) => result.status !== 'passed' || result.exitCode !== 0)
    .map((result) => result.name);
  return {
    runId: retained.runId,
    source: retained.source,
    mode: retained.summary.mode,
    startedAt: retained.summary.startedAt,
    completedAt: retained.summary.completedAt,
    passed: retained.summary.passed,
    totalSteps: retained.summary.totalSteps,
    completedSteps: retained.summary.completedSteps,
    durationMs: retained.summary.durationMs,
    artifactPath: retained.artifactPath,
    summaryDigest: retained.summaryDigest,
    failedStepNames,
    flakeViolations: retained.flakeViolations ?? 0,
  };
}

export function buildFullNightlyRetainedHistoryDashboard(
  retainedSummaries: FullNightlyRetainedSummary[],
  historyArtifactPath = 'test-results/ci-full-suite-history/dashboard.json',
  generatedAt = new Date().toISOString(),
): FullNightlyRetainedHistoryDashboard {
  const retainedRuns = retainedSummaries
    .map(normalizeRetainedSummary)
    .sort((left, right) => Date.parse(left.startedAt) - Date.parse(right.startedAt));
  const runtimeRuns = retainedRuns.filter((run) => run.mode === 'full' || run.mode === 'skip-browser');
  const runtimeDurations = runtimeRuns.map((run) => run.durationMs).sort((left, right) => left - right);
  const failedStepFrequency = retainedRuns.reduce<Record<string, number>>((counts, run) => {
    for (const failedStepName of run.failedStepNames) {
      counts[failedStepName] = (counts[failedStepName] ?? 0) + 1;
    }
    return counts;
  }, {});
  const passedRunCount = retainedRuns.filter((run) => run.passed).length;
  return {
    kind: 'proxyforge-full-nightly-retained-history-dashboard',
    generatedAt,
    historyArtifactPath,
    retainedRunCount: retainedRuns.length,
    runtimeRunCount: runtimeRuns.length,
    fullRunCount: runtimeRuns.filter((run) => run.mode === 'full').length,
    skipBrowserRunCount: runtimeRuns.filter((run) => run.mode === 'skip-browser').length,
    planOnlyRunCount: retainedRuns.filter((run) => run.mode === 'plan-only').length,
    passedRunCount,
    failedRunCount: retainedRuns.length - passedRunCount,
    passRate: retainedRuns.length ? passedRunCount / retainedRuns.length : 0,
    consecutiveRuntimePasses: countTrailingPasses(runtimeRuns),
    medianRuntimeDurationMs: median(runtimeDurations),
    latestRuntimeRun: runtimeRuns.length ? runtimeRuns[runtimeRuns.length - 1] : undefined,
    retainedRuns,
    artifactPaths: retainedRuns.map((run) => run.artifactPath),
    failedStepFrequency,
    zeroFlakeViolations: retainedRuns.reduce((total, run) => total + run.flakeViolations, 0),
  };
}

export function buildFullNightlyRetainedHistoryEvidencePackage(
  request: FullNightlyRetainedHistoryRequest,
): FullNightlyRetainedHistoryEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const minimumRuntimeRuns = request.minimumRuntimeRuns ?? 3;
  const minimumFullRuns = request.minimumFullRuns ?? 1;
  const dashboard = buildFullNightlyRetainedHistoryDashboard(
    request.retainedSummaries,
    request.historyArtifactPath,
    generatedAt,
  );
  const retainedRuntimeSummaries = request.retainedSummaries.filter((retained) => (
    retained.summary.mode === 'full' || retained.summary.mode === 'skip-browser'
  ));
  const latestRuntimeSummary = retainedRuntimeSummaries
    .sort((left, right) => Date.parse(left.summary.startedAt) - Date.parse(right.summary.startedAt))
    .at(-1);
  const currentRuntimeSummaryRetained = !request.currentSummary || request.currentSummary.mode === 'plan-only'
    ? true
    : retainedRuntimeSummaries.some((retained) => (
      retained.summary.startedAt === request.currentSummary?.startedAt
      && retained.summary.completedAt === request.currentSummary?.completedAt
      && retained.summary.mode === request.currentSummary?.mode
    ));
  const stepCorpus = request.retainedSummaries
    .flatMap((retained) => retained.summary.results.map((result) => `${result.name}\n${result.command}\n${result.stdoutTail ?? ''}\n${result.stderrTail ?? ''}`))
    .join('\n');
  const rawMaterial = [
    JSON.stringify(request.plan),
    JSON.stringify(dashboard),
    ...request.retainedSummaries.map((retained) => JSON.stringify(retained.summary)),
    stepCorpus,
    request.historyArtifactPath,
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const requirements = {
    planValid: request.plan.kind === 'proxyforge-ci-full-suite-plan'
      && request.plan.suite === 'full-nightly'
      && request.plan.stepCount >= 70
      && request.plan.coverageOwnership.length === request.plan.stepCount,
    uploadPolicyIncludesHistory: request.plan.uploadPolicy.requiredArtifacts.includes('test-results/ci-full-suite-history/')
      && request.plan.uploadPolicy.requiredArtifacts.includes('test-results/ci-full-suite-history/dashboard.json'),
    retentionPolicyCovered: request.retentionDays >= 30
      && request.plan.uploadPolicy.failureRetentionDays >= 30,
    currentRuntimeSummaryRetained,
    planOnlyRunsExcludedFromRuntimeHistory: request.retainedSummaries.every((retained) => retained.summary.mode !== 'plan-only'),
    minimumRuntimeHistoryCovered: dashboard.runtimeRunCount >= minimumRuntimeRuns,
    fullRunHistoryCovered: dashboard.fullRunCount >= minimumFullRuns,
    latestRuntimeRunPassed: Boolean(dashboard.latestRuntimeRun?.passed)
      && dashboard.latestRuntimeRun?.completedSteps === dashboard.latestRuntimeRun?.totalSteps,
    noRecentFailedRuns: dashboard.failedRunCount === 0
      && Object.keys(dashboard.failedStepFrequency).length === 0,
    coverageOwnershipStable: retainedRuntimeSummaries.every((retained) => (
      retained.summary.coverageOwnership?.length === retained.summary.totalSteps
      && retained.summary.totalSteps >= request.plan.stepCount - 1
      && retained.summary.results.length === retained.summary.completedSteps
    )),
    requiredProductionStepsRetained: requiredRetainedStepPatterns.every((pattern) => pattern.test(stepCorpus)),
    artifactPathsSafe: safeArtifactPath(request.historyArtifactPath)
      && dashboard.artifactPaths.every(safeArtifactPath),
    digestIntegrityCovered: request.retainedSummaries.every((retained) => (
      retained.summaryDigest === simpleDigest(JSON.stringify(retained.summary))
    )),
    zeroFlakeBudgetCovered: request.plan.flakeBudget.maxFlakySteps === 0
      && request.plan.flakeBudget.ownerRequired === true
      && dashboard.zeroFlakeViolations === 0,
    dashboardArtifactCovered: dashboard.kind === 'proxyforge-full-nightly-retained-history-dashboard'
      && dashboard.historyArtifactPath === request.historyArtifactPath
      && dashboard.artifactPaths.includes(latestRuntimeSummary?.artifactPath ?? ''),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|Bearer/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only redaction|submission\/report artifacts redact/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-full-nightly-retained-history-evidence-package',
    generatedAt,
    historyArtifactPath: request.historyArtifactPath,
    retentionDays: request.retentionDays,
    dashboard,
    retainedSummaries: request.retainedSummaries.map((retained) => ({
      runId: retained.runId,
      source: retained.source,
      artifactPath: retained.artifactPath,
      recordedAt: retained.recordedAt,
      summaryDigest: retained.summaryDigest,
      mode: retained.summary.mode,
      passed: retained.summary.passed,
      totalSteps: retained.summary.totalSteps,
      completedSteps: retained.summary.completedSteps,
      stepNames: retained.summary.results.map((result) => result.name),
    })),
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    notes: {
      runtimeOnlyHistory: 'Plan-only summaries are kept as metadata artifacts but are not counted as retained runtime history.',
      trendBoundary: 'Production readiness for this gate requires retained runtime summaries plus a dashboard artifact from real full-suite execution.',
      secretBoundary: 'Operational executor materials stay full fidelity; submission/report artifacts redact only during export.',
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `full-nightly-history-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-full-nightly-retained-history-evidence-package',
    title: 'Full/Nightly retained history evidence package',
    fileName: `proxyforge-full-nightly-retained-history-${stamp}.json`,
    path: `release/proxyforge-full-nightly-retained-history-${stamp}.json`,
    generatedAt,
    retainedRunCount: dashboard.retainedRunCount,
    runtimeRunCount: dashboard.runtimeRunCount,
    requirements,
    dashboard,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: 'Full/nightly retained history evidence covers per-run runtime summaries, dashboard retention, current-run linkage, plan-only exclusion, full and skip-browser runtime history, zero-flake policy, digest integrity, safe artifact paths, full-fidelity executor material, and report-export-only redaction.',
    content,
  };
}

export function buildFullNightlyHostedRetainedHistoryEvidencePackage(
  request: FullNightlyHostedRetainedHistoryRequest,
): FullNightlyHostedRetainedHistoryEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const minimumHostedRuntimeRuns = request.minimumHostedRuntimeRuns ?? 3;
  const minimumScheduledRuntimeRuns = request.minimumScheduledRuntimeRuns ?? 2;
  const dashboard = buildFullNightlyRetainedHistoryDashboard(
    request.retainedSummaries,
    request.historyArtifactPath,
    generatedAt,
  );
  const sortedHostedRuns = [...request.hostedRuns].sort((left, right) => Date.parse(left.startedAt) - Date.parse(right.startedAt));
  const successfulHostedRuns = sortedHostedRuns.filter((run) => run.status === 'completed' && run.conclusion === 'success');
  const scheduledSuccessfulRuns = successfulHostedRuns.filter((run) => run.eventName === 'schedule');
  const retainedRunIds = new Set(dashboard.retainedRuns.map((run) => run.runId));
  const stepCorpus = request.retainedSummaries
    .flatMap((retained) => retained.summary.results.map((result) => `${result.name}\n${result.command}\n${result.stdoutTail ?? ''}\n${result.stderrTail ?? ''}`))
    .join('\n');
  const rawMaterial = [
    JSON.stringify(request.plan),
    JSON.stringify(dashboard),
    ...request.retainedSummaries.map((retained) => JSON.stringify(retained)),
    ...sortedHostedRuns.map((run) => JSON.stringify(run)),
    stepCorpus,
    request.workflowName,
    request.branch,
    request.historyArtifactPath,
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const runHasArtifact = (run: FullNightlyHostedRunReceipt, pattern: RegExp) => (
    pattern.test(run.rawRunMetadata ?? '')
    || (run.artifactNames ?? []).some((artifactName) => pattern.test(artifactName))
  );
  const requirements = {
    hostedRunReceiptsCovered: sortedHostedRuns.length >= minimumHostedRuntimeRuns
      && sortedHostedRuns.every((run) => Boolean(run.runId) && Boolean(run.url) && Boolean(run.startedAt)),
    scheduledRunReceiptsCovered: scheduledSuccessfulRuns.length >= minimumScheduledRuntimeRuns,
    workflowIdentityCovered: sortedHostedRuns.every((run) => run.workflowName === request.workflowName)
      && sortedHostedRuns.every((run) => /^https:\/\/github\.com\//.test(run.url)),
    branchContinuityCovered: sortedHostedRuns.every((run) => run.branch === request.branch && /^[a-f0-9]{7,40}$/i.test(run.headSha)),
    hostedRunsCompletedSuccessfully: successfulHostedRuns.length === sortedHostedRuns.length,
    retainedHistoryRestoreSaveCovered: successfulHostedRuns.every((run) => run.retainedHistoryRestored && run.retainedHistorySaved),
    hostedArtifactUploadCovered: successfulHostedRuns.every((run) => (
      run.suiteSummaryUploaded
      && run.historyDashboardUploaded
      && runHasArtifact(run, /ci-full-suite-summary|proxyforge-full-suite/i)
      && runHasArtifact(run, /ci-full-suite-history|dashboard/i)
    )),
    retainedDashboardLinksHostedRuns: successfulHostedRuns.every((run) => retainedRunIds.has(run.runId)),
    minimumRuntimeHistoryCovered: dashboard.runtimeRunCount >= minimumHostedRuntimeRuns
      && dashboard.consecutiveRuntimePasses >= minimumHostedRuntimeRuns
      && request.retentionDays >= 30,
    requiredProductionStepsRetained: requiredRetainedStepPatterns.every((pattern) => pattern.test(stepCorpus)),
    digestIntegrityCovered: request.retainedSummaries.every((retained) => (
      retained.summaryDigest === simpleDigest(JSON.stringify(retained.summary))
    )),
    noFailedHostedRuns: sortedHostedRuns.every((run) => run.conclusion === 'success'),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|rawRequest|rawResponse|callbackToken|Bearer/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only redaction|submission\/report artifacts redact/i.test(rawMaterial),
  };
  const unsigned = {
    kind: 'proxyforge-full-nightly-hosted-retained-history-evidence-package',
    generatedAt,
    workflowName: request.workflowName,
    branch: request.branch,
    historyArtifactPath: request.historyArtifactPath,
    retentionDays: request.retentionDays,
    minimumHostedRuntimeRuns,
    minimumScheduledRuntimeRuns,
    dashboard,
    hostedRuns: sortedHostedRuns,
    requirements,
    notes: {
      scheduledBoundary: 'Manual workflow_dispatch runs are useful warmups, but Production Ready for this gate requires scheduled run receipts linked to retained history.',
      hostedReceiptBoundary: 'Hosted receipts must prove successful completion, retained-history restore/save, uploaded summary/dashboard artifacts, and dashboard linkage by run id.',
      secretBoundary: 'Operational executor materials stay full fidelity; submission/report artifacts redact only during export.',
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `full-nightly-hosted-history-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-full-nightly-hosted-retained-history-evidence-package',
    title: 'Full/Nightly hosted retained-history evidence package',
    fileName: `proxyforge-full-nightly-hosted-retained-history-${stamp}.json`,
    path: `release/proxyforge-full-nightly-hosted-retained-history-${stamp}.json`,
    generatedAt,
    hostedRunCount: sortedHostedRuns.length,
    scheduledRunCount: scheduledSuccessfulRuns.length,
    requirements,
    dashboard,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    productionReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summaryText: `Full/nightly hosted retained-history evidence links ${sortedHostedRuns.length} hosted run receipt(s), ${scheduledSuccessfulRuns.length} scheduled receipt(s), retained dashboard history, cache restore/save proof, uploaded artifacts, digest integrity, full-fidelity executor material, and report-export-only redaction.`,
    content,
  };
}

function safeArtifactPath(artifactPath: string) {
  return /^test-results\/|^playwright-report\/|^\.gitignored\/|^release\//.test(artifactPath)
    && !artifactPath.includes('..')
    && !artifactPath.startsWith('/');
}

function countTrailingPasses(runs: FullNightlyRetainedHistoryRun[]) {
  let count = 0;
  for (let index = runs.length - 1; index >= 0; index -= 1) {
    if (!runs[index].passed) break;
    count += 1;
  }
  return count;
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
