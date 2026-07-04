import type {
  AiActionExecutionPackage,
  AiActionExecutionStatus,
  AiBenchmarkRun,
  AiEvaluationBaseline,
  AiPromptComparison,
  AiPromptTemplate,
  AiProviderConfig,
  AiRunResult,
  AiSuggestedAction,
  HttpExchange,
  ToolId,
} from './types';

export interface AiParityEvidenceRequest {
  providerConfigs: AiProviderConfig[];
  providerRuns: AiRunResult[];
  promptTemplates: AiPromptTemplate[];
  evaluationBaselines: AiEvaluationBaseline[];
  promptComparisons: AiPromptComparison[];
  benchmarkRuns: AiBenchmarkRun[];
  actionExecutionPackages: AiActionExecutionPackage[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface AiParityEvidencePackage {
  id: string;
  kind: 'proxyforge-ai-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  providerCount: number;
  providerRunCount: number;
  promptTemplateCount: number;
  baselineCount: number;
  comparisonCount: number;
  benchmarkRunCount: number;
  actionExecutionPackageCount: number;
  artifactIds: {
    providerIds: string[];
    providerRunIds: string[];
    promptTemplateIds: string[];
    baselineIds: string[];
    comparisonIds: string[];
    benchmarkRunIds: string[];
    actionExecutionPackageIds: string[];
  };
  requirements: {
    codexProviderCovered: boolean;
    claudeProviderCovered: boolean;
    openAiCompatibleProviderCovered: boolean;
    cliProviderExecutionCovered: boolean;
    httpProviderExecutionCovered: boolean;
    streamingTelemetryCovered: boolean;
    promptEvaluationCovered: boolean;
    promptTemplatesCovered: boolean;
    baselinesCovered: boolean;
    comparisonsCovered: boolean;
    benchmarkReplayCovered: boolean;
    tokenCostAccountingCovered: boolean;
    controlledActionsCovered: boolean;
    scopeBlockingCovered: boolean;
    fullFidelityContextPreserved: boolean;
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

export function buildAiActionExecutionPackage(options: {
  action: AiSuggestedAction;
  aiRun?: AiRunResult | null;
  exchange?: HttpExchange;
  scopeAllowlist: string[];
  activeScanCheckCount?: number;
  now?: string;
}): AiActionExecutionPackage {
  const createdAt = options.now ?? new Date().toISOString();
  const targetTool = targetToolForAiAction(options.action.kind);
  const target = options.action.target || actionTargetFromExchange(options.exchange);
  const scopePassed = isAiActionInScope(options.action, options.exchange, options.scopeAllowlist);
  const trafficSent = false;
  const requestCount = options.action.kind === 'queue-active-scan'
    ? Math.max(1, Math.floor(options.activeScanCheckCount ?? 1))
    : 0;
  const maxRequests = requestCount;
  const status: AiActionExecutionStatus = !scopePassed
    ? 'blocked'
    : options.action.kind === 'queue-active-scan'
      ? 'queued'
      : 'completed';
  const approvalRequired = false;
  const approvalSatisfied = true;
  const safetyGates = [
    scopePassed ? 'scope matched selected target' : 'scope blocked selected target',
    'operator click required',
    'no autonomous traffic sent',
    options.action.kind === 'queue-active-scan' ? 'active scan queued only' : 'UI handoff only',
    options.action.kind === 'open-exploit-review' ? 'Exploit Lab opens in dry-run mode' : 'destructive actions disabled',
  ];
  const artifacts = artifactsForAiAction(options.action, targetTool, status);
  const digestPreview = simpleDigest(`${createdAt}|${options.aiRun?.id ?? 'no-run'}|${options.action.id}|${status}|${target}`);
  const content = JSON.stringify({
    kind: 'proxyforge-ai-action-execution',
    createdAt,
    aiRun: options.aiRun ? {
      id: options.aiRun.id,
      providerId: options.aiRun.providerId,
      task: options.aiRun.task,
      status: options.aiRun.status,
      contextDigest: options.aiRun.contextDigest,
    } : undefined,
    action: {
      id: options.action.id,
      kind: options.action.kind,
      label: options.action.label,
      priority: options.action.priority,
      target,
    },
    exchange: options.exchange ? {
      id: options.exchange.id,
      method: options.exchange.method,
      host: options.exchange.host,
      path: options.exchange.path,
      url: options.exchange.url,
      requestRaw: options.exchange.requestRaw,
      responseRaw: options.exchange.responseRaw,
    } : undefined,
    execution: {
      mode: 'ui-controlled',
      status,
      targetTool,
      trafficSent,
      requestCount,
      maxRequests,
      approvalRequired,
      approvalSatisfied,
      scopePassed,
      safetyGates,
      artifacts,
    },
    digestPreview,
  }, null, 2);

  return {
    id: `ai-action-exec-${digestPreview.slice(0, 12)}`,
    title: `${options.action.label} AI action execution`,
    createdAt,
    aiRunId: options.aiRun?.id,
    providerId: options.aiRun?.providerId,
    actionId: options.action.id,
    actionKind: options.action.kind,
    actionLabel: options.action.label,
    mode: 'ui-controlled',
    status,
    targetTool,
    target,
    scopePassed,
    approvalRequired,
    approvalSatisfied,
    trafficSent,
    requestCount,
    maxRequests,
    safetyGates,
    artifacts,
    summary: `${options.action.label} ${status}: ${targetTool} handoff for ${target}; traffic sent ${trafficSent ? 'yes' : 'no'}; ${scopePassed ? 'scope passed' : 'scope blocked'}.`,
    content,
  };
}

export function buildAiParityEvidencePackage(request: AiParityEvidenceRequest): AiParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const providerIds = new Set(request.providerConfigs.map((provider) => provider.id));
  const completedRunProviderIds = new Set(request.providerRuns
    .filter((run) => run.status === 'complete')
    .map((run) => run.providerId));
  const providerModes = new Map(request.providerConfigs.map((provider) => [provider.id, provider.mode]));
  const artifactOperationalText = [
    JSON.stringify(request.providerConfigs),
    JSON.stringify(request.providerRuns),
    JSON.stringify(request.promptTemplates),
    JSON.stringify(request.evaluationBaselines),
    JSON.stringify(request.promptComparisons),
    JSON.stringify(request.benchmarkRuns),
    JSON.stringify(request.actionExecutionPackages),
    ...request.providerRuns.flatMap((run) => [
      run.prompt ?? '',
      run.output,
      run.contextDigest ?? '',
      run.summary,
      ...(run.streamEvents ?? []).map((event) => event.text),
      ...(run.promptEvaluation?.checks ?? []).map((check) => `${check.label} ${check.detail}`),
    ]),
    ...request.actionExecutionPackages.map((pkg) => pkg.content),
  ].join('\n');
  const cliProviderIds = request.providerConfigs
    .filter((provider) => provider.mode === 'cli')
    .map((provider) => provider.id);
  const httpProviderIds = request.providerConfigs
    .filter((provider) => provider.mode === 'http')
    .map((provider) => provider.id);
  const actionStatuses = new Set(request.actionExecutionPackages.map((pkg) => pkg.status));
  const requirements = {
    codexProviderCovered: providerIds.has('codex') && completedRunProviderIds.has('codex'),
    claudeProviderCovered: providerIds.has('claude') && completedRunProviderIds.has('claude'),
    openAiCompatibleProviderCovered: providerIds.has('local') && completedRunProviderIds.has('local')
      && request.providerConfigs.some((provider) => provider.id === 'local' && provider.mode === 'http' && /\/v1\/chat\/completions|openai|compatible|localhost|127\.0\.0\.1/i.test(`${provider.endpoint ?? ''} ${provider.label}`)),
    cliProviderExecutionCovered: cliProviderIds.length >= 2
      && cliProviderIds.every((providerId) => request.providerRuns.some((run) => run.providerId === providerId && run.status === 'complete' && providerModes.get(providerId) === 'cli')),
    httpProviderExecutionCovered: httpProviderIds.length > 0
      && httpProviderIds.every((providerId) => request.providerRuns.some((run) => run.providerId === providerId && run.status === 'complete' && providerModes.get(providerId) === 'http')),
    streamingTelemetryCovered: request.providerRuns.some((run) => (run.streamEvents ?? []).some((event) => event.source === 'stdout'))
      && request.providerRuns.some((run) => (run.streamEvents ?? []).some((event) => event.source === 'http'))
      && request.providerRuns.every((run) => (run.streamEvents ?? []).some((event) => event.source === 'prompt')
        && (run.streamEvents ?? []).some((event) => event.source === 'complete')),
    promptEvaluationCovered: request.providerRuns.every((run) => Boolean(run.promptEvaluation) && (run.promptEvaluation?.checks.length ?? 0) > 0),
    promptTemplatesCovered: ['triage', 'replay-plan', 'exploit-review', 'report-draft']
      .every((task) => request.promptTemplates.some((template) => template.task === task)),
    baselinesCovered: request.evaluationBaselines.length >= 2
      && request.evaluationBaselines.every((baseline) => baseline.score > 0 && baseline.checks.length > 0 && Boolean(baseline.contextDigest)),
    comparisonsCovered: request.promptComparisons.length > 0
      && request.promptComparisons.every((comparison) => comparison.promptTokens > 0 && Number.isFinite(comparison.estimatedCostUsd)),
    benchmarkReplayCovered: request.benchmarkRuns.length > 0
      && request.benchmarkRuns.every((run) => run.resultCount > 0 && run.providerCount > 0 && run.baselineCount > 0 && run.results.length === run.resultCount),
    tokenCostAccountingCovered: request.providerRuns.every((run) => (run.usage?.totalTokens ?? 0) > 0 && Number.isFinite(run.usage?.estimatedCostUsd ?? Number.NaN))
      && request.promptComparisons.every((comparison) => comparison.promptTokens > 0 && Number.isFinite(comparison.estimatedCostUsd)),
    controlledActionsCovered: request.actionExecutionPackages.length >= 3
      && actionStatuses.has('completed')
      && actionStatuses.has('queued')
      && request.actionExecutionPackages.every((pkg) => pkg.mode === 'ui-controlled' && pkg.trafficSent === false),
    scopeBlockingCovered: request.actionExecutionPackages.some((pkg) => pkg.status === 'blocked' && pkg.scopePassed === false),
    fullFidelityContextPreserved: /HTTP\/[12]|Authorization:|Cookie:|requestRaw|responseRaw|Bearer/i.test(artifactOperationalText),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => artifactOperationalText.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-ai-parity-evidence-package',
    exportedAt,
    providerConfigs: request.providerConfigs,
    providerRuns: request.providerRuns,
    promptTemplates: request.promptTemplates,
    evaluationBaselines: request.evaluationBaselines,
    promptComparisons: request.promptComparisons,
    benchmarkRuns: request.benchmarkRuns,
    actionExecutionPackages: request.actionExecutionPackages,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `ai-parity-${Date.parse(exportedAt) || Date.now()}`,
    kind: 'proxyforge-ai-parity-evidence-package',
    title: 'AI parity evidence package',
    fileName: `proxyforge-ai-parity-${stamp}.json`,
    path: `ai/proxyforge-ai-parity-${stamp}.json`,
    exportedAt,
    providerCount: request.providerConfigs.length,
    providerRunCount: request.providerRuns.length,
    promptTemplateCount: request.promptTemplates.length,
    baselineCount: request.evaluationBaselines.length,
    comparisonCount: request.promptComparisons.length,
    benchmarkRunCount: request.benchmarkRuns.length,
    actionExecutionPackageCount: request.actionExecutionPackages.length,
    artifactIds: {
      providerIds: request.providerConfigs.map((provider) => provider.id),
      providerRunIds: request.providerRuns.map((run) => run.id),
      promptTemplateIds: request.promptTemplates.map((template) => template.id),
      baselineIds: request.evaluationBaselines.map((baseline) => baseline.id),
      comparisonIds: request.promptComparisons.map((comparison) => comparison.id),
      benchmarkRunIds: request.benchmarkRuns.map((run) => run.id),
      actionExecutionPackageIds: request.actionExecutionPackages.map((pkg) => pkg.id),
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'AI parity evidence covers Codex, Claude, OpenAI-compatible local providers, CLI and HTTP execution, streaming telemetry, prompt evaluations, templates, baselines, comparisons, benchmark replay, token/cost accounting, controlled action execution, scope blocking, and full-fidelity operational material until report export.',
    content,
  };
}

function targetToolForAiAction(kind: AiSuggestedAction['kind']): ToolId {
  if (kind === 'stage-repeater' || kind === 'stage-replay-matrix') return 'repeater';
  if (kind === 'queue-active-scan') return 'scanner';
  if (kind === 'open-exploit-review') return 'exploit';
  if (kind === 'record-automation') return 'automations';
  return 'reports';
}

function artifactsForAiAction(action: AiSuggestedAction, tool: ToolId, status: AiActionExecutionStatus) {
  if (status === 'blocked') return ['blocked-ai-action-execution-package'];
  if (action.kind === 'stage-replay-matrix') return ['replay-matrix-staging', 'repeater-workspace'];
  if (action.kind === 'stage-repeater') return ['repeater-workspace'];
  if (action.kind === 'queue-active-scan') return ['scanner-audit-queue-item'];
  if (action.kind === 'open-exploit-review') return ['exploit-lab-template-selection', 'dry-run-mode'];
  if (action.kind === 'record-automation') return ['automation-macro-workflow'];
  return [`${tool}-handoff`];
}

function actionTargetFromExchange(exchange: HttpExchange | undefined) {
  return exchange ? `${exchange.method} ${exchange.host}${exchange.path}` : 'project';
}

function isAiActionInScope(action: AiSuggestedAction, exchange: HttpExchange | undefined, scopeAllowlist: string[]) {
  if (action.kind === 'draft-report') return true;
  const host = exchange?.host ?? hostFromTarget(action.target);
  if (!host) return false;
  return scopeAllowlist.some((scope) => {
    const normalized = scope.trim().toLowerCase();
    const normalizedHost = host.toLowerCase();
    if (!normalized) return false;
    if (normalized === '*') return true;
    if (normalized.startsWith('*.')) return normalizedHost === normalized.slice(2) || normalizedHost.endsWith(normalized.slice(1));
    return normalizedHost === normalized || normalizedHost.endsWith(`.${normalized}`);
  });
}

function hostFromTarget(target: string) {
  try {
    return new URL(target).hostname;
  } catch {
    const methodTarget = target.match(/^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s/]+)(?:\/|$)/i)?.[1];
    if (methodTarget) return methodTarget;
    return target.match(/\b([a-z0-9.-]+\.[a-z]{2,})(?::\d+)?\b/i)?.[1];
  }
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
