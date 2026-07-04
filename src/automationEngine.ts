import type {
  AutomationExecution,
  AutomationCiProvider,
  AutomationSchedulerJob,
  AutomationSchedulerState,
  AutomationSchedulerTickResult,
  AutomationTrigger,
  AutomationWorkflow,
  AutomationWorkflowStep,
  HttpExchange,
  Issue,
} from './types';

const schedulerOwnerId = 'proxyforge-desktop-scheduler';
const schedulerLeaseTtlMs = 90_000;
const schedulerMaxConcurrentJobs = 3;

export const automationStepLabels: Record<AutomationWorkflowStep['type'], string> = {
  replay: 'Replay',
  crawl: 'Crawl',
  'active-scan': 'Active scan',
  'callback-poll': 'Callback poll',
  'report-export': 'Report export',
  delay: 'Delay',
};

export const automationTriggerLabels: Record<AutomationTrigger, string> = {
  manual: 'Manual launch',
  scheduled: 'Scheduled',
  'on-tag': 'On tag',
  ci: 'CI/headless',
};

export const automationCiProviderLabels: Record<AutomationCiProvider, string> = {
  'github-actions': 'GitHub Actions',
  'gitlab-ci': 'GitLab CI',
  'azure-pipelines': 'Azure Pipelines',
  jenkins: 'Jenkins',
};

export interface AutomationCiProviderPreset {
  provider: AutomationCiProvider;
  label: string;
  workflowId: string;
  fileName: string;
  config: string;
  requirements: {
    headlessCommandCovered: boolean;
    sarifCovered: boolean;
    junitCovered: boolean;
    reportBundleCovered: boolean;
    artifactUploadCovered: boolean;
    secretEnvCovered: boolean;
  };
}

export interface AutomationParityEvidenceRequest {
  workflows: AutomationWorkflow[];
  executions: AutomationExecution[];
  schedulerStates: AutomationSchedulerState[];
  schedulerTickResults: AutomationSchedulerTickResult[];
  ciProviderPresets: AutomationCiProviderPreset[];
  sourceExchanges: HttpExchange[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface AutomationParityEvidencePackage {
  id: string;
  kind: 'proxyforge-automation-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  workflowCount: number;
  executionCount: number;
  schedulerStateCount: number;
  ciProviderPresetCount: number;
  artifactIds: {
    workflowIds: string[];
    executionIds: string[];
    schedulerStateIds: string[];
    schedulerJobIds: string[];
    sourceExchangeIds: string[];
    ciProviders: AutomationCiProvider[];
  };
  requirements: {
    macroRecordingCovered: boolean;
    scheduledWorkflowCovered: boolean;
    onTagWorkflowCovered: boolean;
    ciWorkflowCovered: boolean;
    scopedExecutionCovered: boolean;
    approvalBlockingCovered: boolean;
    durableSchedulerQueueCovered: boolean;
    leaseRecoveryCovered: boolean;
    schedulerRestoreCovered: boolean;
    ciHeadlessCliCovered: boolean;
    ciProviderPresetsCovered: boolean;
    reportArtifactExportCovered: boolean;
    serviceLifecycleCovered: boolean;
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

export type AutomationServicePlatform = 'linux-systemd-user' | 'windows-task-scheduler';

export interface AutomationServiceLifecycleRequest {
  workflow: AutomationWorkflow;
  schedulerState: AutomationSchedulerState;
  projectPath: string;
  scopeAllowlist: string[];
  installRoot?: string;
  agentCommand?: string;
  serviceName?: string;
  linuxUser?: string;
  windowsUser?: string;
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface AutomationServiceInstallPlan {
  platform: AutomationServicePlatform;
  serviceName: string;
  displayName: string;
  installPath: string;
  statePath: string;
  logPath: string;
  agentCommand: string;
  installCommand: string;
  startCommand: string;
  statusCommand: string;
  stopCommand: string;
  uninstallCommand: string;
  manifest: string;
  environmentNames: string[];
  restartPolicy: string;
  schedulePolicy: string;
  requirements: {
    installCovered: boolean;
    startCovered: boolean;
    statusCovered: boolean;
    stopCovered: boolean;
    uninstallCovered: boolean;
    durableStateCovered: boolean;
    schedulerTickCommandCovered: boolean;
    secretEnvironmentCovered: boolean;
  };
}

export interface AutomationServiceLifecyclePackage {
  id: string;
  kind: 'proxyforge-automation-service-lifecycle-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  workflowId: string;
  schedulerStateId: string;
  platformCount: number;
  artifactIds: {
    workflowId: string;
    schedulerStateId: string;
    serviceNames: string[];
    platforms: AutomationServicePlatform[];
  };
  plans: AutomationServiceInstallPlan[];
  packageRefreshProof: {
    refreshedAt: string;
    planDigests: string[];
    schedulerDigest: string;
    lifecycleDigest: string;
    stalePlanIds: string[];
  };
  operationalSecretSignals: string[];
  operationalSecretSamples: string[];
  requirements: {
    linuxSystemdInstallStartCovered: boolean;
    windowsTaskSchedulerInstallStartCovered: boolean;
    startStatusStopUninstallCovered: boolean;
    schedulerTickCommandCovered: boolean;
    durableStatePathsCovered: boolean;
    restartPolicyCovered: boolean;
    secretEnvironmentCovered: boolean;
    packageRefreshCovered: boolean;
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

export const seedAutomationWorkflows: AutomationWorkflow[] = [
  {
    id: 'wf-authenticated-crawl-audit',
    name: 'Authenticated crawl and passive audit',
    status: 'ready',
    trigger: 'manual',
    scope: '*.shop.local',
    scheduleEnabled: false,
    scheduleIntervalMinutes: 60,
    nextRunAt: 'manual',
    lastRun: '13:17:04',
    steps: [
      makeStep('crawl', 'Crawl scoped routes', 'selected target', 150, 12, false),
      makeStep('active-scan', 'Audit discovered insertion points', 'crawler output', 300, 4, false),
      makeStep('report-export', 'Export evidence delta', 'current report', 0, 1, false),
    ],
  },
  {
    id: 'wf-authz-matrix',
    name: 'Replay authz matrix',
    status: 'ready',
    trigger: 'on-tag',
    scope: 'app.shop.local/api/*',
    scheduleEnabled: false,
    scheduleIntervalMinutes: 30,
    nextRunAt: 'on authz tag',
    lastRun: '12:41:29',
    steps: [
      makeStep('replay', 'Clone selected request', 'selected exchange', 100, 1, false),
      makeStep('replay', 'Swap role tokens', 'role matrix', 1000, 3, true),
      makeStep('report-export', 'Create evidence bundle', 'authz report section', 0, 1, false),
    ],
  },
  {
    id: 'wf-callback-monitor',
    name: 'Callback monitor enrichment',
    status: 'complete',
    trigger: 'scheduled',
    scope: 'callback tokens',
    scheduleEnabled: true,
    scheduleIntervalMinutes: 5,
    nextRunAt: '+5 minutes',
    lastRun: '13:22:00',
    steps: [
      makeStep('callback-poll', 'Poll callback interactions', 'active payloads', 0, 1, false),
      makeStep('report-export', 'Attach callback evidence', 'open callback issues', 0, 1, false),
    ],
  },
  {
    id: 'wf-headless-ci-scan',
    name: 'Headless CI smoke scan',
    status: 'ready',
    trigger: 'ci',
    scope: '*.shop.local',
    scheduleEnabled: false,
    scheduleIntervalMinutes: 1440,
    nextRunAt: 'on workflow dispatch',
    lastRun: 'Not run',
    steps: [
      makeStep('crawl', 'Start from configured base URL', 'CI target', 100, 8, false),
      makeStep('active-scan', 'Run low-rate active checks', 'CI crawler output', 500, 4, false),
      makeStep('report-export', 'Write machine-readable report', 'ci-artifacts/proxyforge-report.json', 0, 1, false),
    ],
  },
];

export function createMacroWorkflow(exchange: HttpExchange, scopeAllowlist: string[]): AutomationWorkflow {
  const now = new Date();
  return {
    id: `wf-macro-${now.getTime()}`,
    name: `Macro: ${exchange.method} ${exchange.path}`,
    status: 'ready',
    trigger: 'manual',
    scope: scopeAllowlist.join(', ') || exchange.host,
    scheduleEnabled: false,
    scheduleIntervalMinutes: 30,
    nextRunAt: 'manual',
    lastRun: 'Not run',
    steps: [
      makeStep('replay', `Replay ${exchange.method} ${exchange.path}`, exchange.url, 150, 1, false),
      makeStep('active-scan', 'Run passive-plus active checks', exchange.host, 300, 4, false),
      makeStep('report-export', 'Save macro evidence bundle', 'macro report section', 0, 1, false),
    ],
  };
}

export function runAutomationWorkflow(
  workflow: AutomationWorkflow,
  exchange: HttpExchange,
  scopeAllowlist: string[],
): { workflow: AutomationWorkflow; execution: AutomationExecution } {
  const startedAt = new Date();
  const inScope = isInScope(exchange.host, workflow.scope, scopeAllowlist);
  const blockedApproval = workflow.steps.some((step) => step.requiresApproval);
  const status = !inScope || blockedApproval ? 'blocked' : 'complete';
  const logs = [
    `Workflow: ${workflow.name}`,
    `Trigger: ${automationTriggerLabels[workflow.trigger]}`,
    `Scope: ${workflow.scope}`,
    `Selected exchange: ${exchange.method} ${exchange.host}${exchange.path}`,
  ];

  if (!inScope) logs.push(`Blocked: ${exchange.host} is outside project/workflow scope.`);
  if (blockedApproval) logs.push('Blocked: at least one state-changing step requires operator approval.');

  for (const step of workflow.steps) {
    const state = status === 'blocked' && step.requiresApproval ? 'held' : status === 'blocked' ? 'skipped' : 'complete';
    logs.push(`${state.toUpperCase()} ${automationStepLabels[step.type]}: ${step.label} (${step.maxRequests} request cap, ${step.throttleMs}ms throttle)`);
  }
  logs.push(status === 'complete' ? 'workflow complete' : 'workflow blocked');

  const completedAt = new Date(startedAt.getTime() + Math.max(120, workflow.steps.length * 180));
  const exchangePatch = status === 'complete' ? buildAutomationExchange(workflow, exchange, completedAt) : undefined;
  const issue = status === 'complete' ? buildAutomationIssue(workflow, exchange) : undefined;
  const execution: AutomationExecution = {
    id: `auto-exec-${startedAt.getTime()}`,
    workflowId: workflow.id,
    workflowName: workflow.name,
    status,
    trigger: workflow.trigger,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    durationMs: completedAt.getTime() - startedAt.getTime(),
    totalRequests: status === 'complete' ? workflow.steps.reduce((sum, step) => sum + step.maxRequests, 0) : 0,
    logs,
    exchange: exchangePatch,
    issue,
    operationalRawMaterial: {
      sourceExchangeId: exchange.id,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    },
    ciProvider: 'github-actions',
    ciConfig: renderCiConfig(workflow, scopeAllowlist, 'github-actions'),
  };

  return {
    workflow: {
      ...workflow,
      status,
      lastRun: completedAt.toLocaleTimeString([], { hour12: false }),
      nextRunAt: workflow.scheduleEnabled ? `+${workflow.scheduleIntervalMinutes} minutes` : workflow.nextRunAt,
      nextRunAtIso: workflow.scheduleEnabled ? addMinutes(completedAt, workflow.scheduleIntervalMinutes).toISOString() : workflow.nextRunAtIso,
    },
    execution,
  };
}

export function toggleWorkflowSchedule(workflow: AutomationWorkflow): AutomationWorkflow {
  const enabled = !workflow.scheduleEnabled;
  const nextRunAt = enabled ? addMinutes(new Date(), workflow.scheduleIntervalMinutes) : undefined;
  return {
    ...workflow,
    trigger: enabled ? 'scheduled' : workflow.trigger === 'scheduled' ? 'manual' : workflow.trigger,
    scheduleEnabled: enabled,
    nextRunAtIso: nextRunAt?.toISOString(),
    nextRunAt: enabled ? `+${workflow.scheduleIntervalMinutes} minutes` : 'manual',
  };
}

export function createAutomationSchedulerState(
  workflows: AutomationWorkflow[],
  now = new Date(),
  existing?: Partial<AutomationSchedulerState>,
): AutomationSchedulerState {
  const timestamp = now.toISOString();
  const base: AutomationSchedulerState = {
    id: existing?.id ?? 'automation-scheduler-local',
    status: existing?.status ?? 'running',
    ownerId: existing?.ownerId ?? schedulerOwnerId,
    leaseTtlMs: existing?.leaseTtlMs ?? schedulerLeaseTtlMs,
    maxConcurrentJobs: existing?.maxConcurrentJobs ?? schedulerMaxConcurrentJobs,
    heartbeatAt: existing?.heartbeatAt ?? timestamp,
    updatedAt: existing?.updatedAt ?? timestamp,
    queue: existing?.queue ?? [],
  };
  return reconcileAutomationScheduler(base, workflows, now);
}

export function runAutomationSchedulerTick(options: {
  state: AutomationSchedulerState;
  workflows: AutomationWorkflow[];
  exchange: HttpExchange;
  scopeAllowlist: string[];
  now?: Date;
  ownerId?: string;
  maxJobs?: number;
}): AutomationSchedulerTickResult {
  const now = options.now ?? new Date();
  const ownerId = options.ownerId ?? options.state.ownerId ?? schedulerOwnerId;
  const timestamp = now.toISOString();
  const logs = [`Scheduler heartbeat ${timestamp} by ${ownerId}.`];
  let state = reconcileAutomationScheduler(options.state, options.workflows, now);

  if (state.status !== 'running') {
    state = {
      ...state,
      heartbeatAt: timestamp,
      updatedAt: timestamp,
    };
    return { state, workflows: options.workflows, executions: [], logs: [...logs, `Scheduler ${state.status}; no jobs claimed.`], claimedJobs: 0, completedJobs: 0, blockedJobs: 0 };
  }

  const dueJobs = state.queue
    .filter((job) => isClaimableSchedulerJob(job, now))
    .sort((left, right) => Date.parse(left.scheduledFor) - Date.parse(right.scheduledFor))
    .slice(0, options.maxJobs ?? state.maxConcurrentJobs);
  const leaseId = `auto-lease-${now.getTime()}-${Math.random().toString(16).slice(2)}`;
  const leaseExpiresAt = new Date(now.getTime() + state.leaseTtlMs).toISOString();
  const executions: AutomationExecution[] = [];
  let completedJobs = 0;
  let blockedJobs = 0;
  let nextWorkflows = options.workflows;

  state = {
    ...state,
    heartbeatAt: timestamp,
    updatedAt: timestamp,
    queue: state.queue.map((job) => {
      if (!dueJobs.some((dueJob) => dueJob.id === job.id)) return expireSchedulerLease(job, now);
      return {
        ...job,
        status: 'leased',
        attempts: job.attempts + 1,
        leaseId,
        leasedBy: ownerId,
        leaseExpiresAt,
        updatedAt: timestamp,
        summary: `Claimed by ${ownerId} until ${leaseExpiresAt}.`,
      };
    }),
  };

  for (const job of dueJobs) {
    const workflow = nextWorkflows.find((candidate) => candidate.id === job.workflowId);
    if (!workflow || !workflow.scheduleEnabled) {
      blockedJobs += 1;
      state = finishSchedulerJob(state, job.id, 'blocked', timestamp, undefined, 'Workflow was removed or unscheduled before execution.');
      logs.push(`BLOCKED ${job.workflowName}: workflow no longer scheduled.`);
      continue;
    }

    const result = runAutomationWorkflow({ ...workflow, trigger: 'scheduled' }, options.exchange, options.scopeAllowlist);
    const execution: AutomationExecution = {
      ...result.execution,
      schedulerJobId: job.id,
      schedulerLeaseId: leaseId,
      logs: [
        `Scheduler job ${job.id} leased by ${ownerId}.`,
        ...result.execution.logs,
      ],
    };
    executions.push(execution);
    if (execution.status === 'complete') completedJobs += 1;
    else blockedJobs += 1;

    const scheduledWorkflow: AutomationWorkflow = {
      ...result.workflow,
      trigger: workflow.trigger,
      scheduleEnabled: workflow.scheduleEnabled,
      lastSchedulerRunAt: execution.completedAt,
      nextRunAtIso: addMinutes(new Date(execution.completedAt), workflow.scheduleIntervalMinutes).toISOString(),
      nextRunAt: `+${workflow.scheduleIntervalMinutes} minutes`,
    };
    nextWorkflows = nextWorkflows.map((candidate) => (candidate.id === workflow.id ? scheduledWorkflow : candidate));
    state = finishSchedulerJob(state, job.id, execution.status === 'complete' ? 'complete' : 'blocked', timestamp, execution.id, execution.logs[execution.logs.length - 1]);
    logs.push(`${execution.status.toUpperCase()} ${workflow.name}: ${execution.totalRequests} planned request(s).`);
  }

  state = reconcileAutomationScheduler(state, nextWorkflows, now);
  logs.push(`${dueJobs.length} job(s) claimed; ${completedJobs} completed; ${blockedJobs} blocked.`);

  return {
    state,
    workflows: nextWorkflows,
    executions,
    logs,
    claimedJobs: dueJobs.length,
    completedJobs,
    blockedJobs,
  };
}

export function renderCiConfig(workflow: AutomationWorkflow, scopeAllowlist: string[], provider: AutomationCiProvider = 'github-actions') {
  const safeName = workflow.name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'proxyforge-workflow';
  const scope = scopeAllowlist.join(',') || workflow.scope;
  const scheduleMinutes = Math.max(5, Math.min(60, workflow.scheduleIntervalMinutes));
  const headlessCommand = [
    `proxyforge headless --workflow "${workflow.id}"`,
    '--target "$PROXYFORGE_TARGET_URL"',
    `--scope "${scope}"`,
    '--crawl-audit',
    '--max-active-requests 4',
    '--report json,bundle',
    '--sarif',
    '--junit',
    '--out-dir ci-artifacts/proxyforge',
  ].join(' \\\n            ');

  if (provider === 'gitlab-ci') {
    return [
      'stages:',
      '  - dast',
      '',
      `proxyforge-${safeName}:`,
      '  stage: dast',
      '  image: node:20',
      '  variables:',
      '    PROXYFORGE_TARGET_URL: $PROXYFORGE_TARGET_URL',
      '    PROXYFORGE_AUTHORIZATION: $PROXYFORGE_AUTHORIZATION',
      '    PROXYFORGE_COOKIE: $PROXYFORGE_COOKIE',
      '  script:',
      '    - npm ci',
      '    - npm run build',
      `    - ${headlessCommand.replace(/\n\s*/g, ' ')}`,
      '  artifacts:',
      '    when: always',
      '    paths:',
      '      - ci-artifacts/proxyforge',
      '    reports:',
      '      junit: ci-artifacts/proxyforge/proxyforge-junit.xml',
      '      sast: ci-artifacts/proxyforge/proxyforge-results.sarif',
    ].join('\n');
  }

  if (provider === 'azure-pipelines') {
    return [
      `name: proxyforge-${safeName}`,
      'trigger: none',
      'schedules:',
      `  - cron: "*/${scheduleMinutes} * * * *"`,
      '    displayName: ProxyForge scheduled scan',
      '    branches:',
      '      include:',
      '        - main',
      'pool:',
      '  vmImage: ubuntu-latest',
      'steps:',
      '  - task: NodeTool@0',
      '    inputs:',
      '      versionSpec: "20.x"',
      '  - script: npm ci',
      '    displayName: Install dependencies',
      '  - script: npm run build',
      '    displayName: Build ProxyForge',
      '  - script: |',
      `      ${headlessCommand}`,
      '    displayName: Run ProxyForge headless DAST',
      '    env:',
      '      PROXYFORGE_TARGET_URL: $(PROXYFORGE_TARGET_URL)',
      '      PROXYFORGE_AUTHORIZATION: $(PROXYFORGE_AUTHORIZATION)',
      '      PROXYFORGE_COOKIE: $(PROXYFORGE_COOKIE)',
      '  - task: PublishTestResults@2',
      '    condition: always()',
      '    inputs:',
      '      testResultsFormat: JUnit',
      '      testResultsFiles: ci-artifacts/proxyforge/proxyforge-junit.xml',
      '      testRunTitle: ProxyForge DAST',
      '  - publish: ci-artifacts/proxyforge',
      '    condition: always()',
      '    artifact: proxyforge-headless-artifacts',
    ].join('\n');
  }

  if (provider === 'jenkins') {
    return [
      'pipeline {',
      '  agent any',
      '  environment {',
      '    PROXYFORGE_TARGET_URL = credentials("proxyforge-target-url")',
      '    PROXYFORGE_AUTHORIZATION = credentials("proxyforge-authorization")',
      '    PROXYFORGE_COOKIE = credentials("proxyforge-cookie")',
      '  }',
      '  stages {',
      '    stage("ProxyForge DAST") {',
      '      steps {',
      '        sh "npm ci"',
      '        sh "npm run build"',
      '        sh """',
      `          ${headlessCommand}`,
      '        """',
      '      }',
      '    }',
      '  }',
      '  post {',
      '    always {',
      '      junit allowEmptyResults: true, testResults: "ci-artifacts/proxyforge/proxyforge-junit.xml"',
      '      archiveArtifacts allowEmptyArchive: true, artifacts: "ci-artifacts/proxyforge/**"',
      '    }',
      '  }',
      '}',
    ].join('\n');
  }

  return [
    `name: proxyforge-${safeName}`,
    'on:',
    '  workflow_dispatch:',
    '  schedule:',
    `    - cron: "*/${scheduleMinutes} * * * *"`,
    'jobs:',
    '  authorized-scan:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: actions/checkout@v4',
    '      - uses: actions/setup-node@v4',
    '        with:',
    '          node-version: "20"',
    '      - run: npm ci',
    '      - run: npm run build',
    '      - name: Run ProxyForge headless workflow',
    '        env:',
    '          PROXYFORGE_TARGET_URL: ${{ secrets.PROXYFORGE_TARGET_URL }}',
    '          PROXYFORGE_AUTHORIZATION: ${{ secrets.PROXYFORGE_AUTHORIZATION }}',
    '          PROXYFORGE_COOKIE: ${{ secrets.PROXYFORGE_COOKIE }}',
    '          PROXYFORGE_SESSION_HEADERS: ${{ secrets.PROXYFORGE_SESSION_HEADERS }}',
    '        run: |',
    `          npx ${headlessCommand}`,
    '      - name: Upload ProxyForge SARIF',
    '        if: always()',
    '        uses: github/codeql-action/upload-sarif@v3',
    '        with:',
    '          sarif_file: ci-artifacts/proxyforge/proxyforge-results.sarif',
    '      - name: Upload ProxyForge artifacts',
    '        if: always()',
    '        uses: actions/upload-artifact@v4',
    '        with:',
    '          name: proxyforge-headless-artifacts',
    '          path: ci-artifacts/proxyforge',
  ].join('\n');
}

export function buildAutomationCiProviderMatrix(
  workflow: AutomationWorkflow,
  scopeAllowlist: string[],
  providers: AutomationCiProvider[] = ['github-actions', 'gitlab-ci', 'azure-pipelines', 'jenkins'],
): AutomationCiProviderPreset[] {
  return providers.map((provider) => {
    const config = renderCiConfig(workflow, scopeAllowlist, provider);
    const fileName = provider === 'github-actions'
      ? '.github/workflows/proxyforge.yml'
      : provider === 'gitlab-ci'
        ? '.gitlab-ci.yml'
        : provider === 'azure-pipelines'
          ? 'azure-pipelines.proxyforge.yml'
          : 'Jenkinsfile.proxyforge';
    return {
      provider,
      label: automationCiProviderLabels[provider],
      workflowId: workflow.id,
      fileName,
      config,
      requirements: {
        headlessCommandCovered: /proxyforge headless/.test(config),
        sarifCovered: /--sarif|sarif/i.test(config),
        junitCovered: /--junit|junit/i.test(config),
        reportBundleCovered: /--report json,bundle|bundle/i.test(config),
        artifactUploadCovered: /artifact|archiveArtifacts|PublishTestResults|upload-artifact|paths:/i.test(config),
        secretEnvCovered: /PROXYFORGE_AUTHORIZATION|PROXYFORGE_COOKIE/i.test(config),
      },
    };
  });
}

export function buildAutomationParityEvidencePackage(
  request: AutomationParityEvidenceRequest,
): AutomationParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const allJobs = request.schedulerStates.flatMap((state) => state.queue);
  const providerSet = new Set(request.ciProviderPresets.map((preset) => preset.provider));
  const artifactOperationalText = [
    JSON.stringify(request.workflows),
    JSON.stringify(request.executions),
    JSON.stringify(request.schedulerStates),
    JSON.stringify(request.schedulerTickResults),
    JSON.stringify(request.ciProviderPresets),
    JSON.stringify(request.sourceExchanges),
    ...request.executions.map((execution) => execution.ciConfig),
    ...request.executions.flatMap((execution) => [
      execution.exchange?.requestRaw ?? '',
      execution.exchange?.responseRaw ?? '',
      execution.issue?.detail ?? '',
      ...execution.logs,
    ]),
    ...request.sourceExchanges.flatMap((exchange) => [exchange.requestRaw, exchange.responseRaw, exchange.notes ?? '']),
    ...request.ciProviderPresets.map((preset) => preset.config),
  ].join('\n');
  const requirements = {
    macroRecordingCovered: request.workflows.some((workflow) => workflow.id.startsWith('wf-macro-')
      && workflow.trigger === 'manual'
      && workflow.steps.some((step) => step.type === 'replay')
      && workflow.steps.some((step) => step.type === 'active-scan')
      && workflow.steps.some((step) => step.type === 'report-export')),
    scheduledWorkflowCovered: request.workflows.some((workflow) => workflow.scheduleEnabled && workflow.trigger === 'scheduled' && Boolean(workflow.nextRunAtIso)),
    onTagWorkflowCovered: request.workflows.some((workflow) => workflow.trigger === 'on-tag'),
    ciWorkflowCovered: request.workflows.some((workflow) => workflow.trigger === 'ci'),
    scopedExecutionCovered: request.executions.some((execution) => execution.status === 'complete' && execution.totalRequests > 0 && execution.logs.some((line) => /Scope:|request cap|throttle/i.test(line))),
    approvalBlockingCovered: request.executions.some((execution) => execution.status === 'blocked' && execution.logs.some((line) => /approval|requires operator/i.test(line))),
    durableSchedulerQueueCovered: allJobs.some((job) => job.status === 'queued')
      && allJobs.some((job) => job.status === 'complete' && Boolean(job.executionId))
      && allJobs.some((job) => job.status === 'blocked' && Boolean(job.summary)),
    leaseRecoveryCovered: allJobs.some((job) => job.attempts > 1 || /Lease expired/i.test(job.summary ?? ''))
      || request.schedulerTickResults.some((tick) => tick.logs.some((line) => /Lease expired|reclaimed|expired lease/i.test(line))),
    schedulerRestoreCovered: request.schedulerStates.length >= 2
      && request.schedulerStates.some((state) => state.queue.some((job) => job.status === 'complete' || job.status === 'blocked'))
      && request.schedulerStates.some((state) => state.queue.some((job) => job.status === 'queued')),
    ciHeadlessCliCovered: request.ciProviderPresets.every((preset) => preset.requirements.headlessCommandCovered
      && preset.requirements.sarifCovered
      && preset.requirements.junitCovered
      && preset.requirements.reportBundleCovered),
    ciProviderPresetsCovered: ['github-actions', 'gitlab-ci', 'azure-pipelines', 'jenkins'].every((provider) => providerSet.has(provider as AutomationCiProvider)),
    reportArtifactExportCovered: request.ciProviderPresets.every((preset) => preset.requirements.artifactUploadCovered)
      && request.workflows.some((workflow) => workflow.steps.some((step) => step.type === 'report-export')),
    serviceLifecycleCovered: ['running', 'paused', 'stopped'].every((status) => request.schedulerStates.some((state) => state.status === status)),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|requestRaw|responseRaw/i.test(artifactOperationalText),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => artifactOperationalText.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-automation-parity-evidence-package',
    exportedAt,
    workflows: request.workflows,
    executions: request.executions,
    schedulerStates: request.schedulerStates,
    schedulerTickResults: request.schedulerTickResults,
    ciProviderPresets: request.ciProviderPresets,
    sourceExchanges: request.sourceExchanges,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `automation-parity-${Date.parse(exportedAt) || Date.now()}`,
    kind: 'proxyforge-automation-parity-evidence-package',
    title: 'Automation parity evidence package',
    fileName: `proxyforge-automation-parity-${stamp}.json`,
    path: `automations/proxyforge-automation-parity-${stamp}.json`,
    exportedAt,
    workflowCount: request.workflows.length,
    executionCount: request.executions.length,
    schedulerStateCount: request.schedulerStates.length,
    ciProviderPresetCount: request.ciProviderPresets.length,
    artifactIds: {
      workflowIds: request.workflows.map((workflow) => workflow.id),
      executionIds: request.executions.map((execution) => execution.id),
      schedulerStateIds: request.schedulerStates.map((state) => state.id),
      schedulerJobIds: Array.from(new Set(allJobs.map((job) => job.id))),
      sourceExchangeIds: request.sourceExchanges.map((exchange) => exchange.id),
      ciProviders: Array.from(providerSet),
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Automation parity evidence covers macro recording, scheduled/on-tag/CI workflows, scoped execution, approval blocking, durable scheduler queues, lease recovery, scheduler restore, CI provider presets, headless report artifacts, service lifecycle states, and full-fidelity operational material.',
    content,
  };
}

export function buildAutomationServiceLifecyclePackage(
  request: AutomationServiceLifecycleRequest,
): AutomationServiceLifecyclePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const serviceName = normalizeServiceName(request.serviceName ?? `proxyforge-automation-${request.workflow.id}`);
  const installRoot = normalizePath(request.installRoot ?? '/opt/ProxyForge');
  const agentCommand = request.agentCommand ?? `${installRoot}/scripts/proxyforge-agent.mjs`;
  const plans = [
    buildLinuxSystemdServicePlan(request, serviceName, installRoot, agentCommand),
    buildWindowsTaskSchedulerPlan(request, serviceName, installRoot, agentCommand),
  ];
  const rawMaterial = [
    JSON.stringify(request.workflow),
    JSON.stringify(request.schedulerState),
    ...plans.flatMap((plan) => [
      plan.agentCommand,
      plan.installCommand,
      plan.startCommand,
      plan.statusCommand,
      plan.stopCommand,
      plan.uninstallCommand,
      plan.manifest,
    ]),
    ...(request.operationalSecretSamples ?? []),
  ].join('\n');
  const operationalSecretSignals = automationOperationalSecretSignals(rawMaterial);
  const operationalSecretSamples = request.operationalSecretSamples ?? [];
  const schedulerDigest = simpleDigest(JSON.stringify({
    id: request.schedulerState.id,
    status: request.schedulerState.status,
    ownerId: request.schedulerState.ownerId,
    queue: request.schedulerState.queue.map((job) => ({
      id: job.id,
      workflowId: job.workflowId,
      status: job.status,
      scheduledFor: job.scheduledFor,
      attempts: job.attempts,
    })),
  }));
  const planDigests = plans.map((plan) => simpleDigest(JSON.stringify({
    platform: plan.platform,
    serviceName: plan.serviceName,
    commands: [
      plan.installCommand,
      plan.startCommand,
      plan.statusCommand,
      plan.stopCommand,
      plan.uninstallCommand,
    ],
    requirements: plan.requirements,
  })));
  const requirements = {
    linuxSystemdInstallStartCovered: plans.some((plan) => plan.platform === 'linux-systemd-user'
      && plan.requirements.installCovered
      && plan.requirements.startCovered
      && /systemctl --user/i.test(`${plan.installCommand}\n${plan.startCommand}`)),
    windowsTaskSchedulerInstallStartCovered: plans.some((plan) => plan.platform === 'windows-task-scheduler'
      && plan.requirements.installCovered
      && plan.requirements.startCovered
      && /schtasks/i.test(`${plan.installCommand}\n${plan.startCommand}`)),
    startStatusStopUninstallCovered: plans.every((plan) => (
      plan.requirements.startCovered
      && plan.requirements.statusCovered
      && plan.requirements.stopCovered
      && plan.requirements.uninstallCovered
    )),
    schedulerTickCommandCovered: plans.every((plan) => plan.requirements.schedulerTickCommandCovered),
    durableStatePathsCovered: plans.every((plan) => plan.requirements.durableStateCovered),
    restartPolicyCovered: plans.every((plan) => /restart|repetition|on-failure|minute/i.test(`${plan.restartPolicy}\n${plan.schedulePolicy}\n${plan.manifest}`)),
    secretEnvironmentCovered: plans.every((plan) => plan.requirements.secretEnvironmentCovered),
    packageRefreshCovered: planDigests.length === 2 && schedulerDigest.length > 0,
    rawExecutorMaterialPreserved: /automation-scheduler-tick|project|scope|workflow|manifest/i.test(rawMaterial),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const lifecycleDigest = simpleDigest(JSON.stringify({
    serviceName,
    generatedAt,
    planDigests,
    schedulerDigest,
    requirements,
  }));
  const packageRefreshProof = {
    refreshedAt: generatedAt,
    planDigests,
    schedulerDigest,
    lifecycleDigest,
    stalePlanIds: [],
  };
  const unsigned = {
    kind: 'proxyforge-automation-service-lifecycle-package',
    generatedAt,
    workflow: request.workflow,
    schedulerState: request.schedulerState,
    projectPath: request.projectPath,
    scopeAllowlist: request.scopeAllowlist,
    plans,
    packageRefreshProof,
    operationalSecretSignals,
    operationalSecretSamples,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `automation-service-lifecycle-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-automation-service-lifecycle-package',
    title: 'Automation service lifecycle package',
    fileName: `proxyforge-automation-service-lifecycle-${stamp}.json`,
    path: `automations/proxyforge-automation-service-lifecycle-${stamp}.json`,
    generatedAt,
    workflowId: request.workflow.id,
    schedulerStateId: request.schedulerState.id,
    platformCount: plans.length,
    artifactIds: {
      workflowId: request.workflow.id,
      schedulerStateId: request.schedulerState.id,
      serviceNames: plans.map((plan) => plan.serviceName),
      platforms: plans.map((plan) => plan.platform),
    },
    plans,
    packageRefreshProof,
    operationalSecretSignals,
    operationalSecretSamples,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: `Automation service lifecycle package covers ${plans.length} platform service plan(s), systemd user install/start controls, Windows Task Scheduler install/start controls, scheduler tick execution, durable state paths, restart policy, secret environment handling, and report-export-only redaction.`,
    content,
  };
}

function buildLinuxSystemdServicePlan(
  request: AutomationServiceLifecycleRequest,
  serviceName: string,
  installRoot: string,
  agentCommand: string,
): AutomationServiceInstallPlan {
  const unitName = `${serviceName}.service`;
  const installPath = `~/.config/systemd/user/${unitName}`;
  const statePath = `~/.local/state/proxyforge/automations/${serviceName}.json`;
  const logPath = `~/.local/state/proxyforge/logs/${serviceName}.jsonl`;
  const schedulerCommand = renderAutomationSchedulerServiceCommand(request, agentCommand, statePath, logPath);
  const manifest = [
    '[Unit]',
    `Description=ProxyForge automation scheduler (${request.workflow.name})`,
    'After=network-online.target',
    'Wants=network-online.target',
    '',
    '[Service]',
    'Type=simple',
    `WorkingDirectory=${installRoot}`,
    'Environment=PROXYFORGE_AUTHORIZATION=${PROXYFORGE_AUTHORIZATION}',
    'Environment=PROXYFORGE_COOKIE=${PROXYFORGE_COOKIE}',
    'Environment=PROXYFORGE_API_KEY=${PROXYFORGE_API_KEY}',
    `ExecStart=${schedulerCommand}`,
    'Restart=on-failure',
    'RestartSec=15',
    '',
    '[Install]',
    'WantedBy=default.target',
  ].join('\n');
  const environmentNames = ['PROXYFORGE_AUTHORIZATION', 'PROXYFORGE_COOKIE', 'PROXYFORGE_API_KEY'];
  const installCommand = `install -Dm0644 ${unitName} ${installPath} && systemctl --user daemon-reload && systemctl --user enable ${unitName}`;
  const startCommand = `systemctl --user start ${unitName}`;
  const statusCommand = `systemctl --user status ${unitName} --no-pager`;
  const stopCommand = `systemctl --user stop ${unitName}`;
  const uninstallCommand = `systemctl --user disable --now ${unitName} && rm -f ${installPath} && systemctl --user daemon-reload`;
  return {
    platform: 'linux-systemd-user',
    serviceName,
    displayName: `ProxyForge Automation Scheduler (${request.workflow.name})`,
    installPath,
    statePath,
    logPath,
    agentCommand: schedulerCommand,
    installCommand,
    startCommand,
    statusCommand,
    stopCommand,
    uninstallCommand,
    manifest,
    environmentNames,
    restartPolicy: 'systemd Restart=on-failure RestartSec=15',
    schedulePolicy: `${request.workflow.scheduleIntervalMinutes} minute workflow interval; scheduler tick reconciles durable queue state`,
    requirements: buildServicePlanRequirements({
      installCommand,
      startCommand,
      statusCommand,
      stopCommand,
      uninstallCommand,
      statePath,
      schedulerCommand,
      manifest,
      environmentNames,
    }),
  };
}

function buildWindowsTaskSchedulerPlan(
  request: AutomationServiceLifecycleRequest,
  serviceName: string,
  installRoot: string,
  agentCommand: string,
): AutomationServiceInstallPlan {
  const taskName = `ProxyForge\\${serviceName}`;
  const installPath = `%ProgramData%\\ProxyForge\\Automations\\${serviceName}.xml`;
  const statePath = `%ProgramData%\\ProxyForge\\Automations\\${serviceName}.json`;
  const logPath = `%ProgramData%\\ProxyForge\\Logs\\${serviceName}.jsonl`;
  const schedulerCommand = renderAutomationSchedulerServiceCommand(request, agentCommand, statePath, logPath);
  const windowsUser = request.windowsUser ?? '${env:USERNAME}';
  const interval = `PT${Math.max(1, Math.min(1440, request.workflow.scheduleIntervalMinutes))}M`;
  const manifest = [
    '<?xml version="1.0" encoding="UTF-16"?>',
    '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">',
    '  <RegistrationInfo>',
    `    <Description>ProxyForge automation scheduler (${escapeXml(request.workflow.name)})</Description>`,
    '  </RegistrationInfo>',
    '  <Triggers>',
    '    <TimeTrigger>',
    '      <Enabled>true</Enabled>',
    `      <Repetition><Interval>${interval}</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>`,
    '    </TimeTrigger>',
    '  </Triggers>',
    '  <Principals>',
    `    <Principal id="Author"><UserId>${escapeXml(windowsUser)}</UserId><LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal>`,
    '  </Principals>',
    '  <Settings>',
    '    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>',
    '    <RestartOnFailure><Interval>PT1M</Interval><Count>3</Count></RestartOnFailure>',
    '    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>',
    '  </Settings>',
    '  <Actions Context="Author">',
    '    <Exec>',
    '      <Command>node.exe</Command>',
    `      <Arguments>${escapeXml(schedulerCommand)}</Arguments>`,
    `      <WorkingDirectory>${escapeXml(installRoot)}</WorkingDirectory>`,
    '    </Exec>',
    '  </Actions>',
    '</Task>',
  ].join('\n');
  const installCommand = `schtasks /Create /TN "${taskName}" /XML "${installPath}" /F`;
  const startCommand = `schtasks /Run /TN "${taskName}"`;
  const statusCommand = `schtasks /Query /TN "${taskName}" /V /FO LIST`;
  const stopCommand = `schtasks /End /TN "${taskName}"`;
  const uninstallCommand = `schtasks /Delete /TN "${taskName}" /F`;
  const environmentNames = ['PROXYFORGE_AUTHORIZATION', 'PROXYFORGE_COOKIE', 'PROXYFORGE_API_KEY'];
  return {
    platform: 'windows-task-scheduler',
    serviceName: taskName,
    displayName: `ProxyForge Automation Scheduler (${request.workflow.name})`,
    installPath,
    statePath,
    logPath,
    agentCommand: schedulerCommand,
    installCommand,
    startCommand,
    statusCommand,
    stopCommand,
    uninstallCommand,
    manifest,
    environmentNames,
    restartPolicy: 'Task Scheduler RestartOnFailure interval PT1M count 3',
    schedulePolicy: `${interval} repetition with scheduler tick durable queue reconciliation`,
    requirements: buildServicePlanRequirements({
      installCommand,
      startCommand,
      statusCommand,
      stopCommand,
      uninstallCommand,
      statePath,
      schedulerCommand,
      manifest,
      environmentNames,
    }),
  };
}

function renderAutomationSchedulerServiceCommand(
  request: AutomationServiceLifecycleRequest,
  agentCommand: string,
  statePath: string,
  logPath: string,
) {
  return [
    agentCommand,
    'automation-scheduler-tick',
    `--project ${quoteArg(request.projectPath)}`,
    `--scope ${quoteArg(request.scopeAllowlist.join(','))}`,
    `--workflow ${quoteArg(request.workflow.id)}`,
    `--scheduler-state ${quoteArg(statePath)}`,
    `--log ${quoteArg(logPath)}`,
    '--execute',
    '--service-run',
    '--json',
  ].join(' ');
}

function buildServicePlanRequirements(input: {
  installCommand: string;
  startCommand: string;
  statusCommand: string;
  stopCommand: string;
  uninstallCommand: string;
  statePath: string;
  schedulerCommand: string;
  manifest: string;
  environmentNames: string[];
}): AutomationServiceInstallPlan['requirements'] {
  const environmentSource = `${input.manifest}\n${input.environmentNames.join('\n')}`;
  return {
    installCovered: /systemctl|schtasks|Register-ScheduledTask|Create/i.test(input.installCommand),
    startCovered: /start|Run/i.test(input.startCommand),
    statusCovered: /status|Query/i.test(input.statusCommand),
    stopCovered: /stop|End/i.test(input.stopCommand),
    uninstallCovered: /disable|Delete|rm -f|Unregister-ScheduledTask/i.test(input.uninstallCommand),
    durableStateCovered: /proxyforge|Automations|automation/i.test(input.statePath),
    schedulerTickCommandCovered: /automation-scheduler-tick/.test(input.schedulerCommand),
    secretEnvironmentCovered: /PROXYFORGE_AUTHORIZATION/.test(environmentSource)
      && /PROXYFORGE_COOKIE/.test(environmentSource)
      && /PROXYFORGE_API_KEY/.test(environmentSource),
  };
}

export function issuesFromAutomationExecutions(executions: AutomationExecution[]): Issue[] {
  return executions.flatMap((execution) => (execution.issue ? [execution.issue] : []));
}

function reconcileAutomationScheduler(
  state: AutomationSchedulerState,
  workflows: AutomationWorkflow[],
  now: Date,
): AutomationSchedulerState {
  const timestamp = now.toISOString();
  const workflowIds = new Set(workflows.map((workflow) => workflow.id));
  const retainedQueue = state.queue
    .filter((job) => workflowIds.has(job.workflowId) || job.status === 'complete' || job.status === 'blocked')
    .map((job) => expireSchedulerLease(job, now))
    .slice(-200);
  const queue = [...retainedQueue];

  for (const workflow of workflows) {
    if (!workflow.scheduleEnabled) continue;
    const scheduledFor = getWorkflowNextRunAt(workflow, now).toISOString();
    const hasOpenJob = queue.some((job) => job.workflowId === workflow.id && (job.status === 'queued' || job.status === 'leased'));
    const hasReceiptForSchedule = queue.some((job) => (
      job.workflowId === workflow.id
      && job.scheduledFor === scheduledFor
      && (job.status === 'complete' || job.status === 'blocked')
    ));
    const exists = hasOpenJob || hasReceiptForSchedule;
    if (exists) continue;
    queue.push({
      id: buildSchedulerJobId(workflow, scheduledFor),
      workflowId: workflow.id,
      workflowName: workflow.name,
      scheduledFor,
      status: 'queued',
      attempts: 0,
      createdAt: timestamp,
      updatedAt: timestamp,
      summary: `Queued ${workflow.name} for ${scheduledFor}.`,
    });
  }

  return {
    ...state,
    heartbeatAt: timestamp,
    updatedAt: timestamp,
    queue: queue.sort((left, right) => Date.parse(left.scheduledFor) - Date.parse(right.scheduledFor)).slice(-200),
  };
}

function expireSchedulerLease(job: AutomationSchedulerJob, now: Date): AutomationSchedulerJob {
  if (job.status !== 'leased' || !job.leaseExpiresAt || Date.parse(job.leaseExpiresAt) > now.getTime()) return job;
  return {
    ...job,
    status: 'queued',
    leaseId: undefined,
    leasedBy: undefined,
    leaseExpiresAt: undefined,
    updatedAt: now.toISOString(),
    summary: `Lease expired at ${job.leaseExpiresAt}; returned to queue.`,
  };
}

function isClaimableSchedulerJob(job: AutomationSchedulerJob, now: Date) {
  if (Date.parse(job.scheduledFor) > now.getTime()) return false;
  if (job.status === 'queued') return true;
  return job.status === 'leased' && Boolean(job.leaseExpiresAt) && Date.parse(job.leaseExpiresAt!) <= now.getTime();
}

function finishSchedulerJob(
  state: AutomationSchedulerState,
  jobId: string,
  status: 'complete' | 'blocked',
  updatedAt: string,
  executionId: string | undefined,
  summary: string | undefined,
): AutomationSchedulerState {
  return {
    ...state,
    updatedAt,
    queue: state.queue.map((job) => (
      job.id === jobId
        ? {
            ...job,
            status,
            executionId,
            updatedAt,
            summary,
          }
        : job
    )),
  };
}

function getWorkflowNextRunAt(workflow: AutomationWorkflow, now: Date) {
  if (workflow.nextRunAtIso && Number.isFinite(Date.parse(workflow.nextRunAtIso))) return new Date(workflow.nextRunAtIso);
  if (workflow.lastSchedulerRunAt && Number.isFinite(Date.parse(workflow.lastSchedulerRunAt))) {
    return addMinutes(new Date(workflow.lastSchedulerRunAt), workflow.scheduleIntervalMinutes);
  }
  const relative = /^\+(\d+)\s+minutes?$/i.exec(workflow.nextRunAt);
  if (relative) return addMinutes(now, Number(relative[1]));
  return now;
}

function buildSchedulerJobId(workflow: AutomationWorkflow, scheduledFor: string) {
  return `auto-job-${workflow.id}-${scheduledFor.replace(/[^0-9TZ]/g, '')}`;
}

function addMinutes(date: Date, minutes: number) {
  return new Date(date.getTime() + Math.max(1, minutes) * 60_000);
}

function makeStep(
  type: AutomationWorkflowStep['type'],
  label: string,
  target: string,
  throttleMs: number,
  maxRequests: number,
  requiresApproval: boolean,
): AutomationWorkflowStep {
  return {
    id: `${type}-${label.toLowerCase().replace(/[^a-z0-9]+/g, '-')}`,
    type,
    label,
    target,
    throttleMs,
    maxRequests,
    requiresApproval,
  };
}

function buildAutomationExchange(workflow: AutomationWorkflow, exchange: HttpExchange, completedAt: Date): HttpExchange {
  const body = JSON.stringify({
    workflow: workflow.name,
    status: 'complete',
    steps: workflow.steps.length,
    selectedExchange: exchange.id,
  }, null, 2);

  return {
    id: `automation-${completedAt.getTime()}`,
    method: 'POST',
    host: exchange.host,
    path: '/__proxyforge/automation',
    url: `https://${exchange.host}/__proxyforge/automation`,
    status: 200,
    length: body.length,
    mime: 'application/json',
    risk: workflow.steps.some((step) => step.type === 'active-scan') ? 'medium' : 'info',
    timing: Math.max(120, workflow.steps.length * 180),
    notes: `Automation workflow completed: ${workflow.name}`,
    source: 'scanner',
    time: completedAt.toLocaleTimeString([], { hour12: false }),
    requestRaw: `POST /__proxyforge/automation HTTP/2\nHost: ${exchange.host}\nContent-Type: application/json\nX-ProxyForge-Workflow: ${workflow.id}\n\n{"selectedExchange":"${exchange.id}"}`,
    responseRaw: `HTTP/2 200 OK\nContent-Type: application/json\nX-ProxyForge-Automation: true\n\n${body}`,
    tags: ['automation', workflow.trigger, workflow.steps.some((step) => step.type === 'active-scan') ? 'active-scan' : 'workflow'],
  };
}

function buildAutomationIssue(workflow: AutomationWorkflow, exchange: HttpExchange): Issue | undefined {
  if (!workflow.steps.some((step) => step.type === 'active-scan' || step.type === 'replay')) return undefined;
  return {
    id: `automation-${workflow.id}-${exchange.id}`,
    title: 'Automation workflow queued validation evidence',
    severity: workflow.steps.some((step) => step.type === 'active-scan') ? 'medium' : 'info',
    host: exchange.host,
    path: exchange.path,
    confidence: 'tentative',
    status: 'open',
    detail: `${workflow.name} ran against ${exchange.method} ${exchange.host}${exchange.path}, produced an auditable workflow log, and queued follow-up validation evidence.`,
    remediation: 'Review the workflow output, confirm authorization and side-effect expectations manually, and attach the generated evidence to the report only after validation.',
  };
}

function isInScope(host: string, workflowScope: string, scopeAllowlist: string[]) {
  const scopes = [...scopeAllowlist, ...workflowScope.split(/[,\s]+/)].map((scope) => scope.trim()).filter(Boolean);
  if (scopes.length === 0) return false;
  return scopes.some((scope) => {
    if (scope === '*' || scope === '*.*') return true;
    if (scope.includes('/')) return `${host}/`.startsWith(scope.replace(/^https?:\/\//, '').replace(/\*$/, ''));
    if (scope.startsWith('*.')) return host.endsWith(scope.slice(1)) || host === scope.slice(2);
    return host === scope || host.endsWith(`.${scope}`);
  });
}

function normalizeServiceName(value: string) {
  const normalized = String(value || 'proxyforge-automation-scheduler')
    .toLowerCase()
    .replace(/[^a-z0-9_.-]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return normalized || 'proxyforge-automation-scheduler';
}

function normalizePath(value: string) {
  return String(value || '/opt/ProxyForge').replace(/[\\/]$/, '');
}

function quoteArg(value: string) {
  const text = String(value);
  if (/^[A-Za-z0-9_./:@%+=,-]+$/.test(text)) return text;
  return `"${text.replace(/(["\\$`])/g, '\\$1')}"`;
}

function escapeXml(value: string) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function automationOperationalSecretSignals(value: string) {
  const signals = new Set<string>();
  if (/Authorization:\s*\S+|PROXYFORGE_AUTHORIZATION|Bearer\s+[A-Za-z0-9._:-]+/i.test(value)) signals.add('authorization-header');
  if (/Cookie:\s*\S+|PROXYFORGE_COOKIE|session=/i.test(value)) signals.add('cookie-header');
  if (/X-API-Key:\s*\S+|PROXYFORGE_API_KEY|api[-_]?key/i.test(value)) signals.add('x-api-key-header');
  return Array.from(signals).sort();
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  const text = String(value);
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${text.length.toString(16).padStart(8, '0')}`;
}
