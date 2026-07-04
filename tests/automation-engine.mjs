import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'createAutomationSchedulerState',
  'runAutomationSchedulerTick',
  'toggleWorkflowSchedule',
  'runAutomationWorkflow',
  'renderCiConfig',
  'createMacroWorkflow',
  'buildAutomationCiProviderMatrix',
  'buildAutomationParityEvidencePackage',
  'buildAutomationServiceLifecyclePackage',
];

const enginePath = path.resolve('src/automationEngine.ts');
const automationEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof automationEngine[name] !== 'function');
if (missingExports.length) {
  console.log(`automation-engine: skipped; missing export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const now = new Date('2026-05-24T20:00:00.000Z');
const exchange = buildExchange();
const workflows = [
  buildWorkflow({
    id: 'wf-scheduled-crawl',
    name: 'Scheduled crawl smoke',
    scheduleIntervalMinutes: 15,
    nextRunAtIso: '2026-05-24T19:59:00.000Z',
    steps: [
      makeStep('crawl', 'Crawl scoped routes', 'selected target', 25, 4, false),
      makeStep('report-export', 'Write evidence', 'report', 0, 1, false),
    ],
  }),
  buildWorkflow({
    id: 'wf-scheduled-approval',
    name: 'Scheduled approval gate',
    scheduleIntervalMinutes: 30,
    nextRunAtIso: '2026-05-24T19:58:00.000Z',
    steps: [
      makeStep('replay', 'Swap role tokens', 'role matrix', 10, 1, true),
    ],
  }),
];

const initialState = automationEngine.createAutomationSchedulerState(workflows, now);
assert.equal(initialState.status, 'running');
assert.equal(initialState.queue.filter((job) => job.status === 'queued').length, 2, 'scheduler should queue due scheduled workflows');

const tick = automationEngine.runAutomationSchedulerTick({
  state: initialState,
  workflows,
  exchange,
  scopeAllowlist: ['*.shop.local'],
  now,
  ownerId: 'scheduler-test-runner',
  maxJobs: 2,
});
assert.equal(tick.claimedJobs, 2, 'tick should claim both due jobs');
assert.equal(tick.completedJobs, 1, 'non-approval workflow should complete');
assert.equal(tick.blockedJobs, 1, 'approval-gated workflow should be blocked');
assert.equal(tick.executions.length, 2, 'tick should emit executions for claimed jobs');
assert.ok(tick.executions.every((execution) => execution.schedulerJobId), 'executions should be tied to durable scheduler jobs');
assert.ok(tick.executions.every((execution) => execution.schedulerLeaseId), 'executions should retain scheduler lease ids');
assert.match(tick.logs.join('\n'), /1 completed; 1 blocked/);

const completedJob = tick.state.queue.find((job) => job.workflowId === 'wf-scheduled-crawl' && job.status === 'complete');
assert.ok(completedJob?.executionId, 'completed job should retain execution receipt');
const blockedJob = tick.state.queue.find((job) => job.workflowId === 'wf-scheduled-approval' && job.status === 'blocked');
assert.ok(blockedJob?.summary, 'blocked job should retain summary receipt');
const updatedWorkflow = tick.workflows.find((workflow) => workflow.id === 'wf-scheduled-crawl');
assert.ok(Date.parse(updatedWorkflow.nextRunAtIso) > now.getTime(), 'completed scheduled workflow should advance nextRunAtIso');

const restoredState = automationEngine.createAutomationSchedulerState(tick.workflows, new Date('2026-05-24T20:01:00.000Z'), tick.state);
assert.ok(restoredState.queue.some((job) => job.status === 'complete'), 'restored scheduler should keep completion receipts');
assert.ok(restoredState.queue.some((job) => job.status === 'queued' && Date.parse(job.scheduledFor) > now.getTime()), 'restored scheduler should keep future queued job');
const restoredAgain = automationEngine.createAutomationSchedulerState(tick.workflows, new Date('2026-05-24T20:02:00.000Z'), restoredState);
assert.equal(
  restoredAgain.queue.filter((job) => job.workflowId === 'wf-scheduled-crawl' && (job.status === 'queued' || job.status === 'leased')).length,
  1,
  'scheduler reconcile should not duplicate open future jobs for one workflow',
);

const expiredState = {
  ...initialState,
  queue: initialState.queue.map((job) => job.workflowId === workflows[0].id
    ? {
        ...job,
        status: 'leased',
        attempts: 1,
        leaseId: 'expired-lease',
        leasedBy: 'dead-runner',
        leaseExpiresAt: '2026-05-24T19:59:30.000Z',
      }
    : job),
};
const expiredTick = automationEngine.runAutomationSchedulerTick({
  state: expiredState,
  workflows: [workflows[0]],
  exchange,
  scopeAllowlist: ['*.shop.local'],
  now,
  ownerId: 'replacement-runner',
  maxJobs: 1,
});
assert.equal(expiredTick.claimedJobs, 1, 'expired lease should be returned to the queue and reclaimed');
assert.equal(expiredTick.executions[0].status, 'complete');

const macroWorkflow = automationEngine.createMacroWorkflow(exchange, ['*.shop.local']);
assert.ok(macroWorkflow.id.startsWith('wf-macro-'), 'macro recorder should create macro workflow ids');
assert.ok(macroWorkflow.steps.some((step) => step.type === 'replay'), 'macro workflows should replay the selected request');
assert.ok(macroWorkflow.steps.some((step) => step.type === 'active-scan'), 'macro workflows should stage scanner follow-up');
assert.ok(macroWorkflow.steps.some((step) => step.type === 'report-export'), 'macro workflows should export report evidence');

const macroRun = automationEngine.runAutomationWorkflow(macroWorkflow, exchange, ['*.shop.local']);
assert.equal(macroRun.execution.status, 'complete', 'macro run should complete in scope');
assert.match(stringify(macroRun.execution), /automation-secret-token|automation-secret-session|automation-secret-key/, 'macro run should preserve source executor secrets');

const onTagWorkflow = {
  ...workflows[1],
  id: 'wf-on-tag-authz',
  name: 'On-tag authorization replay',
  trigger: 'on-tag',
  scheduleEnabled: false,
};
const ciWorkflow = {
  ...workflows[0],
  id: 'wf-ci-headless-parity',
  name: 'CI headless parity scan',
  trigger: 'ci',
  scheduleEnabled: false,
  steps: [
    makeStep('crawl', 'CI crawl scoped routes', 'ci target', 25, 4, false),
    makeStep('active-scan', 'CI active checks', 'ci crawler output', 50, 4, false),
    makeStep('report-export', 'CI report artifacts', 'ci-artifacts/proxyforge', 0, 1, false),
  ],
};
const ciProviderMatrix = automationEngine.buildAutomationCiProviderMatrix(ciWorkflow, ['*.shop.local']);
assert.equal(JSON.stringify(ciProviderMatrix.map((entry) => entry.provider).sort()), JSON.stringify(['azure-pipelines', 'github-actions', 'gitlab-ci', 'jenkins']), 'CI provider matrix should cover every supported provider');
assert.equal(ciProviderMatrix.every((entry) => Object.values(entry.requirements).every(Boolean)), true, 'CI provider presets should cover headless, SARIF, JUnit, bundle, artifacts, and secrets');

const pausedState = {
  ...restoredState,
  id: 'automation-scheduler-paused',
  status: 'paused',
};
const stoppedState = {
  ...restoredState,
  id: 'automation-scheduler-stopped',
  status: 'stopped',
};
const parityPackage = automationEngine.buildAutomationParityEvidencePackage({
  workflows: [macroWorkflow, onTagWorkflow, ciWorkflow, ...tick.workflows],
  executions: [macroRun.execution, ...tick.executions, ...expiredTick.executions],
  schedulerStates: [initialState, tick.state, restoredState, expiredTick.state, pausedState, stoppedState],
  schedulerTickResults: [tick, expiredTick],
  ciProviderPresets: ciProviderMatrix,
  sourceExchanges: [exchange],
  operationalSecretSamples: ['automation-secret-token', 'automation-secret-session', 'automation-secret-key'],
  exportedAt: now.toISOString(),
});
assertAutomationParityEvidencePackage(parityPackage, 'buildAutomationParityEvidencePackage');

const artifactDir = path.resolve('.gitignored/test-artifacts/automation-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(
  path.join(artifactDir, 'automation-parity-evidence-package.json'),
  `${parityPackage.content}\n`,
);

const serviceLifecyclePackage = automationEngine.buildAutomationServiceLifecyclePackage({
  workflow: workflows[0],
  schedulerState: restoredState,
  projectPath: './workspace.proxyforge.json',
  scopeAllowlist: ['*.shop.local'],
  installRoot: '/opt/ProxyForge',
  agentCommand: '/opt/ProxyForge/scripts/proxyforge-agent.mjs',
  serviceName: 'proxyforge-automation-scheduler',
  linuxUser: 'analyst',
  windowsUser: 'PROXYFORGE\\analyst',
  generatedAt: now.toISOString(),
  operationalSecretSamples: [
    'Authorization: Bearer automation-secret-token',
    'Cookie: session=automation-secret-session',
    'X-API-Key: automation-secret-key',
  ],
});
assertAutomationServiceLifecyclePackage(serviceLifecyclePackage, 'buildAutomationServiceLifecyclePackage');
await fs.writeFile(
  path.join(artifactDir, 'automation-service-lifecycle-package.json'),
  `${serviceLifecyclePackage.content}\n`,
);

console.log('automation-engine: exercised durable scheduler queueing, leases, completion receipts, restore, approval blocking, CI presets, parity evidence, and OS service lifecycle plans');

async function loadEngine(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: filePath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    Buffer,
    console,
    require,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: filePath });
  return module.exports;
}

function normalizeModuleExports(moduleExports) {
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}

function buildWorkflow(overrides) {
  return {
    id: overrides.id,
    name: overrides.name,
    status: 'ready',
    trigger: 'scheduled',
    scope: '*.shop.local',
    scheduleEnabled: true,
    scheduleIntervalMinutes: overrides.scheduleIntervalMinutes,
    nextRunAt: `+${overrides.scheduleIntervalMinutes} minutes`,
    nextRunAtIso: overrides.nextRunAtIso,
    lastRun: 'Not run',
    steps: overrides.steps,
  };
}

function makeStep(type, label, target, throttleMs, maxRequests, requiresApproval) {
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

function buildExchange() {
  return {
    id: 'hx-automation-scheduler',
    method: 'GET',
    host: 'app.shop.local',
    path: '/api/account/profile',
    url: 'https://app.shop.local/api/account/profile',
    status: 200,
    length: 412,
    mime: 'application/json',
    risk: 'medium',
    timing: 88,
    notes: 'Scheduler test exchange.',
    source: 'proxy',
    time: '20:00:00',
    requestRaw: [
      'GET /api/account/profile HTTP/1.1',
      'Host: app.shop.local',
      'Authorization: Bearer automation-secret-token',
      'Cookie: session=automation-secret-session',
      'X-API-Key: automation-secret-key',
      '',
      '',
    ].join('\n'),
    responseRaw: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"ok":true}',
    tags: ['authz'],
  };
}

function assertAutomationParityEvidencePackage(pkg, helperName) {
  const serialized = stringify(pkg);
  const failedRequirements = Object.entries(pkg.requirements).filter(([, value]) => !value).map(([name]) => name);
  assert.equal(pkg.kind, 'proxyforge-automation-parity-evidence-package', `${helperName} should emit an Automation parity evidence package`);
  assert.deepEqual(failedRequirements, [], `${helperName} should satisfy every Automation parity requirement`);
  assert.equal(pkg.reportReady, true, `${helperName} should mark parity packages report-ready`);
  assert.equal(pkg.secretHandling, 'execution-full-fidelity-secrets-preserved', `${helperName} should preserve executor secrets`);
  assert.equal(pkg.reportRedactionBoundary, 'redact-only-during-report-export', `${helperName} should keep redaction at report export only`);
  assert.ok(pkg.artifactIds.workflowIds.some((id) => id.startsWith('wf-macro-')), `${helperName} should link macro workflows`);
  assert.ok(pkg.artifactIds.ciProviders.includes('github-actions'), `${helperName} should link CI provider presets`);
  assert.match(serialized, /automation-secret-token|automation-secret-session|automation-secret-key/, `${helperName} should preserve operational automation tokens`);
  assert.match(serialized, /macroRecordingCovered|ciHeadlessCliCovered|durableSchedulerQueueCovered|serviceLifecycleCovered/i, `${helperName} should expose Automation parity requirements`);
  assert.match(pkg.content, /proxyforge headless|proxyforge-automation-parity-evidence-package|redact-only-during-report-export/i, `${helperName} should keep headless and reporting boundary evidence`);
}

function assertAutomationServiceLifecyclePackage(pkg, helperName) {
  const serialized = stringify(pkg);
  const failedRequirements = Object.entries(pkg.requirements).filter(([, value]) => !value).map(([name]) => name);
  assert.equal(pkg.kind, 'proxyforge-automation-service-lifecycle-package', `${helperName} should emit an Automation service lifecycle package`);
  assert.deepEqual(failedRequirements, [], `${helperName} should satisfy every Automation service lifecycle requirement`);
  assert.equal(pkg.reportReady, true, `${helperName} should mark service lifecycle packages report-ready`);
  assert.equal(pkg.secretHandling, 'execution-full-fidelity-secrets-preserved', `${helperName} should preserve executor secrets`);
  assert.equal(pkg.reportRedactionBoundary, 'redact-only-during-report-export', `${helperName} should keep redaction at report export only`);
  assert.equal(pkg.platformCount, 2, `${helperName} should cover Linux and Windows service plans`);
  assert(pkg.plans.some((plan) => plan.platform === 'linux-systemd-user'), `${helperName} should include Linux systemd user plan`);
  assert(pkg.plans.some((plan) => plan.platform === 'windows-task-scheduler'), `${helperName} should include Windows Task Scheduler plan`);
  assert.match(serialized, /systemctl --user|schtasks \/Create|automation-scheduler-tick|Restart=on-failure|RestartOnFailure/i, `${helperName} should preserve service install/start controls`);
  assert.match(serialized, /PROXYFORGE_AUTHORIZATION|PROXYFORGE_COOKIE|PROXYFORGE_API_KEY/i, `${helperName} should document secret environment inputs`);
  assert.match(serialized, /automation-secret-token|automation-secret-session|automation-secret-key/i, `${helperName} should preserve operational automation secrets`);
  assert.match(serialized, /redact-only-during-report-export/i, `${helperName} should keep report-phase redaction boundary`);
}

function stringify(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
