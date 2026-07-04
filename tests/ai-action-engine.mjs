import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = ['buildAiActionExecutionPackage', 'buildAiParityEvidencePackage'];

const enginePath = path.resolve('src/aiActionEngine.ts');
const aiActionEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof aiActionEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `ai-action-engine: missing export(s): ${missingExports.join(', ')}`);

const sample = buildSampleContext();

const replayPackage = aiActionEngine.buildAiActionExecutionPackage({
  action: sample.replayAction,
  aiRun: sample.aiRun,
  exchange: sample.exchange,
  scopeAllowlist: ['*.shop.local'],
  now: sample.now,
});
const replayContent = JSON.parse(replayPackage.content);

assert.equal(replayPackage.status, 'completed', 'stage replay action should complete as a UI handoff');
assert.equal(replayPackage.mode, 'ui-controlled', 'stage replay action should use UI-controlled execution');
assert.equal(replayPackage.targetTool, 'repeater', 'stage replay action should target Repeater');
assert.equal(replayPackage.trafficSent, false, 'stage replay action should not send traffic');
assert.equal(replayPackage.requestCount, 0, 'stage replay action should not count backend requests');
assert(replayPackage.artifacts.includes('replay-matrix-staging'), 'stage replay action should create replay matrix artifact');
assert(replayPackage.artifacts.includes('repeater-workspace'), 'stage replay action should create repeater workspace artifact');
assert.equal(replayContent.kind, 'proxyforge-ai-action-execution', 'package content should use the AI action execution kind');
assert.equal(replayContent.execution.mode, 'ui-controlled');
assert.equal(replayContent.execution.trafficSent, false);
assert.equal(replayContent.execution.requestCount, 0);

const queuePackage = aiActionEngine.buildAiActionExecutionPackage({
  action: sample.queueAction,
  aiRun: sample.aiRun,
  exchange: sample.exchange,
  scopeAllowlist: ['shop.local'],
  activeScanCheckCount: 7,
  now: sample.now,
});

assert.equal(queuePackage.status, 'queued', 'active scan action should queue work instead of completing immediately');
assert.equal(queuePackage.targetTool, 'scanner', 'active scan action should target Scanner');
assert.equal(queuePackage.trafficSent, false, 'active scan action should not send traffic directly');
assert.equal(queuePackage.requestCount, 7, 'active scan action should inherit active scan check count');
assert.equal(queuePackage.maxRequests, 7, 'active scan action should expose the same max request cap');
assert(queuePackage.artifacts.includes('scanner-audit-queue-item'), 'active scan action should create scanner queue artifact');

const blockedPackage = aiActionEngine.buildAiActionExecutionPackage({
  action: sample.outOfScopeAction,
  aiRun: sample.aiRun,
  exchange: sample.outOfScopeExchange,
  scopeAllowlist: ['shop.local'],
  now: sample.now,
});

assert.equal(blockedPackage.status, 'blocked', 'out-of-scope action should be blocked');
assert.equal(blockedPackage.scopePassed, false, 'out-of-scope action should fail scope');
assert.equal(blockedPackage.trafficSent, false, 'out-of-scope action should not send traffic');
assert(blockedPackage.artifacts.includes('blocked-ai-action-execution-package'), 'blocked action should produce blocked execution artifact');

const secretBearingPackage = aiActionEngine.buildAiActionExecutionPackage({
  action: sample.replayAction,
  aiRun: sample.aiRun,
  exchange: sample.exchangeWithSecrets,
  scopeAllowlist: ['*.shop.local'],
  now: sample.now,
});

assert.match(secretBearingPackage.content, /Bearer secret-token/i, 'operational package content should preserve Authorization secrets');
assert.match(secretBearingPackage.content, /session=abc123/i, 'operational package content should preserve Cookie secrets');
assert.match(secretBearingPackage.content, /Authorization:/i, 'operational package content should preserve Authorization headers');
assert.match(secretBearingPackage.content, /Cookie:/i, 'operational package content should preserve Cookie headers');

const parityContext = buildAiParityContext(sample, {
  replayPackage,
  queuePackage,
  blockedPackage,
  secretBearingPackage,
});
const parityPackage = aiActionEngine.buildAiParityEvidencePackage(parityContext);
const parityContent = JSON.parse(parityPackage.content);

assert.equal(parityPackage.kind, 'proxyforge-ai-parity-evidence-package');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportReady, true, 'AI parity package should be report-ready when all requirements are covered');
assert(Object.values(parityPackage.requirements).every(Boolean), 'all AI parity requirements should be true');
assert.equal(parityPackage.providerCount, 3);
assert.equal(parityPackage.providerRunCount, 3);
assert.equal(parityPackage.promptTemplateCount, 4);
assert.equal(parityPackage.baselineCount, 2);
assert.equal(parityPackage.comparisonCount, 2);
assert.equal(parityPackage.benchmarkRunCount, 1);
assert.equal(parityPackage.actionExecutionPackageCount, 4);
assert.equal(parityContent.kind, 'proxyforge-ai-parity-evidence-package');
assert.match(parityPackage.content, /Codex/i, 'AI parity package should preserve Codex provider evidence');
assert.match(parityPackage.content, /Claude/i, 'AI parity package should preserve Claude provider evidence');
assert.match(parityPackage.content, /OpenAI-compatible Local/i, 'AI parity package should preserve local OpenAI-compatible provider evidence');
assert.match(parityPackage.content, /Bearer secret-token/i, 'AI parity package should preserve bearer secrets until report export');
assert.match(parityPackage.content, /session=abc123/i, 'AI parity package should preserve cookie secrets until report export');
assert.match(parityPackage.content, /reportRedactionBoundary/i, 'AI parity package should state report-phase redaction boundary');

const artifactDir = path.resolve('.gitignored/test-artifacts/ai-action-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'ai-parity-evidence-package.json'), parityPackage.content);

console.log('ai-action-engine: exercised controlled replay, active-scan queueing, scope blocking, full-fidelity package content, and AI parity evidence');

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

function buildSampleContext() {
  const now = '2026-05-24T22:10:00.000Z';
  const aiRun = {
    id: 'ai-run-17',
    providerId: 'codex',
    task: 'triage',
    status: 'complete',
    model: 'codex-test',
    startedAt: '2026-05-24T22:09:00.000Z',
    completedAt: now,
    summary: 'Replay authorization and queue active scan checks.',
    output: 'Stage replay matrix and scanner queue.',
    evidenceCount: 1,
    contextDigest: 'ctx-test-digest',
  };
  const replayAction = {
    id: 'act-replay-matrix',
    kind: 'stage-replay-matrix',
    label: 'Stage replay matrix',
    detail: 'Prepare role-boundary replay permutations.',
    target: 'https://app.shop.local/api/refunds',
    priority: 'high',
  };
  const queueAction = {
    id: 'act-queue-scan',
    kind: 'queue-active-scan',
    label: 'Queue active scan',
    detail: 'Queue scoped audit checks.',
    target: 'https://app.shop.local/api/refunds',
    priority: 'medium',
  };
  const outOfScopeAction = {
    id: 'act-out-of-scope',
    kind: 'stage-repeater',
    label: 'Stage out-of-scope request',
    detail: 'This target should not pass project scope.',
    target: 'https://billing.other.test/admin',
    priority: 'medium',
  };
  const exchange = {
    id: 'hx-refund-role-boundary',
    method: 'POST',
    host: 'app.shop.local',
    path: '/api/refunds',
    url: 'https://app.shop.local/api/refunds',
    status: 403,
    length: 420,
    mime: 'application/json',
    risk: 'high',
    timing: 121,
    source: 'repeater',
    time: '22:08:30',
    requestRaw: 'POST /api/refunds HTTP/2\nHost: app.shop.local\n\namount=100',
    responseRaw: 'HTTP/2 403 Forbidden\nContent-Type: application/json\n\n{"role":"viewer"}',
    notes: 'Role boundary replay candidate.',
    tags: ['authz', 'replay'],
  };
  const exchangeWithSecrets = {
    ...exchange,
    requestRaw: 'POST /api/refunds HTTP/2\nHost: app.shop.local\nAuthorization: Bearer secret-token\nCookie: session=abc123\n\namount=100',
  };
  const outOfScopeExchange = {
    ...exchange,
    id: 'hx-other-admin',
    host: 'billing.other.test',
    path: '/admin',
    url: 'https://billing.other.test/admin',
    requestRaw: 'GET /admin HTTP/2\nHost: billing.other.test\n\n',
  };

  return {
    now,
    aiRun,
    replayAction,
    queueAction,
    outOfScopeAction,
    exchange,
    exchangeWithSecrets,
    outOfScopeExchange,
  };
}

function buildAiParityContext(sample, packages) {
  const checks = [
    { label: 'Scope boundary', status: 'ready', detail: 'Prompt references scope.' },
    { label: 'Evidence request', status: 'ready', detail: 'Prompt anchors on raw request and response evidence.' },
    { label: 'Safety gates', status: 'ready', detail: 'Prompt asks for non-destructive scoped next steps.' },
    { label: 'Actionable output', status: 'ready', detail: 'Prompt asks for next actions.' },
  ];
  const providerConfigs = [
    {
      id: 'codex',
      label: 'Codex',
      mode: 'cli',
      enabled: true,
      model: 'codex-test-model',
      command: 'codex',
      args: ['exec', '--ephemeral', '-'],
      timeoutMs: 90000,
    },
    {
      id: 'claude',
      label: 'Claude',
      mode: 'cli',
      enabled: true,
      model: 'claude-test-model',
      command: 'claude',
      args: ['--print', '--no-session-persistence'],
      timeoutMs: 90000,
    },
    {
      id: 'local',
      label: 'OpenAI-compatible Local',
      mode: 'http',
      enabled: true,
      model: 'local-security-model',
      endpoint: 'http://127.0.0.1:11434/v1/chat/completions',
      apiKeyEnv: 'PROXYFORGE_AI_KEY',
      timeoutMs: 60000,
      inputCostPerMillionTokens: 0.25,
      outputCostPerMillionTokens: 0.5,
    },
  ];
  const providerRuns = providerConfigs.map((provider, index) => ({
    id: `ai-run-${provider.id}`,
    providerId: provider.id,
    task: index === 1 ? 'replay-plan' : 'triage',
    status: 'complete',
    model: provider.model,
    startedAt: '2026-05-24T22:09:00.000Z',
    completedAt: sample.now,
    summary: `${provider.label} completed scoped analysis.`,
    output: `${provider.label} reviewed POST /api/refunds and preserved Authorization: Bearer secret-token with Cookie: session=abc123 for executor use.`,
    evidenceCount: 1,
    command: provider.mode === 'cli' ? provider.command : provider.endpoint,
    providerLabel: provider.label,
    prompt: `Scope: *.shop.local\nrequestRaw:\n${sample.exchangeWithSecrets.requestRaw}\nresponseRaw:\n${sample.exchange.responseRaw}\nReturn scoped, non-destructive next steps.`,
    contextDigest: 'ctx-test-digest',
    usage: {
      promptTokens: 120 + index,
      completionTokens: 40 + index,
      totalTokens: 160 + (index * 2),
      estimatedCostUsd: 0.001 + index / 10000,
      latencyMs: 200 + index,
      source: provider.mode === 'http' ? 'provider' : 'estimated',
    },
    streamEvents: [
      { id: `stream-${provider.id}-prompt`, at: sample.now, source: 'prompt', text: `Prompt sent to ${provider.label}` },
      { id: `stream-${provider.id}-body`, at: sample.now, source: provider.mode === 'http' ? 'http' : 'stdout', text: `${provider.label} provider returned analysis.` },
      { id: `stream-${provider.id}-complete`, at: sample.now, source: 'complete', text: `${provider.label} provider completed.` },
    ],
    promptEvaluation: {
      score: 100,
      providerId: provider.id,
      model: provider.model,
      checks,
      recommendations: [],
    },
    suggestedActions: [sample.replayAction, sample.queueAction],
  }));
  const promptTemplates = [
    makeTemplate('tpl-triage', 'triage', 'Traffic triage'),
    makeTemplate('tpl-replay', 'replay-plan', 'Replay planning'),
    makeTemplate('tpl-exploit', 'exploit-review', 'Exploit review'),
    makeTemplate('tpl-report', 'report-draft', 'Report draft'),
  ];
  const evaluationBaselines = [
    {
      id: 'baseline-codex-triage',
      name: 'Codex scoped triage',
      providerId: 'codex',
      providerLabel: 'Codex',
      model: 'codex-test-model',
      task: 'triage',
      prompt: promptTemplates[0].prompt,
      contextDigest: 'ctx-test-digest',
      score: 96,
      usage: providerRuns[0].usage,
      checks,
      notes: 'Expected scoped triage baseline.',
      createdAt: sample.now,
      updatedAt: sample.now,
    },
    {
      id: 'baseline-claude-replay',
      name: 'Claude replay plan',
      providerId: 'claude',
      providerLabel: 'Claude',
      model: 'claude-test-model',
      task: 'replay-plan',
      prompt: promptTemplates[1].prompt,
      contextDigest: 'ctx-test-digest',
      score: 94,
      usage: providerRuns[1].usage,
      checks,
      notes: 'Expected replay planning baseline.',
      createdAt: sample.now,
      updatedAt: sample.now,
    },
  ];
  const promptComparisons = [
    makeComparison('comparison-codex', evaluationBaselines[0], 98, 2, providerRuns[0].usage),
    makeComparison('comparison-local', {
      ...evaluationBaselines[0],
      id: 'baseline-local-triage',
      providerId: 'local',
      providerLabel: 'OpenAI-compatible Local',
      model: 'local-security-model',
    }, 95, -1, providerRuns[2].usage),
  ];
  const benchmarkRuns = [
    {
      id: 'benchmark-ai-parity',
      createdAt: sample.now,
      projectName: 'Retail API Assessment',
      projectSavedAt: sample.now,
      providerCount: 3,
      baselineCount: 2,
      resultCount: 2,
      averageScore: 96.5,
      improvedCount: 1,
      regressedCount: 0,
      unbaselinedCount: 0,
      results: promptComparisons.map((comparison, index) => ({
        ...comparison,
        baselineName: evaluationBaselines[Math.min(index, evaluationBaselines.length - 1)].name,
        baselineScore: evaluationBaselines[Math.min(index, evaluationBaselines.length - 1)].score,
        projectName: 'Retail API Assessment',
        contextDigest: 'ctx-test-digest',
      })),
      notes: 'Replay benchmark over saved baselines.',
    },
  ];

  return {
    providerConfigs,
    providerRuns,
    promptTemplates,
    evaluationBaselines,
    promptComparisons,
    benchmarkRuns,
    actionExecutionPackages: [
      packages.replayPackage,
      packages.queuePackage,
      packages.blockedPackage,
      packages.secretBearingPackage,
    ],
    operationalSecretSamples: ['secret-token', 'session=abc123'],
    exportedAt: sample.now,
  };
}

function makeTemplate(id, task, title) {
  return {
    id,
    task,
    title,
    prompt: `${title}: preserve scope, raw request/response evidence, non-destructive gates, and report-export-only redaction.`,
    updatedAt: '2026-05-24T22:10:00.000Z',
  };
}

function makeComparison(id, baseline, score, scoreDelta, usage) {
  return {
    id,
    createdAt: '2026-05-24T22:10:00.000Z',
    baselineId: baseline.id,
    providerId: baseline.providerId,
    providerLabel: baseline.providerLabel,
    model: baseline.model,
    task: baseline.task,
    score,
    scoreDelta,
    promptTokens: usage.promptTokens,
    estimatedCostUsd: usage.estimatedCostUsd,
    checkDelta: ['Scope boundary ready', 'Safety gates ready'],
    verdict: scoreDelta >= 0 ? 'improved' : 'similar',
    notes: 'Provider comparison preserves token and cost accounting.',
  };
}
