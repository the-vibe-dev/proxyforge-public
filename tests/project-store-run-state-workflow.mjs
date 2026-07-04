import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { ProjectStore } = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-run-state-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'run-state-workflow.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

let store;
let reopened;
let restored;

const exchange = {
  id: 'hx-run-state',
  method: 'POST',
  url: 'https://agent.fixture.local/api/run_state?token=run_state_secret',
  host: 'agent.fixture.local',
  path: '/api/run_state?token=run_state_secret',
  status: 202,
  length: 77,
  mime: 'application/json',
  risk: 'medium',
  timing: 33,
  notes: 'Run state exchange preserves run_state_secret for agent replay.',
  source: 'automation',
  time: '2026-05-26T13:00:00.000Z',
  requestRaw: [
    'POST /api/run_state?token=run_state_secret HTTP/1.1',
    'Host: agent.fixture.local',
    'Authorization: Bearer run-state-token',
    'Cookie: session=run_state_session',
    'X-API-Key: run_state_key',
    'Content-Type: application/json',
    '',
    '{"automation":"run_state_secret","role":"support_admin"}',
  ].join('\r\n'),
  responseRaw: [
    'HTTP/1.1 202 Accepted',
    'Content-Type: application/json',
    '',
    '{"ok":true,"token":"run-state-token"}',
  ].join('\r\n'),
  tags: ['automation', 'run-state'],
};

try {
  store = await ProjectStore.create(projectDir, {
    projectName: 'Project Store Run State Workflow',
    projectId: 'project-store-run-state-workflow',
  });

  await store.addAutomationRun({
    id: 'automation-run-state',
    workflowId: 'wf-run-state',
    workflowName: 'Run state macro',
    status: 'complete',
    trigger: 'scheduled',
    startedAt: '2026-05-26T13:00:00.000Z',
    completedAt: '2026-05-26T13:00:03.000Z',
    durationMs: 3000,
    totalRequests: 1,
    logs: [
      'Replayed run_state_secret with Authorization: Bearer run-state-token.',
      'Scheduler lease scheduler-lease-run-state completed.',
    ],
    exchange,
    issue: {
      id: 'issue-run-state',
      title: 'Automation run preserved replay material',
      type: 'automation',
      severity: 'medium',
      confidence: 'firm',
      status: 'open',
      host: 'agent.fixture.local',
      path: '/api/run_state',
      detail: 'Automation issue keeps run_state_secret and run_state_key until report export.',
      remediation: 'Review workflow-scoped replay and redact only report-phase exports.',
      evidenceRefs: [
        { kind: 'automation-run', id: 'automation-run-state', label: 'Automation run', source: 'automation' },
        { kind: 'http-exchange', id: exchange.id, label: 'Automation replay exchange', source: 'automation' },
      ],
      source: 'automation',
    },
    operationalRawMaterial: {
      sourceExchangeId: exchange.id,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    },
    schedulerJobId: 'scheduler-job-run-state',
    schedulerLeaseId: 'scheduler-lease-run-state',
    ciProvider: 'github-actions',
    ciConfig: 'env: RUN_STATE_TOKEN=run_state_secret',
    tags: ['automation', 'agent-drivable'],
    notes: 'Automation run survives restart for agent scheduling.',
  });

  await store.addAiRun({
    id: 'ai-run-state',
    providerId: 'codex',
    task: 'replay-plan',
    status: 'complete',
    model: 'configured-default',
    startedAt: '2026-05-26T13:01:00.000Z',
    completedAt: '2026-05-26T13:01:04.000Z',
    summary: 'AI drafted a replay plan using run_state_secret.',
    prompt: 'Use Authorization: Bearer run-state-token and Cookie: session=run_state_session to explain run_state_secret.',
    output: 'Stage Repeater, preserve run_state_secret, then queue Scanner and report evidence after operator approval.',
    evidenceCount: 2,
    command: 'codex exec --sandbox read-only -',
    providerLabel: 'Codex',
    contextDigest: 'ctx-run-state',
    usage: {
      promptTokens: 18,
      completionTokens: 22,
      totalTokens: 40,
      estimatedCostUsd: 0.001,
      latencyMs: 4000,
      source: 'estimated',
    },
    streamEvents: [
      { id: 'ai-stream-prompt', at: '2026-05-26T13:01:00.000Z', source: 'prompt', text: 'run_state_secret prompt accepted' },
      { id: 'ai-stream-complete', at: '2026-05-26T13:01:04.000Z', source: 'complete', text: 'run_state_secret plan complete' },
    ],
    promptEvaluation: {
      score: 100,
      checks: [{ label: 'raw material preserved', status: 'ready', detail: 'run_state_secret present' }],
    },
    suggestedActions: [
      { id: 'ai-action-stage-repeater', kind: 'stage-repeater', label: 'Stage in Repeater', detail: 'Use run_state_secret', target: 'POST agent.fixture.local/api/run_state', priority: 'medium' },
    ],
    tags: ['ai', 'agent-drivable'],
    notes: 'AI output remains raw for executor workflows.',
  });

  await store.addExtensionRun({
    id: 'extension-run-state',
    extensionId: 'ext-run-state',
    extensionName: 'Run State Header Lens',
    hook: 'request-editor',
    status: 'complete',
    target: 'POST agent.fixture.local/api/run_state',
    startedAt: '2026-05-26T13:02:00.000Z',
    completedAt: '2026-05-26T13:02:01.000Z',
    summary: 'Extension captured run_state_key from the request editor hook.',
    logs: [
      'request-editor saw X-API-Key: run_state_key.',
      'Authorization: Bearer run-state-token stayed available to executor.',
    ],
    exchange: {
      ...exchange,
      id: 'hx-extension-run-state',
      source: 'extension',
      tags: ['extension', 'request-editor'],
    },
    issue: {
      id: 'issue-extension-run-state',
      title: 'Extension run preserved hook evidence',
      type: 'extension-runtime',
      severity: 'low',
      confidence: 'firm',
      status: 'open',
      host: 'agent.fixture.local',
      path: '/api/run_state',
      detail: 'Extension hook evidence keeps run_state_key for executor review.',
      remediation: 'Audit extension hook output before report export.',
      evidenceRefs: [
        { kind: 'extension-run', id: 'extension-run-state', label: 'Extension hook run', source: 'extensions' },
        { kind: 'http-exchange', id: 'hx-extension-run-state', label: 'Extension hook exchange', source: 'extensions' },
      ],
      source: 'extension',
    },
    tags: ['extension', 'agent-drivable'],
    notes: 'Extension run survives restart for compatibility triage.',
  });

  store.close();
  store = null;

  reopened = await ProjectStore.open(projectDir);
  let stats = reopened.stats();
  assert.equal(stats.automationRunCount, 1);
  assert.equal(stats.aiRunCount, 1);
  assert.equal(stats.extensionRunCount, 1);
  assert.equal(stats.exchangeCount, 2);
  assert.equal(stats.issueCount, 2);
  assert(stats.aiPromptBytes > 0);
  assert(stats.aiOutputBytes > 0);

  const automationRows = reopened.listAutomationRuns({ text: 'run_state_secret', limit: 5 });
  assert.equal(automationRows.length, 1);
  const automationRun = reopened.getAutomationRun('automation-run-state');
  assert(automationRun);
  assert.match(JSON.stringify(automationRun.operationalRawMaterial), /run_state_secret|run_state_key/);
  assert.match(automationRun.exchange.requestRaw.toString('utf8'), /run_state_key/);
  assert.match(automationRun.issue.detail, /run_state_secret/);

  const aiRows = reopened.listAiRuns({ text: 'run_state_secret', limit: 5 });
  assert.equal(aiRows.length, 1);
  const aiRun = reopened.getAiRun('ai-run-state');
  assert(aiRun);
  assert.match(aiRun.prompt.toString('utf8'), /run_state_session/);
  assert.match(aiRun.output.toString('utf8'), /run_state_secret/);
  assert.equal(aiRun.suggestedActions.length, 1);

  const extensionRows = reopened.listExtensionRuns({ text: 'run_state_key', limit: 5 });
  assert.equal(extensionRows.length, 1);
  const extensionRun = reopened.getExtensionRun('extension-run-state');
  assert(extensionRun);
  assert.match(extensionRun.logs.join('\n'), /run_state_key/);
  assert.match(extensionRun.exchange.requestRaw.toString('utf8'), /run_state_key/);
  assert.match(extensionRun.issue.detail, /run_state_key/);

  const backup = await reopened.createBackup(path.join(artifactRoot, 'backups'), { label: 'run-state' });
  assert.equal(backup.stats.automationRunCount, 1);
  assert.equal(backup.stats.aiRunCount, 1);
  assert.equal(backup.stats.extensionRunCount, 1);
  reopened.close();
  reopened = null;

  restored = await ProjectStore.open(backup.backupDir);
  stats = restored.stats();
  assert.equal(stats.automationRunCount, 1);
  assert.equal(stats.aiRunCount, 1);
  assert.equal(stats.extensionRunCount, 1);
  assert.match(restored.getAiRun('ai-run-state').output.toString('utf8'), /run_state_secret/);
  assert.match(restored.getAutomationRun('automation-run-state').exchange.requestRaw.toString('utf8'), /run_state_key/);
  assert.match(restored.getExtensionRun('extension-run-state').exchange.requestRaw.toString('utf8'), /run_state_key/);

  console.log(`project-store-run-state-workflow: persisted automation, AI, and extension run state with raw secrets, issue/exchange links, search, and backup restore from ${projectDir}`);
} finally {
  restored?.close();
  reopened?.close();
  store?.close();
}
