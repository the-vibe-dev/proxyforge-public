import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { ProjectStore } = require('../dist-electron/projectStore.js');
const { ProjectStoreRunStateRecorder } = require('../dist-electron/runStatePersistence.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-live-run-state-wiring', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'live-run-state.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

let recorder;
let reopened;

const exchange = {
  id: 'hx-live-run-state',
  method: 'POST',
  url: 'https://agent-live.fixture.local/api/execute?token=live_run_secret',
  host: 'agent-live.fixture.local',
  path: '/api/execute?token=live_run_secret',
  status: 200,
  length: 96,
  mime: 'application/json',
  risk: 'medium',
  timing: 41,
  notes: 'Live path execution kept Authorization and X-API-Key values.',
  source: 'automation',
  time: '2026-05-26T15:00:00.000Z',
  requestRaw: [
    'POST /api/execute?token=live_run_secret HTTP/1.1',
    'Host: agent-live.fixture.local',
    'Authorization: Bearer live-run-token',
    'Cookie: session=live_run_session',
    'X-API-Key: live_run_key',
    'Content-Type: application/json',
    '',
    '{"action":"collect","token":"live_run_secret"}',
  ].join('\r\n'),
  responseRaw: [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json',
    '',
    '{"ok":true,"secret":"live_run_secret"}',
  ].join('\r\n'),
  tags: ['automation', 'agent', 'live-run-state'],
};

try {
  recorder = new ProjectStoreRunStateRecorder(projectDir, {
    projectName: 'Live Run State Wiring',
    projectId: 'live-run-state-wiring',
  });

  const automationResult = await recorder.recordAutomationRun({
    id: 'auto-live-run-state',
    workflowId: 'wf-live-run-state',
    workflowName: 'Agent live collection',
    status: 'complete',
    trigger: 'manual',
    startedAt: '2026-05-26T15:00:00.000Z',
    completedAt: '2026-05-26T15:00:02.000Z',
    durationMs: 2000,
    totalRequests: 1,
    logs: [
      'Collected Authorization: Bearer live-run-token.',
      'Collected X-API-Key: live_run_key.',
    ],
    exchange,
    issue: {
      id: 'issue-live-run-state',
      title: 'Live run state retained executor evidence',
      severity: 'medium',
      confidence: 'firm',
      status: 'open',
      host: 'agent-live.fixture.local',
      path: '/api/execute',
      detail: 'The live execution path retains live_run_secret and live_run_key until report export.',
      remediation: 'Keep raw execution material in Project Store and redact only during report export.',
    },
    operationalRawMaterial: {
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      executorToken: 'live-run-token',
      executorKey: 'live_run_key',
      redactionBoundary: 'report-only',
    },
    ciProvider: 'github-actions',
    ciConfig: 'PROXYFORGE_AUTHORIZATION=Bearer live-run-token\nPROXYFORGE_API_KEY=live_run_key',
  });
  assert.equal(automationResult.stats.automationRunCount, 1);

  const aiResult = await recorder.recordAiRun({
    id: 'ai-live-run-state',
    providerId: 'codex',
    task: 'replay-plan',
    status: 'complete',
    model: 'configured-default',
    startedAt: '2026-05-26T15:00:03.000Z',
    completedAt: '2026-05-26T15:00:04.000Z',
    summary: 'Codex staged live agent replay plan',
    output: 'Replay the live request with Authorization: Bearer live-run-token and live_run_key preserved.',
    prompt: JSON.stringify({
      operatorPrompt: 'Use full executor material for replay.',
      context: {
        exchanges: [exchange],
        rawCredential: 'live_run_secret',
      },
      reportRedactionBoundary: 'redact-only-during-report-export',
    }, null, 2),
    evidenceCount: 1,
    command: 'codex exec',
    providerLabel: 'Codex',
    contextDigest: 'ctx-live-run-state',
    usage: { totalTokens: 120, source: 'estimated' },
    streamEvents: [{ id: 'stream-live', source: 'complete', text: 'complete' }],
    suggestedActions: [{ id: 'act-live', kind: 'stage-repeater', target: exchange.url }],
  });
  assert.equal(aiResult.stats.aiRunCount, 1);

  const extensionResult = await recorder.recordExtensionRun({
    id: 'ext-live-run-state',
    extensionId: 'callback-canary-injector',
    extensionName: 'Callback Canary Injector',
    hook: 'request-editor',
    status: 'complete',
    target: 'POST agent-live.fixture.local/api/execute',
    startedAt: '2026-05-26T15:00:05.000Z',
    completedAt: '2026-05-26T15:00:06.000Z',
    summary: 'Injected callback token while preserving live_run_secret.',
    logs: ['Extension saw Cookie: session=live_run_session and X-API-Key: live_run_key.'],
    exchange,
    issue: {
      id: 'issue-extension-live-run-state',
      title: 'Extension hook retained raw request material',
      severity: 'low',
      confidence: 'firm',
      status: 'open',
      host: 'agent-live.fixture.local',
      path: '/api/execute',
      detail: 'Extension run kept live_run_secret available to follow-on executor workflows.',
      remediation: 'Only redact this evidence when exporting report artifacts.',
    },
  });
  assert.equal(extensionResult.stats.extensionRunCount, 1);
  assert.equal(extensionResult.stats.auditEventCount, 3);

  await recorder.close();
  reopened = await ProjectStore.open(projectDir);
  const stats = reopened.stats();
  assert.equal(stats.automationRunCount, 1);
  assert.equal(stats.aiRunCount, 1);
  assert.equal(stats.extensionRunCount, 1);
  assert.equal(stats.auditEventCount, 3);

  const automationRun = reopened.getAutomationRun('auto-live-run-state');
  assert(automationRun);
  assert.match(JSON.stringify(automationRun.operationalRawMaterial), /live-run-token|live_run_key|live_run_secret/);
  assert.match(automationRun.exchange.requestRaw.toString('utf8'), /Authorization: Bearer live-run-token/);

  const aiRun = reopened.getAiRun('ai-live-run-state');
  assert(aiRun);
  assert.match(aiRun.prompt.toString('utf8'), /live_run_secret|live_run_key|redact-only-during-report-export/);
  assert.match(aiRun.output.toString('utf8'), /live-run-token|live_run_key/);

  const extensionRun = reopened.getExtensionRun('ext-live-run-state');
  assert(extensionRun);
  assert.match(extensionRun.logs.join('\n'), /live_run_session|live_run_key/);
  assert.match(extensionRun.exchange.requestRaw.toString('utf8'), /live_run_secret/);

  const searched = reopened.listAiRuns({ text: 'live_run_secret', limit: 10 });
  assert.equal(searched.length, 1);

  console.log(`project-store-live-run-state-wiring: persisted live automation, AI, and extension runs with full executor material at ${projectDir}`);
} finally {
  await recorder?.close().catch(() => undefined);
  reopened?.close();
}
