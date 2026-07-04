import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  IPC_LIMITS,
  IpcValidationError,
  guardedIpcHandler,
  ipcContracts,
} = require('../dist-electron/ipcContracts.js');
const { ProjectLifecycleService } = require('../dist-electron/services/projectLifecycleService.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/ipc-contract-security', `${Date.now()}-${process.pid}`);
const projectsRootDir = path.join(artifactRoot, 'projects');
const backupsRootDir = path.join(artifactRoot, 'restore-points');
await fs.mkdir(artifactRoot, { recursive: true });

const validExchange = {
  id: 'hx-ipc-raw',
  method: 'POST',
  host: 'ipc.fixture.local',
  path: '/api/raw',
  url: 'https://ipc.fixture.local/api/raw',
  status: 202,
  length: 71,
  mime: 'application/json',
  risk: 'medium',
  timing: 44,
  notes: 'IPC contract must keep ipc_secret_token and ipc_secret_key intact.',
  source: 'automation',
  time: '2026-05-26T16:00:00.000Z',
  requestRaw: [
    'POST /api/raw HTTP/1.1',
    'Host: ipc.fixture.local',
    'Authorization: Bearer ipc_secret_token',
    'Cookie: session=ipc_secret_cookie',
    'X-API-Key: ipc_secret_key',
    '',
    '{"secret":"ipc_secret_token"}',
  ].join('\r\n'),
  responseRaw: 'HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n\r\n{"ok":true}',
  tags: ['ipc', 'raw-secret'],
};

const validIssue = {
  id: 'issue-ipc',
  title: 'IPC raw material retained',
  severity: 'medium',
  host: 'ipc.fixture.local',
  path: '/api/raw',
  confidence: 'firm',
  status: 'open',
  detail: 'ipc_secret_token and ipc_secret_key remain available for executor workflows.',
  remediation: 'Redact only during report/export generation.',
};

assert.throws(
  () => ipcContracts.projectCreate.validate({ rootDir: '../escape.proxyforge' }),
  /path traversal/i,
  'project:create should reject traversal before service code runs',
);
assert.throws(
  () => ipcContracts.projectCreate.validate({ projectName: 'bad', unexpected: true }),
  /unsupported field/i,
  'schemas should reject unknown fields',
);
assert.throws(
  () => ipcContracts.projectOpen.validate({ operator: 'missing-root' }),
  /rootDir/i,
  'project:open should require rootDir',
);

const externalProject = ipcContracts.projectOpen.validate({
  rootDir: path.join(artifactRoot, 'external.proxyforge'),
  allowExternalRoot: true,
  operator: 'ipc-test',
});
assert.equal(externalProject.allowExternalRoot, true);

assert.throws(
  () => ipcContracts.aiProvidersSet.validate([{
    id: 'codex',
    label: 'Codex',
    mode: 'cli',
    enabled: true,
    model: 'configured-default',
    command: 'codex; rm -rf /',
    timeoutMs: 90000,
  }]),
  /shell expression/i,
  'AI provider commands should not accept shell expressions',
);
assert.throws(
  () => ipcContracts.aiProvidersSet.validate([{
    id: 'local',
    label: 'Local',
    mode: 'http',
    enabled: true,
    model: 'local-security-model',
    endpoint: 'file:///tmp/not-http',
    timeoutMs: 90000,
  }]),
  /http\(s\) URL/i,
  'AI HTTP provider endpoint must be http(s)',
);

const aiRun = ipcContracts.aiRun.validate({
  providerId: 'codex',
  task: 'replay-plan',
  prompt: 'Plan replay with Authorization: Bearer ipc_secret_token and ipc_secret_key intact.',
  context: {
    projectName: 'IPC Contract Fixture',
    scopeAllowlist: ['*.fixture.local'],
    taskHint: 'Replay plan',
    exchanges: [{
      method: validExchange.method,
      host: validExchange.host,
      path: validExchange.path,
      status: validExchange.status,
      risk: validExchange.risk,
      notes: validExchange.notes,
      requestRaw: validExchange.requestRaw,
      responseRaw: validExchange.responseRaw,
      tags: validExchange.tags,
    }],
    issues: [{
      title: validIssue.title,
      severity: validIssue.severity,
      host: validIssue.host,
      path: validIssue.path,
      detail: validIssue.detail,
      remediation: validIssue.remediation,
    }],
  },
});
assert.match(aiRun.prompt, /ipc_secret_token|ipc_secret_key/);
assert.match(aiRun.context.exchanges[0].requestRaw, /ipc_secret_cookie/);
assert.throws(
  () => ipcContracts.aiRun.validate({ ...aiRun, prompt: 'x'.repeat(IPC_LIMITS.rawTextBytes + 1) }),
  /byte limit/i,
  'AI prompts should have an IPC size ceiling without masking valid secrets',
);

const automationRun = ipcContracts.automationRunState.validate({
  id: 'auto-ipc',
  workflowId: 'wf-ipc',
  workflowName: 'IPC raw collector',
  status: 'complete',
  trigger: 'manual',
  startedAt: '2026-05-26T16:00:00.000Z',
  completedAt: '2026-05-26T16:00:02.000Z',
  durationMs: 2000,
  totalRequests: 1,
  logs: ['Collected Authorization: Bearer ipc_secret_token and X-API-Key: ipc_secret_key.'],
  exchange: validExchange,
  issue: validIssue,
  operationalRawMaterial: {
    requestRaw: validExchange.requestRaw,
    executorToken: 'ipc_secret_token',
    executorKey: 'ipc_secret_key',
  },
  ciProvider: 'github-actions',
  ciConfig: 'PROXYFORGE_AUTHORIZATION=Bearer ipc_secret_token\nPROXYFORGE_API_KEY=ipc_secret_key',
});
assert.match(JSON.stringify(automationRun.operationalRawMaterial), /ipc_secret_token|ipc_secret_key/);
assert.throws(
  () => ipcContracts.automationRunState.validate({ ...automationRun, extraMutation: true }),
  /unsupported field/i,
  'run-state automation IPC should reject unexpected mutation fields',
);

const extensionRun = ipcContracts.extensionRunState.validate({
  id: 'ext-ipc',
  extensionId: 'raw-context-helper',
  extensionName: 'Raw Context Helper',
  hook: 'request-editor',
  status: 'complete',
  target: 'POST ipc.fixture.local/api/raw',
  startedAt: '2026-05-26T16:00:03.000Z',
  completedAt: '2026-05-26T16:00:04.000Z',
  summary: 'Preserved ipc_secret_token for follow-on replay.',
  logs: ['Saw ipc_secret_cookie and ipc_secret_key.'],
  issue: validIssue,
  exchange: validExchange,
});
assert.match(extensionRun.logs.join('\n'), /ipc_secret_cookie|ipc_secret_key/);

const replayRequest = ipcContracts.repeaterSend.validate({
  rawRequest: validExchange.requestRaw,
  targetUrl: validExchange.url,
  scopeAllowlist: ['*.fixture.local'],
  settings: {
    redirectMode: 'manual',
    maxRedirects: 0,
    connectionMode: 'keep-alive',
    timeoutMs: 10000,
  },
  oastPayloads: [{
    id: 'payload-ipc',
    token: 'ipc_callback_secret',
    endpoint: 'http://127.0.0.1:7777/callback/ipc_callback_secret',
    protocol: 'http',
  }],
  operator: 'ipc-test',
  tags: ['ipc-active'],
  notes: 'Repeater IPC keeps ipc_secret_token for active replay.',
});
assert.match(replayRequest.rawRequest, /ipc_secret_token|ipc_secret_key/);
assert.throws(
  () => ipcContracts.repeaterSend.validate({ ...replayRequest, targetUrl: 'file:///tmp/blocked' }),
  /http\(s\) URL/i,
  'Repeater active IPC should reject non-http targets',
);

const intruderRequest = ipcContracts.intruderRun.validate({
  rawRequest: validExchange.requestRaw,
  targetUrl: validExchange.url,
  payloads: ['ipc_secret_token', 'ipc_secret_key'],
  payloadSets: [['alpha'], ['beta']],
  attackMode: 'pitchfork',
  payloadProcessors: ['url-encode', 'base64'],
  payloadRules: ['case-variants'],
  scopeAllowlist: ['*.fixture.local'],
  throttleMs: 25,
  grepTerms: ['ok'],
  extractRegexes: ['ipc_secret_[a-z]+'],
  maxPayloadRequests: 2,
  resultWindowSize: 2,
  oastPayloads: [{
    id: 'payload-intruder-ipc',
    token: 'ipc_intruder_secret',
    endpoint: 'http://127.0.0.1:7777/oast/ipc_intruder_secret',
    label: 'Intruder IPC',
    protocol: 'http',
  }],
});
assert.deepEqual(intruderRequest.payloads, ['ipc_secret_token', 'ipc_secret_key']);
assert.throws(
  () => ipcContracts.intruderRun.validate({ ...intruderRequest, payloadProcessors: ['shell-out'] }),
  /payloadProcessors/i,
  'Intruder IPC should reject unsupported payload processors',
);

const scanRequest = ipcContracts.scannerRunActive.validate({
  rawRequest: validExchange.requestRaw,
  targetUrl: validExchange.url,
  scopeAllowlist: ['*.fixture.local'],
  checks: ['security-headers', 'oast-ssrf'],
  throttleMs: 50,
  maxRequests: 4,
  oastPayloadUrl: 'http://127.0.0.1:7777/oast/ipc_scan_secret',
  oastPayloadToken: 'ipc_scan_secret',
  oastPayloadId: 'payload-scan-ipc',
});
assert.match(scanRequest.rawRequest, /ipc_secret_token/);
assert.throws(
  () => ipcContracts.scannerRunActive.validate({ ...scanRequest, scopeAllowlist: [] }),
  /scopeAllowlist/i,
  'Active scanner IPC should require explicit scope',
);

const crawlAudit = ipcContracts.scannerRunCrawlAudit.validate({
  scopeAllowlist: ['*.fixture.local'],
  checks: ['security-headers'],
  insertionPoints: [{
    id: 'ip-query-ipc',
    routeId: 'route-ipc',
    type: 'query',
    name: 'q',
    method: 'GET',
    url: 'https://ipc.fixture.local/search?q=ipc_secret_token',
    evidence: 'q=ipc_secret_token',
  }],
  sessionHeaders: {
    Authorization: 'Bearer ipc_secret_token',
    'X-API-Key': 'ipc_secret_key',
  },
  throttleMs: 10,
  maxInsertionPoints: 1,
});
assert.match(crawlAudit.sessionHeaders.Authorization, /ipc_secret_token/);

const callbackProfile = {
  id: 'cb-ipc',
  name: 'IPC callback listener',
  createdAt: '2026-05-26T16:00:05.000Z',
  mode: 'local-http',
  status: 'planned',
  host: '127.0.0.1',
  publicBaseUrl: 'http://127.0.0.1:7777',
  protocols: ['http'],
  httpPort: 0,
  dnsPort: 0,
  smtpPort: 0,
  pollIntervalSeconds: 2,
  retentionHours: 24,
  signingKeyId: 'ipc-signing-key',
  ciCommand: 'proxyforge-agent callback-listener-start --profile cb-ipc --token ipc_callback_secret',
  healthChecks: ['local http only'],
  summary: 'Local IPC callback listener',
  content: 'Keep ipc_callback_secret in listener payloads until report export.',
};
const callbackStart = ipcContracts.callbackListenerStart.validate({
  profile: callbackProfile,
  payloads: [{
    id: 'payload-callback-ipc',
    token: 'ipc_callback_secret',
    label: 'IPC callback payload',
    protocol: 'http',
    endpoint: 'http://127.0.0.1:7777/oast/ipc_callback_secret',
    createdAt: '2026-05-26T16:00:06.000Z',
    status: 'waiting',
    sourceHost: 'ipc.fixture.local',
    sourcePath: '/api/raw',
    notes: 'Preserve ipc_callback_secret until report export.',
  }],
});
assert.match(callbackStart.payloads[0].token, /ipc_callback_secret/);
assert.throws(
  () => ipcContracts.callbackListenerStart.validate({ profile: { ...callbackProfile, host: '0.example.com' }, payloads: [] }),
  /local interface|loopback interface/i,
  'Callback listener IPC should only bind local interfaces',
);
const callbackPoll = ipcContracts.callbackListenerPoll.validate({
  profileId: 'cb-ipc',
  payloads: callbackStart.payloads,
});
assert.equal(callbackPoll.profileId, 'cb-ipc');

const auditEvents = [];
const guarded = guardedIpcHandler(
  ipcContracts.projectCreate,
  async (request) => ({ ok: true, rootDir: request.rootDir ?? 'default.proxyforge' }),
  (event) => auditEvents.push(event),
);
await assert.rejects(
  guarded({}, { rootDir: '../blocked.proxyforge' }),
  IpcValidationError,
  'guarded handler should reject malformed IPC and emit a blocked audit event',
);
assert.equal(auditEvents.length, 1);
assert.equal(auditEvents[0].decision, 'blocked');
assert.equal(auditEvents[0].capability, 'project.lifecycle');
const guardedOk = await guarded({}, { rootDir: 'allowed.proxyforge', operator: 'ipc-test' });
assert.equal(guardedOk.rootDir, 'allowed.proxyforge');

const lifecycle = new ProjectLifecycleService({
  projectsRootDir,
  backupsRootDir,
  defaultProjectName: 'IPC Contract Project',
});
try {
  const created = await lifecycle.createProject({
    projectName: 'IPC Contract Project',
    projectId: 'ipc-contract-project',
    operator: 'ipc-test',
  });
  assert.equal(created.activeProject.stats.auditEventCount, 1);
  await lifecycle.recordAuditEvent({
    actor: 'ipc-guard',
    action: 'ipc.project:create',
    targetRef: 'project.lifecycle',
    decision: 'blocked',
    detail: 'file-write: rootDir must not contain path traversal segments',
  });
  const status = await lifecycle.status();
  assert.equal(status.activeProject.stats.auditEventCount, 2);
  assert.equal(status.activeProject.auditEvents.some((event) => event.action === 'ipc.project:create' && event.decision === 'blocked'), true);
} finally {
  await lifecycle.dispose();
}

const mainSource = await fs.readFile('electron/main.ts', 'utf8');
assert.match(mainSource, /guardedIpcHandler\(ipcContracts\.projectCreate/, 'project:create should be registered through guarded IPC');
assert.match(mainSource, /guardedIpcHandler\(ipcContracts\.aiRun/, 'ai:run should be registered through guarded IPC');
assert.match(mainSource, /guardedIpcHandler<ReplayRequest[\s\S]+ipcContracts\.repeaterSend/, 'repeater:send should be registered through guarded IPC');
assert.match(mainSource, /guardedIpcHandler<IntruderAttackRequest[\s\S]+ipcContracts\.intruderRun/, 'intruder:run should be registered through guarded IPC');
assert.match(mainSource, /guardedIpcHandler<ActiveScanRequest[\s\S]+ipcContracts\.scannerRunActive/, 'scanner:run-active should be registered through guarded IPC');
assert.match(mainSource, /guardedIpcHandler<\{ profile: RuntimeCallbackListenerProfile; payloads: RuntimeCallbackPayload\[\] \}[\s\S]+ipcContracts\.callbackListenerStart/, 'callback-listener:start should be registered through guarded IPC');
assert.match(mainSource, /guardedIpcHandler\(ipcContracts\.automationRunState/, 'automation run-state should be registered through guarded IPC');
assert.match(mainSource, /guardedIpcHandler\(ipcContracts\.extensionRunState/, 'extension run-state should be registered through guarded IPC');

console.log(`ipc-contract-security: validated typed IPC contracts, blocked audit path, and full-fidelity raw secret preservation in ${artifactRoot}`);
