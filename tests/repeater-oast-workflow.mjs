import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import net from 'node:net';
import path from 'node:path';
import vm from 'node:vm';
import { startVulnerableApp } from './fixtures/vulnerable-app/server.mjs';

const require = createRequire(import.meta.url);
const ts = require('typescript');
const { CallbackListenerService } = require('../dist-electron/callbackListenerService.js');
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const { ProjectStore, ProjectStoreCallbackRecorder, ProjectStoreProxyRecorder } = require('../dist-electron/projectStore.js');
const { ProxyEngine } = require('../dist-electron/proxyEngine.js');

const repeaterEngine = await loadRepeaterEvidenceEngine();
assert.equal(typeof repeaterEngine.buildRepeaterOastEvidencePackage, 'function');

const artifactRoot = path.resolve('.gitignored/test-artifacts/repeater-oast-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'repeater-oast.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

const app = await startVulnerableApp();
let callbackService;
let callbackRecorder;
let proxyRecorder;
let reopened;

try {
  const callbackPort = await freePort();
  const targetHost = new URL(app.httpUrl).host;
  const sourceExchange = {
    id: 'hx-repeater-oast-source',
    method: 'GET',
    url: `${app.httpUrl}/ssrf?url=placeholder`,
    host: targetHost,
    path: '/ssrf?url=placeholder',
    status: 200,
    length: 15,
    mime: 'application/json',
    risk: 'medium',
    timing: 17,
    source: 'proxy',
    time: '22:55:00',
    tags: ['repeater-source', 'oast', 'ssrf-candidate'],
    notes: 'Source request staged into Repeater for OAST payload injection.',
    requestRaw: [
      'GET /ssrf?url=placeholder HTTP/1.1',
      `Host: ${targetHost}`,
      'Authorization: Bearer repeater-oast-source-token',
      'Cookie: session=repeater-oast-source-cookie',
      '',
      '',
    ].join('\r\n'),
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"source":true}',
  };
  const payload = {
    id: 'cb-repeater-oast',
    token: 'pf-repeater-oast',
    label: 'Repeater OAST payload',
    protocol: 'http',
    endpoint: `http://127.0.0.1:${callbackPort}/probe?token=pf-repeater-oast`,
    createdAt: '2026-05-25T22:55:01.000Z',
    status: 'waiting',
    sourceExchangeId: sourceExchange.id,
    sourceHost: targetHost,
    sourcePath: '/ssrf',
    notes: 'Generated for Repeater OAST workflow regression.',
  };

  const seedStore = await ProjectStore.create(projectDir, {
    projectName: 'Repeater OAST Workflow',
    projectId: 'repeater-oast-workflow',
  });
  await seedStore.addHttpExchange({
    id: sourceExchange.id,
    method: sourceExchange.method,
    url: sourceExchange.url,
    host: sourceExchange.host,
    path: sourceExchange.path,
    status: sourceExchange.status,
    mime: sourceExchange.mime,
    timingMs: sourceExchange.timing,
    source: sourceExchange.source,
    tags: sourceExchange.tags,
    notes: sourceExchange.notes,
    requestRaw: sourceExchange.requestRaw,
    responseRaw: sourceExchange.responseRaw,
    createdAt: '2026-05-25T22:55:00.000Z',
  });
  seedStore.close();

  callbackRecorder = new ProjectStoreCallbackRecorder(projectDir, {
    projectName: 'Repeater OAST Workflow',
    projectId: 'repeater-oast-workflow',
  });
  callbackService = new CallbackListenerService({
    payloads: (_profile, payloads) => callbackRecorder.capturePayloads(payloads),
    interaction: (_profile, interaction) => callbackRecorder.captureInteraction(interaction),
  });
  const profile = {
    id: 'repeater-oast-runtime',
    name: 'Repeater OAST runtime',
    createdAt: '2026-05-25T22:55:00.000Z',
    mode: 'local-http',
    status: 'planned',
    host: '127.0.0.1',
    publicBaseUrl: 'oast.local',
    protocols: ['http'],
    httpPort: callbackPort,
    dnsPort: 0,
    smtpPort: 0,
    pollIntervalSeconds: 2,
    retentionHours: 24,
    signingKeyId: 'repeater-oast-key',
    ciCommand: 'proxyforge oast poll --listener repeater-oast-runtime',
    healthChecks: [],
    summary: 'Repeater OAST callback regression profile',
    content: '{}',
  };
  const listenerStatus = await callbackService.start(profile, [payload]);
  await callbackRecorder.flush();
  assert.equal(listenerStatus.running, true);
  assert.equal(listenerStatus.ports.http, callbackPort);

  const proxy = new ProxyEngine(
    () => undefined,
    new CertificateAuthorityManager(path.join(artifactRoot, 'certs')),
  );
  const rawRequest = [
    `GET /ssrf?url=${encodeURIComponent(payload.endpoint)} HTTP/1.1`,
    `Host: ${targetHost}`,
    'Authorization: Bearer repeater-oast-secret-token',
    'Cookie: session=repeater-oast-cookie',
    'X-API-Key: repeater-oast-api-key',
    'Accept: application/json',
    '',
    '',
  ].join('\r\n');
  const replay = await proxy.replay({
    rawRequest,
    targetUrl: `${app.httpUrl}/ssrf?url=placeholder`,
    scopeAllowlist: ['127.0.0.1'],
    oastPayloads: [payload],
    settings: {
      redirectMode: 'manual',
      maxRedirects: 0,
      connectionMode: 'close',
      timeoutMs: 5000,
    },
  });

  assert.equal(replay.status, 200);
  assert(replay.tags.includes('oast-payload'));
  assert(replay.tags.includes(`callback-payload:${payload.id}`));
  assert.match(replay.notes, /OAST 1 payload/);
  assert.match(replay.requestRaw, /Bearer repeater-oast-secret-token|repeater-oast-api-key|pf-repeater-oast/);
  assert.match(replay.responseRaw, /callbackStatus|ssrf-local-callback/i);
  assert.equal(app.state.ssrfCalls.length, 1);
  assert.equal(app.state.ssrfCalls[0].callbackUrl, payload.endpoint);

  await delay(100);
  const poll = callbackService.poll(profile.id, [payload]);
  assert.equal(poll.newInteractionIds.length, 1);
  assert.equal(poll.interactions[0].payloadId, payload.id);
  assert.match(poll.interactions[0].raw, /pf-repeater-oast/);

  const packageResult = repeaterEngine.buildRepeaterOastEvidencePackage({
    sourceExchange,
    replayExchange: replay,
    payloads: [payload],
    interactions: poll.interactions,
    selectedPayloadId: payload.id,
    exportedAt: '2026-05-25T23:00:00.000Z',
  });
  assert.equal(packageResult.kind, 'proxyforge-repeater-oast-evidence-package');
  assert.equal(packageResult.requirements.payloadInjectedInReplay, true);
  assert.equal(packageResult.requirements.callbackObserved, true);
  assert.equal(packageResult.requirements.sourceAndReplayLinked, true);
  assert.equal(packageResult.requirements.issuePromotionCovered, true);
  assert.equal(packageResult.requirements.rawExecutorMaterialPreserved, true);
  assert.equal(packageResult.requirements.operationalSecretsPreserved, true);
  assert.equal(packageResult.reportRedactionBoundary, 'redact-only-during-report-export');
  assert.equal(packageResult.promotedIssue.title, 'Repeater OAST callback confirmed');
  assert.match(packageResult.content, /Bearer repeater-oast-secret-token|session=repeater-oast-cookie|repeater-oast-api-key|pf-repeater-oast/);
  await fs.writeFile(path.join(artifactRoot, 'repeater-oast-evidence-package.json'), JSON.stringify(packageResult, null, 2), 'utf8');

  await callbackRecorder.flush();
  await callbackService.stopAll();
  await callbackRecorder.close();

  proxyRecorder = new ProjectStoreProxyRecorder(projectDir, {
    projectName: 'Repeater OAST Workflow',
    projectId: 'repeater-oast-workflow',
  });
  await proxyRecorder.record(replay);
  await proxyRecorder.close();

  reopened = await ProjectStore.open(projectDir);
  const stats = reopened.stats();
  assert.equal(stats.exchangeCount, 2);
  assert.equal(stats.callbackPayloadCount, 1);
  assert.equal(stats.callbackInteractionCount, 1);
  const replayRows = reopened.searchHttpExchanges({ text: 'cb-repeater-oast', limit: 5 });
  assert.equal(replayRows.length, 1);
  assert(replayRows[0].tags.includes(`callback-payload:${payload.id}`));
  const replayFull = reopened.getHttpExchange(replayRows[0].id);
  assert.match(replayFull.requestRaw.toString('utf8'), /Bearer repeater-oast-secret-token|pf-repeater-oast/);
  const interactionRows = reopened.listCallbackInteractions({ payloadId: payload.id, limit: 5 });
  assert.equal(interactionRows.length, 1);
  assert.match(reopened.getCallbackInteraction(interactionRows[0].id).raw.toString('utf8'), /pf-repeater-oast/);

  console.log(`repeater-oast-workflow: linked replay ${replay.id} to ${stats.callbackInteractionCount} callback interaction and issue ${packageResult.promotedIssue.id}`);
} finally {
  reopened?.close();
  await proxyRecorder?.close().catch(() => undefined);
  await callbackService?.stopAll().catch(() => undefined);
  await callbackRecorder?.close().catch(() => undefined);
  await app.close().catch(() => undefined);
}

async function loadRepeaterEvidenceEngine() {
  const enginePath = path.resolve('src/repeaterEvidenceEngine.ts');
  const source = await fs.readFile(enginePath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: enginePath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    Date,
    Math,
    JSON,
    RegExp,
    Set,
    Array,
    encodeURIComponent,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: enginePath });
  return module.exports;
}

function freePort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      server.close((error) => {
        if (error) reject(error);
        else resolve(port);
      });
    });
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
