import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import { startVulnerableApp } from './fixtures/vulnerable-app/server.mjs';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const { ProxyEngine } = require('../dist-electron/proxyEngine.js');
const {
  ProjectStore,
  ProjectStoreRepeaterRecorder,
} = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-repeater-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'repeater-workflow.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

const app = await startVulnerableApp();
let proxy;
let reopened;
let restored;

try {
  const seedStore = await ProjectStore.create(projectDir, {
    projectName: 'Project Store Repeater Workflow',
    projectId: 'project-store-repeater-workflow',
  });
  await seedStore.upsertRepeaterTab({
    id: 'rt-manual-secret',
    name: 'Manual token proof',
    targetUrl: `${app.httpUrl}/api/profile`,
    rawRequest: [
      'GET /api/profile HTTP/1.1',
      hostHeader(app.httpUrl),
      'Authorization: Bearer manual-repeater-secret',
      'Cookie: pf_session=manual-repeater-session',
      '',
      '',
    ].join('\r\n'),
    group: 'manual-fixture',
    tags: ['manual', 'full-fidelity'],
    notes: 'Manual Repeater tab keeps raw execution secrets inside the Project Store.',
  });
  await seedStore.addRepeaterSend({
    id: 'send-manual-secret',
    tabId: 'rt-manual-secret',
    targetUrl: `${app.httpUrl}/api/profile`,
    rawRequest: [
      'GET /api/profile HTTP/1.1',
      hostHeader(app.httpUrl),
      'Authorization: Bearer manual-repeater-secret',
      'X-API-Key: manual-repeater-key',
      'Cookie: pf_session=manual-repeater-session',
      '',
      '',
    ].join('\r\n'),
    responseRaw: [
      'HTTP/1.1 200 OK',
      'Content-Type: application/json',
      '',
      '{"apiToken":"manual-repeater-response-token","ok":true}',
    ].join('\r\n'),
    status: 200,
    mime: 'application/json',
    timingMs: 12,
    tags: ['manual-send'],
    notes: 'Manual Repeater send keeps request and response tokens until report export.',
  });
  seedStore.close();

  proxy = new ProxyEngine(() => undefined, new CertificateAuthorityManager(path.join(artifactRoot, 'certs')));
  const recorder = new ProjectStoreRepeaterRecorder(projectDir, {
    projectName: 'Project Store Repeater Workflow',
    projectId: 'project-store-repeater-workflow',
  });

  const loginRaw = [
    'POST /login HTTP/1.1',
    hostHeader(app.httpUrl),
    'Content-Type: application/x-www-form-urlencoded',
    '',
    'username=repeater-store&role=admin',
  ].join('\r\n');
  const loginExchange = await proxy.replay({
    rawRequest: loginRaw,
    targetUrl: `${app.httpUrl}/login`,
    scopeAllowlist: ['127.0.0.1'],
  });
  assert.equal(loginExchange.status, 200);
  const cookies = cookieHeaderFromRaw(loginExchange.responseRaw);
  assert.match(cookies, /pf_session=/);

  const replayRequest = {
    rawRequest: [
      'GET /api/profile HTTP/1.1',
      hostHeader(app.httpUrl),
      'Authorization: Bearer repeater-store-secret-token',
      'X-API-Key: repeater-store-secret-key',
      `Cookie: ${cookies}; agentToken=repeater-store-cookie-secret`,
      '',
      '',
    ].join('\r\n'),
    targetUrl: `${app.httpUrl}/api/profile`,
    scopeAllowlist: ['127.0.0.1'],
    repeaterTabId: 'rt-live-profile',
    repeaterTabName: 'Live profile replay',
    repeaterTabGroup: 'live-fixture',
    sourceExchangeId: 'hx-history-profile-source',
    sessionProfile: { id: 'profile-admin', name: 'Admin profile' },
    oastPayloads: [{ id: 'payload-repeater-store', token: 'repeater-store-oast-token', endpoint: 'http://127.0.0.1/oast/repeater-store-oast-token' }],
    tags: ['live-replay', 'agent-drivable'],
    notes: 'Live Repeater replay persisted through the Project Store backbone.',
  };
  const replayed = await proxy.replay(replayRequest);
  assert.equal(replayed.status, 200);
  assert.match(replayed.responseRaw, /fixture-token-/);

  await recorder.recordSend(replayRequest, replayed);
  const recorderStats = recorder.stats();
  assert.equal(recorderStats.failedCount, 0);
  assert.equal(recorderStats.pendingCount, 0);
  assert.equal(recorderStats.persistedSendCount, 1);
  await recorder.close();

  reopened = await ProjectStore.open(projectDir);
  const stats = reopened.stats();
  assert.equal(stats.repeaterTabCount, 2);
  assert.equal(stats.repeaterSendCount, 2);
  assert.equal(stats.exchangeCount, 1);
  assert.equal(stats.auditEventCount, 1);
  assert(stats.repeaterRequestBytes > 0);
  assert(stats.repeaterResponseBytes > 0);

  const manualTab = reopened.getRepeaterTab('rt-manual-secret');
  assert(manualTab);
  assert.match(manualTab.rawRequest.toString('utf8'), /Authorization: Bearer manual-repeater-secret/);

  const manualSend = reopened.getRepeaterSend('send-manual-secret');
  assert(manualSend);
  assert.match(manualSend.rawRequest.toString('utf8'), /X-API-Key: manual-repeater-key/);
  assert.match(manualSend.responseRaw.toString('utf8'), /manual-repeater-response-token/);

  const liveRows = reopened.listRepeaterSends({ text: 'repeater-store-secret-token', limit: 5 });
  assert.equal(liveRows.length, 1);
  const liveSend = reopened.getRepeaterSend(liveRows[0].id);
  assert(liveSend);
  assert.equal(liveSend.tabId, 'rt-live-profile');
  assert.equal(liveSend.exchangeId, replayed.id);
  assert.equal(liveSend.sessionProfileId, 'profile-admin');
  assert.deepEqual(liveSend.oastPayloadIds, ['payload-repeater-store']);
  assert.match(liveSend.rawRequest.toString('utf8'), /Authorization: Bearer repeater-store-secret-token/);
  assert.match(liveSend.rawRequest.toString('utf8'), /agentToken=repeater-store-cookie-secret/);
  assert.match(liveSend.responseRaw.toString('utf8'), /fixture-token-/);

  const replayedExchange = reopened.getHttpExchange(replayed.id);
  assert(replayedExchange);
  assert.match(replayedExchange.requestRaw.toString('utf8'), /X-API-Key: repeater-store-secret-key/);
  assert.match(replayedExchange.responseRaw.toString('utf8'), /fixture-token-/);

  const backup = await reopened.createBackup(path.join(artifactRoot, 'backups'), { label: 'repeater-store' });
  assert.equal(backup.stats.repeaterSendCount, 2);
  reopened.close();
  reopened = null;

  restored = await ProjectStore.open(backup.backupDir);
  assert.equal(restored.stats().repeaterTabCount, 2);
  const restoredSend = restored.getRepeaterSend(liveSend.id);
  assert(restoredSend);
  assert.match(restoredSend.rawRequest.toString('utf8'), /Bearer repeater-store-secret-token/);
  assert.match(restoredSend.responseRaw.toString('utf8'), /fixture-token-/);

  console.log(`project-store-repeater-workflow: persisted ${stats.repeaterSendCount} Repeater send(s), exact raw secrets, audit lineage, and backup restore from ${projectDir}`);
} finally {
  restored?.close();
  reopened?.close();
  if (proxy) await proxy.stop().catch(() => undefined);
  await app.close();
}

function hostHeader(urlString) {
  return `Host: ${new URL(urlString).host}`;
}

function cookieHeaderFromRaw(raw) {
  const cookies = [];
  for (const match of raw.matchAll(/^set-cookie:\s*([^;\r\n]+)/gim)) {
    cookies.push(match[1]);
  }
  return cookies.join('; ');
}
