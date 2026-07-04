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
  ProjectStoreIntruderRecorder,
} = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-intruder-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'intruder-workflow.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

const app = await startVulnerableApp();
let proxy;
let reopened;
let restored;

try {
  const seedStore = await ProjectStore.create(projectDir, {
    projectName: 'Project Store Intruder Workflow',
    projectId: 'project-store-intruder-workflow',
  });
  seedStore.close();

  proxy = new ProxyEngine(() => undefined, new CertificateAuthorityManager(path.join(artifactRoot, 'certs')));
  const recorder = new ProjectStoreIntruderRecorder(projectDir, {
    projectName: 'Project Store Intruder Workflow',
    projectId: 'project-store-intruder-workflow',
  });

  const attackRequest = {
    rawRequest: [
      'GET /reflected?input=§payload§ HTTP/1.1',
      hostHeader(app.httpUrl),
      'Authorization: Bearer intruder-store-token',
      'Cookie: session=intruder-store-session',
      'X-API-Key: intruder-store-key',
      '',
      '',
    ].join('\r\n'),
    targetUrl: `${app.httpUrl}/reflected?input=baseline`,
    payloads: ['user', 'admin<script>'],
    payloadSets: [['user', 'admin<script>']],
    attackMode: 'sniper',
    payloadProcessors: ['url-encode'],
    payloadRules: ['grep:admin'],
    scopeAllowlist: ['127.0.0.1'],
    throttleMs: 0,
    grepTerms: ['admin', 'intruder-store-token'],
    extractRegexes: ['<output>(.*?)</output>'],
    resourcePoolName: 'project-store-intruder',
    resourcePoolMaxConcurrent: 1,
    resultWindowSize: 10,
  };

  const summary = await proxy.runIntruderAttack(attackRequest);
  assert.equal(summary.blocked, false);
  assert.equal(summary.totalRequests, 2);
  assert.equal(summary.results.length, 2);
  assert(summary.results.some((result) => result.payload.includes('admin')));
  assert.match(summary.results[0].requestRaw, /intruder-store-token/);

  await recorder.recordAttack(attackRequest, summary);
  assert.equal(recorder.stats().failedCount, 0);
  assert.equal(recorder.stats().persistedAttackCount, 1);
  assert.equal(recorder.stats().persistedResultCount, 2);
  await recorder.close();

  reopened = await ProjectStore.open(projectDir);
  const stats = reopened.stats();
  assert.equal(stats.intruderAttackCount, 1);
  assert.equal(stats.intruderResultCount, 2);
  assert(stats.intruderRequestBytes > 0);
  assert(stats.intruderResponseBytes > 0);
  assert.equal(stats.auditEventCount, 1);

  const attack = reopened.getIntruderAttack(summary.id);
  assert(attack);
  assert.equal(attack.attackMode, 'sniper');
  assert.equal(attack.payloadPositions, 1);
  assert.equal(attack.totalRequests, 2);
  assert.equal(attack.retainedResultCount, 2);
  assert.match(attack.rawRequest.toString('utf8'), /Authorization: Bearer intruder-store-token/);
  assert.deepEqual(attack.payloads, ['user', 'admin<script>']);
  assert.deepEqual(attack.payloadSets, [['user', 'admin<script>']]);

  const searchRows = reopened.listIntruderResults({ text: 'admin', limit: 5 });
  assert.equal(searchRows.length >= 1, true);
  const result = reopened.getIntruderResult(searchRows[0].id);
  assert(result);
  assert.equal(result.attackId, summary.id);
  assert.match(result.requestRaw.toString('utf8'), /intruder-store-token/);
  assert.match(result.responseRaw.toString('utf8'), /<output>|admin|user/);
  assert(result.grepMatches.includes('admin') || result.grepMatches.includes('intruder-store-token'));

  await reopened.upsertIssue({
    id: 'issue-intruder-reflection',
    title: 'Intruder reflection proof preserves executor material',
    type: 'intruder-manual',
    severity: 'medium',
    confidence: 'firm',
    status: 'open',
    host: new URL(app.httpUrl).host,
    path: '/reflected?input=payload',
    detail: 'Intruder row evidence preserves Bearer intruder-store-token and session=intruder-store-session until report export.',
    remediation: 'Validate reflected input handling and redact public report text only at export.',
    evidenceRefs: [
      { kind: 'intruder-attack', id: summary.id, label: 'Intruder attack definition', source: 'intruder' },
      { kind: 'intruder-result', id: result.id, label: 'Intruder reflected row', source: 'intruder' },
    ],
    source: 'intruder-workflow',
  });

  const issue = reopened.getIssue('issue-intruder-reflection');
  assert(issue);
  assert.equal(issue.evidenceRefs.filter((ref) => ref.kind === 'intruder-result').length, 1);
  assert.match(issue.detail, /intruder-store-token|intruder-store-session/);

  const backup = await reopened.createBackup(path.join(artifactRoot, 'backups'), { label: 'intruder-store' });
  assert.equal(backup.stats.intruderAttackCount, 1);
  assert.equal(backup.stats.intruderResultCount, 2);
  reopened.close();
  reopened = null;

  restored = await ProjectStore.open(backup.backupDir);
  assert.equal(restored.stats().intruderAttackCount, 1);
  assert.equal(restored.stats().intruderResultCount, 2);
  assert.match(restored.getIntruderAttack(summary.id).rawRequest.toString('utf8'), /intruder-store-key/);
  assert.match(restored.getIntruderResult(result.id).requestRaw.toString('utf8'), /Bearer intruder-store-token/);
  assert.equal(restored.getIssue('issue-intruder-reflection').evidenceRefs.length, 2);

  console.log(`project-store-intruder-workflow: persisted ${stats.intruderResultCount} Intruder result row(s), raw attack material, issue refs, audit event, and backup restore from ${projectDir}`);
} finally {
  restored?.close();
  reopened?.close();
  if (proxy) await proxy.stop().catch(() => undefined);
  await app.close();
}

function hostHeader(urlString) {
  return `Host: ${new URL(urlString).host}`;
}
