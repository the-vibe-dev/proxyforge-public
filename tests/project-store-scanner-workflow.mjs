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
  ProjectStoreScannerRecorder,
} = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-scanner-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'scanner-workflow.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

const app = await startVulnerableApp();
let proxy;
let reopened;
let restored;

try {
  const seedStore = await ProjectStore.create(projectDir, {
    projectName: 'Project Store Scanner Workflow',
    projectId: 'project-store-scanner-workflow',
  });
  seedStore.close();

  proxy = new ProxyEngine(() => undefined, new CertificateAuthorityManager(path.join(artifactRoot, 'certs')));
  const recorder = new ProjectStoreScannerRecorder(projectDir, {
    projectName: 'Project Store Scanner Workflow',
    projectId: 'project-store-scanner-workflow',
  });

  const scanRequest = {
    rawRequest: [
      'GET /reflected?input=baseline HTTP/1.1',
      hostHeader(app.httpUrl),
      'Authorization: Bearer scanner-store-token',
      'Cookie: session=scanner-store-session',
      'X-API-Key: scanner-store-key',
      'Accept: text/html',
      '',
      '',
    ].join('\r\n'),
    targetUrl: `${app.httpUrl}/reflected?input=baseline`,
    scopeAllowlist: ['127.0.0.1'],
    checks: ['security-headers', 'reflected-xss', 'open-redirect'],
    throttleMs: 0,
    maxRequests: 3,
  };

  const summary = await proxy.runActiveScan(scanRequest);
  assert.equal(summary.blocked, false);
  assert.equal(summary.totalRequests, 3);
  assert(summary.findings.some((finding) => finding.checkId === 'security-headers'));
  assert(summary.exchanges.every((exchange) => exchange.source === 'scanner'));
  assert.match(summary.exchanges[0].requestRaw, /scanner-store-token/);

  await recorder.recordTask(scanRequest, summary);
  assert.equal(recorder.stats().failedCount, 0);
  assert.equal(recorder.stats().persistedTaskCount, 1);
  assert.equal(recorder.stats().persistedFindingCount, summary.findings.length + summary.suppressedFindings.length);
  await recorder.close();

  reopened = await ProjectStore.open(projectDir);
  const stats = reopened.stats();
  assert.equal(stats.scannerTaskCount, 1);
  assert.equal(stats.scannerFindingCount, summary.findings.length + summary.suppressedFindings.length);
  assert.equal(stats.exchangeCount, summary.exchanges.length);
  assert.equal(stats.auditEventCount, 1);

  const task = reopened.getScannerTask(summary.id);
  assert(task);
  assert.equal(task.kind, 'active');
  assert.equal(task.totalRequests, 3);
  assert.equal(task.exchangeIds.length, 3);
  assert(task.requestedChecks.includes('security-headers'));
  assert.match(task.message, /Active scan complete/);

  const findingRows = reopened.listScannerFindings({ checkId: 'security-headers', limit: 10 });
  assert.equal(findingRows.length >= 1, true);
  const finding = reopened.getScannerFinding(findingRows[0].id);
  assert(finding);
  assert.equal(finding.taskId, summary.id);
  assert.equal(finding.suppressed, false);
  assert(finding.evidenceExchange);
  assert.match(finding.evidenceExchange.requestRaw.toString('utf8'), /Bearer scanner-store-token/);
  assert.match(finding.evidenceExchange.responseRaw.toString('utf8'), /<output>|Content-Security-Policy|proxyforge/);

  await reopened.upsertIssue({
    id: 'issue-scanner-store',
    title: 'Scanner finding persists with raw probe evidence',
    type: 'scanner-active',
    severity: finding.severity,
    confidence: finding.confidence,
    status: 'open',
    host: finding.host,
    path: finding.path,
    detail: `${finding.detail} Evidence keeps scanner-store-token for executor replay until report export.`,
    remediation: finding.remediation || 'Review scanner evidence and apply the route-specific remediation.',
    evidenceRefs: [
      { kind: 'scanner-task', id: summary.id, label: 'Active scanner task', source: 'scanner' },
      { kind: 'scanner-finding', id: finding.id, label: 'Active scanner finding', source: 'scanner' },
      { kind: 'http-exchange', id: finding.evidenceExchangeId, label: 'Scanner probe exchange', source: 'scanner' },
    ],
    source: 'scanner-workflow',
  });

  const issue = reopened.getIssue('issue-scanner-store');
  assert(issue);
  assert.equal(issue.evidenceRefs.filter((ref) => ref.kind === 'scanner-finding').length, 1);
  assert.match(issue.detail, /scanner-store-token/);

  const backup = await reopened.createBackup(path.join(artifactRoot, 'backups'), { label: 'scanner-store' });
  assert.equal(backup.stats.scannerTaskCount, 1);
  assert.equal(backup.stats.scannerFindingCount, summary.findings.length + summary.suppressedFindings.length);
  reopened.close();
  reopened = null;

  restored = await ProjectStore.open(backup.backupDir);
  assert.equal(restored.stats().scannerTaskCount, 1);
  assert.equal(restored.stats().scannerFindingCount, summary.findings.length + summary.suppressedFindings.length);
  const restoredFinding = restored.getScannerFinding(finding.id);
  assert(restoredFinding);
  assert.match(restoredFinding.evidenceExchange.requestRaw.toString('utf8'), /scanner-store-key|scanner-store-token/);
  assert.equal(restored.getIssue('issue-scanner-store').evidenceRefs.length, 3);

  console.log(`project-store-scanner-workflow: persisted scanner task ${summary.id}, ${stats.scannerFindingCount} finding record(s), raw probe exchanges, issue refs, audit event, and backup restore from ${projectDir}`);
} finally {
  restored?.close();
  reopened?.close();
  if (proxy) await proxy.stop().catch(() => undefined);
  await app.close();
}

function hostHeader(urlString) {
  return `Host: ${new URL(urlString).host}`;
}
