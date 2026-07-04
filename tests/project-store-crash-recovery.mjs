import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  ProjectStore,
  appendProjectStorePendingHttpExchange,
} = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-crash-recovery', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'crash-recovery.proxyforge');
const backupRoot = path.join(artifactRoot, 'restore-points');
await fs.mkdir(artifactRoot, { recursive: true });

const store = await ProjectStore.create(projectDir, {
  projectName: 'Crash Recovery Regression',
  projectId: 'project-store-crash-recovery',
});
store.close();

await appendProjectStorePendingHttpExchange(projectDir, {
  id: 'hx-crash-pending-secret',
  method: 'POST',
  url: 'https://crash.fixture.local/api/transfer',
  host: 'crash.fixture.local',
  path: '/api/transfer',
  protocol: 'https',
  status: 202,
  mime: 'application/json',
  timingMs: 37,
  source: 'proxy',
  tags: ['crash-recovery', 'pending-capture'],
  notes: 'pending capture written before simulated process death',
  scopeState: 'captured',
  createdAt: '2026-05-26T02:00:00.000Z',
  requestRaw: [
    'POST /api/transfer HTTP/1.1',
    'Host: crash.fixture.local',
    'Authorization: Bearer crash-recovery-secret-token',
    'Cookie: session=crash-recovery-session; csrf=crash-recovery-csrf',
    'X-API-Key: crash-recovery-api-key',
    'Content-Type: application/json',
    '',
    '{"amount":1337,"token":"crash-recovery-body-token"}',
  ].join('\r\n'),
  responseRaw: [
    'HTTP/1.1 202 Accepted',
    'Content-Type: application/json',
    'Set-Cookie: callbackToken=crash-recovery-callback-token; HttpOnly',
    '',
    '{"queued":true,"secretEcho":"crash-recovery-body-token"}',
  ].join('\r\n'),
});

let recoveredStore;
try {
  recoveredStore = await ProjectStore.open(projectDir, { recover: false });
  const report = await recoveredStore.recoverPendingHttpExchanges();
  assert.equal(report.kind, 'proxyforge-project-store-recovery-report');
  assert.equal(report.recoveredHttpExchangeCount, 1);
  assert.equal(report.failedCount, 0);
  assert.equal(report.requirements.durableJournalPresent, true);
  assert.equal(report.requirements.recoveryReplayAttempted, true);
  assert.equal(report.requirements.sqliteWalEnabled, true);
  assert.equal(report.requirements.rawOperationalSecretsPreserved, true);
  assert.equal(report.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.equal(report.reportRedactionBoundary, 'redact-only-during-report-export');
  if (process.platform !== 'win32') {
    assert.equal((await fs.stat(path.join(projectDir, 'recovery'))).mode & 0o777, 0o700, 'recovery directory should be private');
    assert.equal((await fs.stat(path.join(projectDir, 'recovery', 'http-exchanges.pending.jsonl'))).mode & 0o777, 0o600, 'pending recovery journal should be private');
    assert.equal((await fs.stat(path.join(projectDir, 'recovery', 'http-exchanges.committed.jsonl'))).mode & 0o777, 0o600, 'committed recovery journal should be private');
  }

  const recovered = recoveredStore.getHttpExchange('hx-crash-pending-secret');
  assert(recovered);
  assert.match(recovered.requestRaw.toString('utf8'), /Authorization: Bearer crash-recovery-secret-token/);
  assert.match(recovered.requestRaw.toString('utf8'), /session=crash-recovery-session/);
  assert.match(recovered.requestRaw.toString('utf8'), /X-API-Key: crash-recovery-api-key/);
  assert.match(recovered.responseRaw.toString('utf8'), /crash-recovery-callback-token/);
  assert.equal(recoveredStore.stats().exchangeCount, 1);

  const secondReport = await recoveredStore.recoverPendingHttpExchanges();
  assert.equal(secondReport.recoveredHttpExchangeCount, 0);
  assert.equal(secondReport.skippedCommittedCount, 1);

  const backup = await recoveredStore.createBackup(backupRoot, {
    label: 'operator-restore-point',
    createdAt: '2026-05-26T02:05:00.000Z',
  });
  assert.equal(backup.kind, 'proxyforge-project-store-backup');
  assert.equal(backup.requirements.manifestCopied, true);
  assert.equal(backup.requirements.databaseCopied, true);
  assert.equal(backup.requirements.blobsCopied, true);
  assert.equal(backup.requirements.recoveryJournalCopied, true);
  assert.equal(backup.requirements.rawOperationalSecretsPreserved, true);
  assert.match(backup.content, /project-store-crash-recovery/);
  await fs.access(backup.manifestPath);

  recoveredStore.close();
  recoveredStore = null;

  const restored = await ProjectStore.open(backup.backupDir);
  try {
    const restoredExchange = restored.getHttpExchange('hx-crash-pending-secret');
    assert(restoredExchange);
    assert.match(restoredExchange.requestRaw.toString('utf8'), /crash-recovery-secret-token/);
    assert.equal(restored.stats().exchangeCount, 1);
  } finally {
    restored.close();
  }

  console.log(`project-store-crash-recovery: replayed pending journal, preserved full secrets, created restore point, and reopened backup from ${backup.backupDir}`);
} finally {
  recoveredStore?.close();
}
