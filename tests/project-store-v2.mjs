// run-all: slow  (writes 50 000 exchanges to SQLite and verifies search + import; needs ~20 s)
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  ProjectStore,
  validateProjectStoreImportEntries,
} = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-v2', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'store-v2-regression.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

const totalExchanges = 50_000;
const batchSize = 1_000;
const createdAt = '2026-05-25T20:00:00.000Z';
const store = await ProjectStore.create(projectDir, {
  projectName: 'Project Store v2 Regression',
  projectId: 'project-store-v2-regression',
});

try {
  await store.addScopeRule('127.0.0.1');
  await store.addScopeRule('*.fixture.local');

  const originalDateNow = Date.now;
  Date.now = () => 1779785130284;
  try {
    await Promise.all(Array.from({ length: 12 }, (_, index) => (
      store.addScopeRule(`concurrent-${index}.fixture.local`, 'include', 'concurrency-regression')
    )));
  } finally {
    Date.now = originalDateNow;
  }

  for (let start = 0; start < totalExchanges; start += batchSize) {
    const batch = [];
    for (let offset = 0; offset < batchSize && start + offset < totalExchanges; offset += 1) {
      const index = start + offset;
      const pathKey = index % 100;
      const status = index % 11 === 0 ? 403 : 200;
      batch.push({
        id: `hx-store-${index}`,
        method: index % 7 === 0 ? 'POST' : 'GET',
        url: `https://app.fixture.local/api/items/${pathKey}?q=store-v2-secret-${pathKey}`,
        host: 'app.fixture.local',
        path: `/api/items/${pathKey}?q=store-v2-secret-${pathKey}`,
        protocol: 'https',
        status,
        mime: 'application/json',
        timingMs: index % 250,
        source: index % 5 === 0 ? 'scanner' : 'proxy',
        tags: ['fixture', 'large-project', status === 403 ? 'authz' : 'ok'],
        notes: index === 42_424 ? 'needle-admin-token retained in durable metadata' : '',
        createdAt,
        requestRaw: [
          `GET /api/items/${pathKey}?q=store-v2-secret-${pathKey} HTTP/1.1`,
          'Host: app.fixture.local',
          `Authorization: Bearer store-v2-secret-${pathKey}`,
          'Cookie: pf_session=store-v2-cookie',
          '',
          '',
        ].join('\r\n'),
        responseRaw: [
          `HTTP/1.1 ${status} ${status === 403 ? 'Forbidden' : 'OK'}`,
          'Content-Type: application/json',
          '',
          JSON.stringify({
            id: pathKey,
            status,
            secretEcho: `store-v2-secret-${pathKey}`,
          }),
        ].join('\r\n'),
      });
    }
    await store.addHttpExchanges(batch);
  }

  let stats = store.stats();
  assert.equal(stats.schemaVersion, 2);
  assert.equal(stats.exchangeCount, totalExchanges);
  assert.equal(stats.scopeRuleCount, 14);
  assert(stats.blobCount <= 320, `blob dedupe should keep repeated raw bodies compact, got ${stats.blobCount}`);
  assert(stats.requestBytes > 0);
  assert(stats.responseBytes > 0);

  const authzRows = store.searchHttpExchanges({ statusMin: 400, statusMax: 499, limit: 25 });
  assert.equal(authzRows.length, 25);
  assert(authzRows.every((row) => row.status === 403));

  const textRows = store.searchHttpExchanges({ text: 'store-v2-secret-42', limit: 10 });
  assert.equal(textRows.length, 10);
  assert(textRows.every((row) => row.path.includes('store-v2-secret-42')));

  const full = store.getHttpExchange('hx-store-4242');
  assert(full);
  assert.match(full.requestRaw.toString('utf8'), /Authorization: Bearer store-v2-secret-42/);
  assert.match(full.responseRaw.toString('utf8'), /store-v2-secret-42/);
  assert.equal(full.tags.includes('large-project'), true);

  const manifest = store.exportManifest();
  assert.equal(manifest.kind, 'proxyforge-project-store');
  assert.equal(manifest.schemaVersion, 2);
  assert.equal(manifest.projectId, 'project-store-v2-regression');
  assert.match(manifest.updatedAt, /T/);
  store.close();

  const reopened = await ProjectStore.open(projectDir);
  try {
    const reopenedStats = reopened.stats();
    assert.deepEqual(
      {
        schemaVersion: reopenedStats.schemaVersion,
        exchangeCount: reopenedStats.exchangeCount,
        scopeRuleCount: reopenedStats.scopeRuleCount,
        requestBytes: reopenedStats.requestBytes,
        responseBytes: reopenedStats.responseBytes,
      },
      {
        schemaVersion: stats.schemaVersion,
        exchangeCount: stats.exchangeCount,
        scopeRuleCount: stats.scopeRuleCount,
        requestBytes: stats.requestBytes,
        responseBytes: stats.responseBytes,
      },
    );
    const reopenedNeedle = reopened.searchHttpExchanges({ text: 'needle-admin-token', limit: 1 });
    assert.equal(reopenedNeedle.length, 1);
    assert.equal(reopenedNeedle[0].id, 'hx-store-42424');

    const legacySnapshot = JSON.stringify({
      kind: 'proxyforge-project-legacy',
      name: 'Legacy Authz Import',
      targets: ['legacy.fixture.local'],
      traffic: [{
        id: 'hx-legacy-import',
        method: 'POST',
        url: 'https://legacy.fixture.local/api/graphql',
        statusCode: 200,
        contentType: 'application/json',
        rawRequest: 'POST /api/graphql HTTP/1.1\r\nHost: legacy.fixture.local\r\nAuthorization: Bearer legacy-token\r\n\r\n{"query":"{__schema{name}}"}',
        rawResponse: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
        tags: ['legacy', 'graphql'],
      }],
    });
    const imported = await reopened.importSnapshotContent(legacySnapshot, '2026-05-25T20:10:00.000Z');
    assert.equal(imported.version, 1);
    assert.equal(imported.projectName, 'Legacy Authz Import');
    assert.equal(reopened.getHttpExchange('hx-legacy-import').responseRaw.toString('utf8').includes('__schema'), true);

    const rawHttpImport = await reopened.importSnapshotContent([
      'POST /import/raw HTTP/1.1',
      'Host: raw-import.fixture.local',
      'Authorization: Bearer raw-import-token',
      'Cookie: raw_import_session=raw-import-cookie',
      '',
      '{"token":"raw-import-token"}',
      '--- response ---',
      'HTTP/1.1 202 Accepted',
      'Content-Type: application/json',
      '',
      '{"accepted":true,"session":"raw-import-cookie"}',
    ].join('\n'), '2026-05-25T20:11:00.000Z');
    assert.equal(rawHttpImport.exchanges.length, 1);
    assert.equal(rawHttpImport.exchanges[0].host, 'raw-import.fixture.local');
    assert.match(reopened.getHttpExchange(rawHttpImport.exchanges[0].id).requestRaw.toString('utf8'), /raw-import-token/);

    stats = reopened.stats();
    assert.equal(stats.exchangeCount, totalExchanges + 2);
    assert.equal(stats.scopeRuleCount, 16);
  } finally {
    reopened.close();
  }

  const acceptedPlan = validateProjectStoreImportEntries([
    'manifest.json',
    'project.db',
    'blobs/sha256/ab/cd/abcdef.bin',
  ]);
  assert.equal(acceptedPlan.accepted, true);
  assert.equal(acceptedPlan.requiredEntriesPresent, true);

  const rejectedPlan = validateProjectStoreImportEntries([
    'manifest.json',
    'project.db',
    '../secrets.txt',
    '/absolute/path',
    'C:/Users/operator/AppData/secret',
    'blobs//bad.bin',
  ]);
  assert.equal(rejectedPlan.accepted, false);
  assert(rejectedPlan.rejectedEntries.includes('../secrets.txt'));
  assert(rejectedPlan.rejectedEntries.includes('/absolute/path'));
  assert(rejectedPlan.rejectedEntries.includes('C:/Users/operator/AppData/secret'));
  assert(rejectedPlan.rejectedEntries.includes('blobs//bad.bin'));

  console.log(`project-store-v2: wrote ${totalExchanges} exchanges, reopened/search verified, imported legacy/raw HTTP snapshots, and rejected unsafe archive entries in ${projectDir}`);
} catch (error) {
  try {
    store.close();
  } catch {
    // ignore close errors while preserving the failing artifact directory
  }
  throw error;
}
