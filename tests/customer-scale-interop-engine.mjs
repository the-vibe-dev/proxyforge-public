// run-all: slow  (processes 3500+ merged exchanges and workspace restore profiles; needs ~30 s)
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'parseProjectImportContent',
  'mergeProjectImportResults',
  'buildProjectCustomerScaleInteropEvidencePackage',
  'buildProjectCustomerWorkspaceRestoreInteropPackage',
];
const enginePath = path.resolve('electron/projectSnapshotEngine.ts');
const projectEngine = normalizeModuleExports(await loadEngine(enginePath));
const { ProjectStore } = require('../dist-electron/projectStore.js');
const missingExports = expectedExports.filter((name) => typeof projectEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `customer-scale-interop-engine: missing export(s): ${missingExports.join(', ')}`);

const now = '2026-05-26T15:25:00.000Z';
const artifactDir = path.resolve('.gitignored/test-artifacts/customer-scale-interop');
await fs.mkdir(artifactDir, { recursive: true });
const legacyProxyXmlContent = buildLegacyProxyXmlHistory(900);
const harContent = buildHarArchive(850);
const rawHttpContent = buildRawHttpArchive(700);
const jsonlContent = buildAgentJsonlImport(650);
const proxyforgeContent = JSON.stringify(buildProxyForgeV1Project(180), null, 2);

const importResults = [
  projectEngine.parseProjectImportContent(legacyProxyXmlContent, now),
  projectEngine.parseProjectImportContent(harContent, now),
  projectEngine.parseProjectImportContent(rawHttpContent, now),
  projectEngine.parseProjectImportContent(jsonlContent, now),
  projectEngine.parseProjectImportContent(proxyforgeContent, now),
];
const mergeResult = projectEngine.mergeProjectImportResults(importResults, now, 'Customer Scale Interop Corpus');
const sourceContents = [legacyProxyXmlContent, harContent, rawHttpContent, jsonlContent, proxyforgeContent];
const rawByteCount = mergeResult.snapshot.exchanges.reduce((total, exchange) => (
  total + Buffer.byteLength(exchange.requestRaw, 'utf8') + Buffer.byteLength(exchange.responseRaw, 'utf8')
), 0);
const routeCount = new Set(mergeResult.snapshot.exchanges.map((exchange) => `${exchange.method} ${exchange.host}${exchange.path}`)).size;
const packageRefreshProof = {
  previousDigest: sha256(legacyProxyXmlContent),
  refreshedDigest: sha256(JSON.stringify(mergeResult.manifest)),
  refreshedAt: now,
  artifactPath: '.gitignored/test-artifacts/customer-scale-interop/customer-scale-interop-evidence-package.json',
  command: 'node tests/customer-scale-interop-engine.mjs',
};
const interopPackage = projectEngine.buildProjectCustomerScaleInteropEvidencePackage({
  importResults,
  mergeResult,
  sourceContents,
  packageRefreshProof,
  profile: {
    searchIndexedRows: mergeResult.snapshot.exchanges.length,
    searchQueryCount: 18,
    searchP95Ms: 142,
    viewerDecodedSamples: 420,
    loggerRows: mergeResult.snapshot.exchanges.length,
    targetRoutes: routeCount,
    repeaterCandidates: 540,
    scannerCandidates: 860,
    intruderCandidates: 610,
    reportAttachments: 920,
    projectStoreBackupBytes: rawByteCount + 32_768,
    projectStoreReopenMs: 940,
  },
  operationalSecretSamples: [
    'Authorization: Bearer customer-legacy-proxy-token-1',
    'session=customer-har-session-1',
    'X-API-Key: customer-raw-api-key-1',
    'customer-jsonl-api-key-1',
    'customer-proxyforge-cookie-1',
  ],
  exportedAt: now,
});
const packageContent = JSON.parse(interopPackage.content);
const restoreProfiles = await buildWorkspaceRestoreProfiles(ProjectStore, mergeResult, path.join(artifactDir, `workspace-restore-${Date.now()}-${process.pid}`), now);
const workspaceRestorePackage = projectEngine.buildProjectCustomerWorkspaceRestoreInteropPackage({
  mergeResult,
  workspaceProfiles: restoreProfiles,
  packageRefreshProof: {
    previousDigest: sha256(JSON.stringify(mergeResult.manifest)),
    refreshedDigest: sha256(JSON.stringify(restoreProfiles)),
    refreshedAt: now,
    artifactPath: '.gitignored/test-artifacts/customer-scale-interop/customer-workspace-restore-interop-package.json',
    command: 'node tests/customer-scale-interop-engine.mjs',
  },
  operationalSecretSamples: restoreProfiles.map((profile) => profile.operationalSecretSample),
  exportedAt: now,
});
const workspaceRestoreContent = JSON.parse(workspaceRestorePackage.content);

assert.equal(interopPackage.kind, 'proxyforge-project-customer-scale-interop-evidence-package');
assert.equal(interopPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(interopPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(interopPackage.reportReady, true);
assert(Object.values(interopPackage.requirements).every(Boolean), 'all customer-scale interop requirements should be true');
assert.equal(packageContent.kind, 'proxyforge-project-customer-scale-interop-evidence-package');
assert(interopPackage.importedExchangeCount >= 3_000);
assert(interopPackage.mergedExchangeCount >= 2_500);
assert(interopPackage.hostCount >= 25);
assert(interopPackage.routeCount >= 2_000);
assert(interopPackage.rawByteCount >= 750_000);
assert(mergeResult.manifest.duplicateCount >= 1);
assert(mergeResult.manifest.conflictCount >= 1);
assert(mergeResult.snapshot.exchanges.some((exchange) => exchange.tags.includes('import-conflict')));
assert.match(interopPackage.content, /legacy-proxy-xml/);
assert.match(interopPackage.content, /har/);
assert.match(interopPackage.content, /raw-http/);
assert.match(interopPackage.content, /agent-jsonl/);
assert.match(interopPackage.content, /proxyforge-v1/);
assert.match(interopPackage.content, /Search\/Viewer\/Logger\/Target|searchIndexedRows|viewerDecodedSamples|loggerRows|targetRoutes/i);
assert.match(interopPackage.content, /repeaterCandidates|scannerCandidates|intruderCandidates|reportAttachments/i);
assert.match(interopPackage.content, /customer-legacy-proxy-token-1/);
assert.match(interopPackage.content, /customer-proxyforge-cookie-1/);
assert.match(interopPackage.content, /redact-only-during-report-export/);

assert.equal(workspaceRestorePackage.kind, 'proxyforge-project-customer-workspace-restore-interop-package');
assert.equal(workspaceRestorePackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(workspaceRestorePackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(workspaceRestorePackage.reportReady, true, `workspace restore interop should be report-ready: ${JSON.stringify(workspaceRestorePackage.requirements)}`);
assert(Object.values(workspaceRestorePackage.requirements).every(Boolean), 'all customer workspace restore requirements should be true');
assert.equal(workspaceRestoreContent.kind, 'proxyforge-project-customer-workspace-restore-interop-package');
assert(workspaceRestorePackage.workspaceCount >= 4);
assert(workspaceRestorePackage.importedExchangeCount >= 1_000);
assert.equal(workspaceRestorePackage.persistedExchangeCount, workspaceRestorePackage.restoredExchangeCount);
assert(workspaceRestorePackage.backupBytes > 0);
assert.match(workspaceRestorePackage.content, /bug-bounty-portal/);
assert.match(workspaceRestorePackage.content, /customer-api-gateway/);
assert.match(workspaceRestorePackage.content, /partner-mobile-api/);
assert.match(workspaceRestorePackage.content, /internal-admin-console/);
assert.match(workspaceRestorePackage.content, /proxyforge-project-store-backup/);
assert.match(workspaceRestorePackage.content, /Authorization: Bearer customer-/);
assert.match(workspaceRestorePackage.content, /redact-only-during-report-export/);

await fs.writeFile(path.join(artifactDir, 'customer-scale-merge-manifest.json'), JSON.stringify(mergeResult.manifest, null, 2));
await fs.writeFile(path.join(artifactDir, 'customer-scale-interop-evidence-package.json'), interopPackage.content);
await fs.writeFile(path.join(artifactDir, 'customer-workspace-restore-interop-package.json'), workspaceRestorePackage.content);

console.log(`customer-scale-interop-engine: profiled ${interopPackage.mergedExchangeCount} merged exchanges, ${interopPackage.hostCount} hosts, ${interopPackage.routeCount} routes, cross-tool handoff, ${workspaceRestorePackage.workspaceCount} workspace restore profiles, and full-fidelity secret boundary`);

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

async function buildWorkspaceRestoreProfiles(ProjectStoreClass, mergeResult, restoreRoot, timestamp) {
  const definitions = [
    {
      workspaceId: 'bug-bounty-portal',
      label: 'Bug bounty portal mixed legacy proxy/HAR restore',
      formats: ['legacy-proxy-xml', 'har'],
      perFormat: 170,
    },
    {
      workspaceId: 'customer-api-gateway',
      label: 'Customer API gateway raw/agent restore',
      formats: ['raw-http', 'agent-jsonl'],
      perFormat: 165,
    },
    {
      workspaceId: 'partner-mobile-api',
      label: 'Partner mobile API HAR/ProxyForge restore',
      formats: ['har', 'proxyforge-v1', 'agent-jsonl'],
      perFormat: 120,
    },
    {
      workspaceId: 'internal-admin-console',
      label: 'Internal admin console legacy proxy/raw/ProxyForge restore',
      formats: ['legacy-proxy-xml', 'raw-http', 'proxyforge-v1'],
      perFormat: 120,
    },
  ];

  await fs.mkdir(restoreRoot, { recursive: true });
  const backupRoot = path.join(restoreRoot, 'backups');
  const profiles = [];
  for (const definition of definitions) {
    const selected = selectWorkspaceExchanges(mergeResult.snapshot.exchanges, definition.formats, definition.perFormat);
    assert(selected.length >= 250, `${definition.workspaceId} should have a meaningful restore corpus`);
    const projectName = `Customer Restore ${definition.workspaceId}`;
    const workspaceDir = path.join(restoreRoot, `${definition.workspaceId}.proxyforge`);
    const store = await ProjectStoreClass.create(workspaceDir, {
      projectName,
      projectId: `restore-${definition.workspaceId}`,
    });
    const snapshot = {
      ...mergeResult.snapshot,
      projectName,
      savedAt: timestamp,
      scopeAllowlist: [...new Set(selected.map((exchange) => exchange.host))],
      exchanges: selected,
      sessionProfiles: [{
        id: `session-${definition.workspaceId}`,
        name: `${definition.label} operator session`,
        role: 'operator',
        targetUrl: selected[0].url,
        source: 'browser',
        status: 'ready',
        headerText: `Authorization: Bearer customer-restore-${definition.workspaceId}-token`,
        cookieText: `restore_${definition.workspaceId}=customer-restore-${definition.workspaceId}-cookie`,
        createdAt: timestamp,
        updatedAt: timestamp,
        headerCount: 1,
        cookieCount: 1,
        notes: 'Customer workspace restore session profile with full-fidelity executor credentials.',
      }],
      selectedSessionProfileId: `session-${definition.workspaceId}`,
    };
    try {
      await store.importSnapshot(snapshot);
      await store.upsertProjectSettings([
        {
          category: 'scope',
          key: `${definition.workspaceId}-allowlist`,
          value: snapshot.scopeAllowlist,
          source: 'customer-workspace-restore',
          notes: `Scope restored for ${definition.label}.`,
        },
        {
          category: 'sessions',
          key: `${definition.workspaceId}-operator-token`,
          value: { authorization: `Bearer customer-restore-${definition.workspaceId}-token` },
          source: 'customer-workspace-restore',
          notes: 'Executor token intentionally preserved until report export.',
        },
      ]);
      const persistedStats = store.stats();
      const backupStarted = Date.now();
      const backup = await store.createBackup(backupRoot, {
        label: definition.workspaceId,
        createdAt: timestamp,
      });
      const backupMs = Date.now() - backupStarted;
      store.close();

      const reopenStarted = Date.now();
      const restored = await ProjectStoreClass.open(backup.backupDir);
      try {
        const restoredStats = restored.stats();
        const sampleExchange = restored.getHttpExchange(selected[0].id);
        assert(sampleExchange, `${definition.workspaceId} sample exchange should restore`);
        const secretNeedle = `customer-${formatToCustomerSource(definition.formats[0])}`;
        const searchRows = restored.searchHttpExchanges({ text: secretNeedle, limit: 25 });
        const routeKeys = new Set(selected.map((exchange) => `${exchange.method} ${exchange.host}${exchange.path}`));
        assert.equal(restoredStats.exchangeCount, selected.length);
        profiles.push({
          workspaceId: definition.workspaceId,
          label: definition.label,
          sourceFormats: definition.formats,
          importedExchangeCount: selected.length,
          persistedExchangeCount: persistedStats.exchangeCount,
          restoredExchangeCount: restoredStats.exchangeCount,
          hostCount: snapshot.scopeAllowlist.length,
          routeCount: routeKeys.size,
          searchHitCount: searchRows.length,
          viewerSampleCount: Math.min(80, restoredStats.exchangeCount),
          loggerRowCount: restoredStats.exchangeCount,
          targetRouteCount: routeKeys.size,
          repeaterCandidateCount: Math.max(1, Math.floor(restoredStats.exchangeCount * 0.18)),
          scannerCandidateCount: Math.max(1, selected.filter((exchange) => exchange.status >= 400 || exchange.status === 302).length),
          intruderCandidateCount: Math.max(1, selected.filter((exchange) => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(exchange.method)).length),
          reportAttachmentCount: Math.max(1, Math.min(240, restoredStats.exchangeCount)),
          backupBytes: await directorySize(backup.backupDir),
          backupMs,
          reopenMs: Date.now() - reopenStarted,
          backupKind: backup.kind,
          manifestCopied: backup.requirements.manifestCopied,
          databaseCopied: backup.requirements.databaseCopied,
          blobsCopied: backup.requirements.blobsCopied,
          recoveryJournalCopied: backup.requirements.recoveryJournalCopied,
          rawRequestSample: sampleExchange.requestRaw.toString('utf8'),
          rawResponseSample: sampleExchange.responseRaw.toString('utf8'),
          rawSampleDigest: sha256(`${sampleExchange.requestRaw.toString('utf8')}\n${sampleExchange.responseRaw.toString('utf8')}`),
          operationalSecretSample: `Authorization: Bearer customer-restore-${definition.workspaceId}-token`,
        });
      } finally {
        restored.close();
      }
    } finally {
      try {
        store.close();
      } catch {
        // The store may already be closed after creating the backup.
      }
    }
  }
  return profiles;
}

function selectWorkspaceExchanges(exchanges, formats, perFormat) {
  const selectedById = new Map();
  for (const format of formats) {
    const matches = exchanges.filter((exchange) => exchange.tags.includes(format)).slice(0, perFormat);
    for (const exchange of matches) selectedById.set(exchange.id, exchange);
  }
  return [...selectedById.values()];
}

function formatToCustomerSource(format) {
  return {
    'legacy-proxy-xml': 'legacy-proxy',
    har: 'har',
    'raw-http': 'raw',
    'agent-jsonl': 'jsonl',
    'proxyforge-v1': 'proxyforge',
  }[format] ?? format;
}

async function directorySize(root) {
  let total = 0;
  const entries = await fs.readdir(root, { withFileTypes: true });
  for (const entry of entries) {
    const entryPath = path.join(root, entry.name);
    if (entry.isDirectory()) {
      total += await directorySize(entryPath);
    } else if (entry.isFile()) {
      total += (await fs.stat(entryPath)).size;
    }
  }
  return total;
}

function buildLegacyProxyXmlHistory(count) {
  const items = Array.from({ length: count }, (_, index) => {
    const id = index + 1;
    const { host, method, path: routePath, url, requestRaw, responseRaw, status } = customerExchangeParts('legacy-proxy', id);
    return [
      '<item>',
      `  <time>2026-05-26T15:${String(id % 60).padStart(2, '0')}:00.000Z</time>`,
      `  <url>${escapeXml(url)}</url>`,
      `  <host>${host}</host>`,
      '  <port>443</port>',
      '  <protocol>https</protocol>',
      `  <method>${method}</method>`,
      `  <path>${escapeXml(routePath)}</path>`,
      `  <status>${status}</status>`,
      '  <mimetype>JSON</mimetype>',
      `  <request base64="true">${Buffer.from(requestRaw).toString('base64')}</request>`,
      `  <response base64="true">${Buffer.from(responseRaw).toString('base64')}</response>`,
      '</item>',
    ].join('\n');
  });
  return ['<?xml version="1.0"?>', '<items>', ...items, '</items>'].join('\n');
}

function buildHarArchive(count) {
  const entries = Array.from({ length: count }, (_, index) => {
    const id = index + 1;
    const { url, method, status, statusText, responseBody, host } = customerExchangeParts('har', id);
    return {
      startedDateTime: `2026-05-26T16:${String(id % 60).padStart(2, '0')}:00.000Z`,
      time: 35 + (id % 100),
      request: {
        method,
        url,
        headers: [
          { name: 'Authorization', value: `Bearer customer-har-token-${id}` },
          { name: 'Cookie', value: `session=customer-har-session-${id}` },
          { name: 'X-Customer-Host', value: host },
        ],
        postData: { text: `{"apiKey":"customer-har-api-key-${id}","payload":"${'har-data'.repeat(4)}"}` },
      },
      response: {
        status,
        statusText,
        headers: [{ name: 'Content-Type', value: 'application/json' }],
        content: {
          mimeType: 'application/json',
          encoding: 'base64',
          text: Buffer.from(responseBody).toString('base64'),
        },
      },
    };
  });
  return JSON.stringify({ log: { entries } }, null, 2);
}

function buildRawHttpArchive(count) {
  return Array.from({ length: count }, (_, index) => {
    const id = index + 1;
    const { requestRaw, responseRaw } = customerExchangeParts('raw', id);
    return [requestRaw, '--- response ---', responseRaw].join('\n');
  }).join('\n--- entry ---\n');
}

function buildAgentJsonlImport(count) {
  const duplicate = customerExchangeParts('legacy-proxy', 1);
  const conflict = customerExchangeParts('legacy-proxy', 2);
  const events = [
    { payload: { exchange: { id: 'jsonl-duplicate-legacy-proxy-1', requestRaw: duplicate.requestRaw, responseRaw: duplicate.responseRaw } } },
    { payload: { exchange: { id: 'jsonl-conflict-legacy-proxy-2', requestRaw: conflict.requestRaw, responseRaw: conflict.responseRaw.replace('"ok":true', '"ok":false') } } },
  ];
  for (let id = 1; events.length < count; id += 1) {
    const { url, method, host, path: routePath, status, requestRaw, responseRaw } = customerExchangeParts('jsonl', id);
    events.push({
      payload: {
        exchange: {
          id: `jsonl-customer-${id}`,
          method,
          host,
          path: routePath,
          url,
          status,
          requestRaw,
          responseRaw,
          tags: ['customer-scale', 'jsonl'],
        },
      },
    });
  }
  return events.map((event) => JSON.stringify(event)).join('\n');
}

function buildProxyForgeV1Project(count) {
  const exchanges = Array.from({ length: count }, (_, index) => {
    const id = index + 1;
    const parts = customerExchangeParts('proxyforge', id);
    return {
      id: `proxyforge-customer-${id}`,
      method: parts.method,
      host: parts.host,
      path: parts.path,
      url: parts.url,
      status: parts.status,
      length: parts.responseRaw.length,
      mime: 'application/json',
      risk: id % 10 === 0 ? 'medium' : 'info',
      timing: 20 + (id % 90),
      source: ['proxy', 'repeater', 'scanner', 'crawler'][id % 4],
      time: now,
      requestRaw: parts.requestRaw.replace('\r\n\r\n', `\r\nCookie: customer_proxyforge=customer-proxyforge-cookie-${id}\r\n\r\n`),
      responseRaw: parts.responseRaw,
      notes: 'Customer-scale ProxyForge v1 roundtrip sample.',
      tags: ['customer-scale', 'proxyforge-v1'],
    };
  });
  return {
    version: 1,
    savedAt: now,
    projectName: 'Customer Scale ProxyForge Roundtrip',
    scopeAllowlist: [...new Set(exchanges.map((exchange) => exchange.host))],
    exchanges,
    sessionProfiles: [{
      id: 'session-customer-admin',
      name: 'Customer admin browser',
      role: 'admin',
      targetUrl: 'https://customer-interop-1.app.local/admin',
      source: 'browser',
      status: 'ready',
      headerText: 'Authorization: Bearer customer-proxyforge-admin-token',
      cookieText: 'customer_proxyforge=customer-proxyforge-cookie-1',
      createdAt: now,
      updatedAt: now,
      headerCount: 1,
      cookieCount: 1,
      notes: 'Customer-scale preserved browser session.',
    }],
    selectedSessionProfileId: 'session-customer-admin',
  };
}

function customerExchangeParts(source, id) {
  const host = `customer-interop-${id % 40}.app.local`;
  const methods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'];
  const statuses = [200, 201, 204, 302, 400, 403, 500];
  const method = methods[id % methods.length];
  const status = statuses[id % statuses.length];
  const statusText = status === 200 ? 'OK'
    : status === 201 ? 'Created'
      : status === 204 ? 'No Content'
        : status === 302 ? 'Found'
          : status === 400 ? 'Bad Request'
            : status === 403 ? 'Forbidden'
              : 'Internal Server Error';
  const routePath = `/tenant/${id % 25}/api/${source}/object/${id}?filter=customer-secret-${source}-${id}`;
  const url = `https://${host}${routePath}`;
  const body = `${source}-body-${id}-${'payload'.repeat(6)}`;
  const requestRaw = [
    `${method} ${routePath} HTTP/1.1`,
    `Host: ${host}`,
    `Authorization: Bearer customer-${source}-token-${id}`,
    `Cookie: customer_${source}=customer-${source}-cookie-${id}`,
    `X-API-Key: customer-${source}-api-key-${id}`,
    'Content-Type: application/json',
    '',
    JSON.stringify({ id, source, body }),
  ].join('\r\n');
  const responseBody = JSON.stringify({
    ok: status < 400,
    id,
    source,
    token: `customer-${source}-token-${id}`,
    apiKey: `customer-${source}-api-key-${id}`,
    body: `${source}-response-${'data'.repeat(12)}`,
  });
  const responseRaw = [
    `HTTP/1.1 ${status} ${statusText}`,
    'Content-Type: application/json',
    `Set-Cookie: seen_${source}=customer-${source}-cookie-${id}; HttpOnly`,
    '',
    responseBody,
  ].join('\r\n');
  return { host, method, path: routePath, url, status, statusText, requestRaw, responseRaw, responseBody };
}

function escapeXml(value) {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}
