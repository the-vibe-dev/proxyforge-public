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
  'buildProjectImportCompatibilityEvidencePackage',
];
const enginePath = path.resolve('electron/projectSnapshotEngine.ts');
const projectEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof projectEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `project-import-compatibility-engine: missing export(s): ${missingExports.join(', ')}`);

const now = '2026-05-26T12:45:00.000Z';
const legacyProxyXmlContent = buildLegacyProxyXmlHistory(60);
const harContent = buildHarArchive(45);
const rawHttpContent = buildRawHttpArchive(30);
const jsonlContent = buildAgentJsonlImport(26);
const proxyforgeContent = JSON.stringify(buildProxyForgeV1Project(), null, 2);

const legacyProxyImport = projectEngine.parseProjectImportContent(legacyProxyXmlContent, now);
const harImport = projectEngine.parseProjectImportContent(harContent, now);
const rawImport = projectEngine.parseProjectImportContent(rawHttpContent, now);
const jsonlImport = projectEngine.parseProjectImportContent(jsonlContent, now);
const proxyforgeImport = projectEngine.parseProjectImportContent(proxyforgeContent, now);
const importResults = [legacyProxyImport, harImport, rawImport, jsonlImport, proxyforgeImport];

assert.equal(legacyProxyImport.sourceFormat, 'legacy-proxy-xml');
assert.equal(harImport.sourceFormat, 'har');
assert.equal(rawImport.sourceFormat, 'raw-http');
assert.equal(jsonlImport.sourceFormat, 'agent-jsonl');
assert.equal(proxyforgeImport.sourceFormat, 'proxyforge-v1');
assert.equal(legacyProxyImport.snapshot.exchanges.length, 60);
assert.equal(harImport.snapshot.exchanges.length, 45);
assert.equal(rawImport.snapshot.exchanges.length, 30);
assert.equal(jsonlImport.snapshot.exchanges.length, 26);
assert.equal(proxyforgeImport.snapshot.exchanges.length, 5);

const mergeResult = projectEngine.mergeProjectImportResults(importResults, now, 'Compatibility Import Corpus');
assert.equal(mergeResult.manifest.kind, 'proxyforge-project-import-merge-manifest');
assert.equal(mergeResult.manifest.sourceCount, 5);
assert(mergeResult.manifest.importedExchangeCount >= 160);
assert(mergeResult.manifest.mergedExchangeCount >= 150);
assert(mergeResult.manifest.duplicateCount >= 1);
assert(mergeResult.manifest.conflictCount >= 1);
assert(mergeResult.manifest.hosts.includes('compat.shop.local'));
assert(mergeResult.manifest.hosts.includes('har.compat.shop.local'));
assert(mergeResult.manifest.hosts.includes('raw.compat.shop.local'));
assert(mergeResult.manifest.hosts.includes('jsonl.compat.shop.local'));
assert(mergeResult.snapshot.exchanges.some((exchange) => exchange.tags.includes('import-conflict')));
assert.match(JSON.stringify(mergeResult), /Authorization: Bearer compat-legacy-proxy-token-1/);
assert.match(JSON.stringify(mergeResult), /session=compat-har-session-1/);
assert.match(JSON.stringify(mergeResult), /X-API-Key: compat-raw-api-key-1/);
assert.match(JSON.stringify(mergeResult), /compat-jsonl-token-duplicate/);

const previousDigest = sha256(legacyProxyXmlContent);
const refreshedDigest = sha256(JSON.stringify(mergeResult));
const compatibilityPackage = projectEngine.buildProjectImportCompatibilityEvidencePackage({
  importResults,
  mergeResult,
  sourceContents: [legacyProxyXmlContent, harContent, rawHttpContent, jsonlContent, proxyforgeContent],
  packageRefreshProof: {
    previousDigest,
    refreshedDigest,
    refreshedAt: now,
    artifactPath: '.gitignored/test-artifacts/project-import-compatibility/project-import-compatibility-evidence-package.json',
    command: 'node tests/project-import-compatibility-engine.mjs',
  },
  operationalSecretSamples: [
    'Authorization: Bearer compat-legacy-proxy-token-1',
    'session=compat-har-session-1',
    'X-API-Key: compat-raw-api-key-1',
    'compat-jsonl-token-duplicate',
    'compat-proxyforge-cookie-1',
  ],
  exportedAt: now,
});
const packageContent = JSON.parse(compatibilityPackage.content);

assert.equal(compatibilityPackage.kind, 'proxyforge-project-import-compatibility-evidence-package');
assert.equal(compatibilityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(compatibilityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(compatibilityPackage.reportReady, true);
assert(Object.values(compatibilityPackage.requirements).every(Boolean), 'all Project import compatibility requirements should be true');
assert.equal(packageContent.kind, 'proxyforge-project-import-compatibility-evidence-package');
assert.match(compatibilityPackage.content, /legacy-proxy-xml/);
assert.match(compatibilityPackage.content, /har/);
assert.match(compatibilityPackage.content, /raw-http/);
assert.match(compatibilityPackage.content, /agent-jsonl/);
assert.match(compatibilityPackage.content, /proxyforge-v1/);
assert.match(compatibilityPackage.content, /duplicate:/);
assert.match(compatibilityPackage.content, /conflict:/);
assert.match(compatibilityPackage.content, /compat-legacy-proxy-token-1/);
assert.match(compatibilityPackage.content, /compat-proxyforge-cookie-1/);
assert.match(compatibilityPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/project-import-compatibility');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'project-import-merge-manifest.json'), JSON.stringify(mergeResult.manifest, null, 2));
await fs.writeFile(path.join(artifactDir, 'project-import-compatibility-evidence-package.json'), compatibilityPackage.content);

console.log('project-import-compatibility-engine: exercised mixed legacy proxy XML/HAR/raw HTTP/JSONL/ProxyForge import corpus, dedupe/conflict merge diagnostics, package refresh proof, and full-fidelity secret boundary');

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

function buildLegacyProxyXmlHistory(count) {
  const items = Array.from({ length: count }, (_, index) => {
    const id = index + 1;
    const requestRaw = [
      `GET /api/item/${id}?secret=compat-token-${id} HTTP/1.1`,
      'Host: compat.shop.local',
      `Authorization: Bearer compat-legacy-proxy-token-${id}`,
      `Cookie: legacy_proxy_session=compat-legacy-proxy-cookie-${id}`,
      '',
      '',
    ].join('\r\n');
    const responseRaw = [
      'HTTP/1.1 200 OK',
      'Content-Type: application/json',
      '',
      `{"id":${id},"token":"compat-legacy-proxy-token-${id}"}`,
    ].join('\r\n');
    return [
      '<item>',
      `  <time>2026-05-26T12:${String(id).padStart(2, '0')}:00.000Z</time>`,
      `  <url>https://compat.shop.local/api/item/${id}?secret=compat-token-${id}</url>`,
      '  <host>compat.shop.local</host>',
      '  <port>443</port>',
      '  <protocol>https</protocol>',
      '  <method>GET</method>',
      `  <path>/api/item/${id}?secret=compat-token-${id}</path>`,
      '  <status>200</status>',
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
    return {
      startedDateTime: `2026-05-26T13:${String(id).padStart(2, '0')}:00.000Z`,
      time: 50 + id,
      request: {
        method: 'POST',
        url: `https://har.compat.shop.local/api/search/${id}?q=compat-har-secret-${id}`,
        headers: [
          { name: 'Authorization', value: `Bearer compat-har-token-${id}` },
          { name: 'Cookie', value: `session=compat-har-session-${id}` },
        ],
        postData: { text: `{"apiKey":"compat-har-api-key-${id}"}` },
      },
      response: {
        status: 207,
        statusText: 'Multi-Status',
        headers: [{ name: 'Content-Type', value: 'application/json' }],
        content: {
          mimeType: 'application/json',
          encoding: 'base64',
          text: Buffer.from(`{"echo":"compat-har-token-${id}","cookie":"compat-har-session-${id}"}`).toString('base64'),
        },
      },
    };
  });
  return JSON.stringify({ log: { entries } }, null, 2);
}

function buildRawHttpArchive(count) {
  return Array.from({ length: count }, (_, index) => {
    const id = index + 1;
    return [
      `PUT /raw/import/${id}?k=compat-raw-secret-${id} HTTP/1.1`,
      'Host: raw.compat.shop.local',
      `Authorization: Bearer compat-raw-token-${id}`,
      `X-API-Key: compat-raw-api-key-${id}`,
      '',
      `raw-body-${id}`,
      '--- response ---',
      'HTTP/1.1 201 Created',
      'Content-Type: text/plain',
      '',
      `compat-raw-token-${id} compat-raw-api-key-${id}`,
    ].join('\n');
  }).join('\n--- entry ---\n');
}

function buildAgentJsonlImport(count) {
  const events = Array.from({ length: count - 2 }, (_, index) => {
    const id = index + 1;
    return {
      payload: {
        exchange: {
          id: `jsonl-compat-${id}`,
          method: 'PATCH',
          url: `https://jsonl.compat.shop.local/api/jsonl/${id}`,
          requestRaw: [
            `PATCH /api/jsonl/${id} HTTP/1.1`,
            'Host: jsonl.compat.shop.local',
            `Authorization: Bearer compat-jsonl-token-${id}`,
            '',
            `{"key":"compat-jsonl-api-key-${id}"}`,
          ].join('\r\n'),
          responseRaw: [
            'HTTP/1.1 200 OK',
            'Content-Type: application/json',
            '',
            `{"token":"compat-jsonl-token-${id}"}`,
          ].join('\r\n'),
        },
      },
    };
  });
  const conflictEvent = {
    payload: {
      exchange: {
        id: 'jsonl-compat-conflict',
        method: 'GET',
        url: 'https://compat.shop.local/api/item/1?secret=compat-token-1',
        requestRaw: [
          'GET /api/item/1?secret=compat-token-1 HTTP/1.1',
          'Host: compat.shop.local',
          'Authorization: Bearer compat-jsonl-token-duplicate',
          '',
          '',
        ].join('\r\n'),
        responseRaw: [
          'HTTP/1.1 409 Conflict',
          'Content-Type: application/json',
          '',
          '{"token":"compat-jsonl-token-duplicate","conflict":true}',
        ].join('\r\n'),
      },
    },
  };
  events.push(conflictEvent, conflictEvent);
  return events.map((event) => JSON.stringify(event)).join('\n');
}

function buildProxyForgeV1Project() {
  return {
    version: 1,
    savedAt: '2026-05-26T12:40:00.000Z',
    projectName: 'ProxyForge v1 compatibility fixture',
    scopeAllowlist: ['proxyforge.compat.shop.local'],
    selectedSessionProfileId: 'session-proxyforge-1',
    sessionProfiles: [{
      id: 'session-proxyforge-1',
      name: 'ProxyForge imported operator',
      role: 'operator',
      targetUrl: 'https://proxyforge.compat.shop.local/',
      source: 'manual',
      status: 'ready',
      headerText: 'Authorization: Bearer compat-proxyforge-token-1',
      cookieText: 'compat-proxyforge-cookie-1=value',
      createdAt: '2026-05-26T12:40:00.000Z',
      updatedAt: '2026-05-26T12:40:00.000Z',
      headerCount: 1,
      cookieCount: 1,
      notes: 'Full-fidelity imported session.',
    }],
    exchanges: Array.from({ length: 5 }, (_, index) => {
      const id = index + 1;
      return {
        id: `proxyforge-compat-${id}`,
        method: 'GET',
        host: 'proxyforge.compat.shop.local',
        path: `/project/${id}`,
        url: `https://proxyforge.compat.shop.local/project/${id}`,
        status: 200,
        length: 32,
        mime: 'application/json',
        risk: 'info',
        timing: 12,
        notes: 'ProxyForge v1 roundtrip fixture.',
        source: 'proxy',
        time: '2026-05-26T12:40:00.000Z',
        requestRaw: [
          `GET /project/${id} HTTP/1.1`,
          'Host: proxyforge.compat.shop.local',
          `Cookie: compat-proxyforge-cookie-${id}=value`,
          '',
          '',
        ].join('\r\n'),
        responseRaw: [
          'HTTP/1.1 200 OK',
          'Content-Type: application/json',
          '',
          `{"cookie":"compat-proxyforge-cookie-${id}"}`,
        ].join('\r\n'),
        tags: ['proxyforge-v1'],
      };
    }),
  };
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}
