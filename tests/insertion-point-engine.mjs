import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');
const enginePath = path.resolve('src/insertionPointEngine.ts');
const engine = loadTsModule(enginePath);

assert.equal(typeof engine.extractInsertionPointsFromExchange, 'function');
assert.equal(typeof engine.extractInsertionPointsFromExchanges, 'function');
assert.equal(typeof engine.buildInsertionPointInventoryPackage, 'function');

const exchanges = buildCorpus();
const points = engine.extractInsertionPointsFromExchanges(exchanges);
const byType = new Map();
for (const point of points) byType.set(point.type, (byType.get(point.type) ?? 0) + 1);

for (const type of ['query', 'path', 'header', 'cookie', 'form', 'json', 'graphql', 'multipart', 'xml']) {
  assert(byType.get(type) > 0, `expected ${type} insertion points`);
}

assert(points.some((point) => point.type === 'header' && point.name === 'Authorization' && point.valuePreview.includes('Bearer insertion-secret-token')));
assert(points.some((point) => point.type === 'cookie' && point.name === 'session' && point.valuePreview.includes('insertion-session-secret')));
assert(points.some((point) => point.type === 'json' && point.name === 'variables.amount' && point.originalValue === 7900));
assert(points.some((point) => point.type === 'graphql' && point.name === 'variables.orderId' && point.valuePreview === 'ord_90210'));
assert(points.some((point) => point.type === 'multipart' && point.name === 'metadata' && point.valuePreview.includes('upload-secret-key')));
assert(points.some((point) => point.type === 'xml' && point.name === 'transfer@id' && point.valuePreview === 'xfer-123'));
assert(points.every((point) => point.exchangeId && point.routeId && point.evidence && point.notes.includes('report/export redaction')));

const packageResult = engine.buildInsertionPointInventoryPackage({
  exchanges,
  scopeAllowlist: ['app.shop.local'],
  now: '2026-05-25T20:00:00.000Z',
  operationalSecretSamples: [
    'Bearer insertion-secret-token',
    'insertion-session-secret',
    'upload-secret-key',
  ],
});

assert.equal(packageResult.kind, 'proxyforge-insertion-point-inventory-package');
assert.equal(packageResult.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(packageResult.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(packageResult.reportReady, true);
assert(Object.values(packageResult.requirements).every(Boolean), 'all insertion inventory requirements should be true');
assert.match(packageResult.content, /Bearer insertion-secret-token/);
assert.match(packageResult.content, /insertion-session-secret/);
assert.match(packageResult.content, /upload-secret-key/);
assert.match(packageResult.content, /rawExchanges/);
assert.match(packageResult.summary, /scanner-ready point/);

const artifactDir = path.resolve('.gitignored/test-artifacts/insertion-point-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'insertion-point-inventory.json'), packageResult.content);

console.log('insertion-point-engine: extracted scanner-ready query/path/header/cookie/form/json/graphql/multipart/xml insertion points');

function buildCorpus() {
  return [
    {
      id: 'hx-json-graphql',
      method: 'POST',
      host: 'app.shop.local',
      path: '/graphql?debug=true',
      url: 'https://app.shop.local/graphql?debug=true',
      status: 200,
      length: 512,
      mime: 'application/json',
      risk: 'high',
      timing: 42,
      notes: 'GraphQL mutation with operational tokens.',
      source: 'proxy',
      time: '20:00:01',
      tags: ['graphql', 'auth'],
      requestRaw: [
        'POST /graphql?debug=true HTTP/2',
        'Host: app.shop.local',
        'Authorization: Bearer insertion-secret-token',
        'Cookie: session=insertion-session-secret; csrf=insertion-csrf-secret',
        'X-CSRF-Token: insertion-csrf-secret',
        'Content-Type: application/json',
        '',
        JSON.stringify({
          query: 'mutation UpdateOrder($orderId: ID!, $amount: Int!) { updateOrder(id: $orderId, amount: $amount) { id } }',
          operationName: 'UpdateOrder',
          variables: { orderId: 'ord_90210', amount: 7900 },
          clientTrace: 'json-secret-key',
        }),
      ].join('\r\n'),
      responseRaw: 'HTTP/2 200 OK\r\nContent-Type: application/json\r\n\r\n{"ok":true}',
    },
    {
      id: 'hx-form-path',
      method: 'POST',
      host: 'app.shop.local',
      path: '/api/orders/ord_90210/refund?returnUrl=/orders',
      url: 'https://app.shop.local/api/orders/ord_90210/refund?returnUrl=/orders',
      status: 403,
      length: 128,
      mime: 'application/json',
      risk: 'medium',
      timing: 31,
      notes: 'Form submission creates path and form insertion points.',
      source: 'proxy',
      time: '20:00:02',
      tags: ['form'],
      requestRaw: [
        'POST /api/orders/ord_90210/refund?returnUrl=/orders HTTP/1.1',
        'Host: app.shop.local',
        'Content-Type: application/x-www-form-urlencoded',
        'Idempotency-Key: refund-secret-idempotency',
        '',
        'reason=manual+review&amount=7900&csrf=insertion-csrf-secret',
      ].join('\r\n'),
      responseRaw: 'HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\n\r\n{"error":"denied"}',
    },
    {
      id: 'hx-multipart',
      method: 'POST',
      host: 'app.shop.local',
      path: '/api/uploads',
      url: 'https://app.shop.local/api/uploads',
      status: 201,
      length: 144,
      mime: 'application/json',
      risk: 'medium',
      timing: 58,
      notes: 'Multipart upload with metadata field.',
      source: 'proxy',
      time: '20:00:03',
      tags: ['multipart'],
      requestRaw: [
        'POST /api/uploads HTTP/1.1',
        'Host: app.shop.local',
        'Content-Type: multipart/form-data; boundary=----pfboundary',
        '',
        '------pfboundary',
        'Content-Disposition: form-data; name="metadata"',
        '',
        '{"apiKey":"upload-secret-key","filename":"invoice.pdf"}',
        '------pfboundary',
        'Content-Disposition: form-data; name="file"; filename="invoice.pdf"',
        'Content-Type: application/pdf',
        '',
        '%PDF-1.7 fixture',
        '------pfboundary--',
      ].join('\r\n'),
      responseRaw: 'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{"stored":true}',
    },
    {
      id: 'hx-xml',
      method: 'POST',
      host: 'app.shop.local',
      path: '/xml/import',
      url: 'https://app.shop.local/xml/import',
      status: 200,
      length: 96,
      mime: 'application/xml',
      risk: 'medium',
      timing: 64,
      notes: 'XML import with attributes and text nodes.',
      source: 'proxy',
      time: '20:00:04',
      tags: ['xml'],
      requestRaw: [
        'POST /xml/import HTTP/1.1',
        'Host: app.shop.local',
        'Content-Type: application/xml',
        '',
        '<?xml version="1.0"?><transfer id="xfer-123"><amount>7900</amount><token>xml-secret-token</token></transfer>',
      ].join('\r\n'),
      responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"parsed":true}',
    },
  ];
}

function loadTsModule(filePath, cache = new Map()) {
  const resolved = path.resolve(filePath);
  if (cache.has(resolved)) return cache.get(resolved).exports;
  const source = fsSync.readFileSync(resolved, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: resolved,
  }).outputText;
  const module = { exports: {} };
  cache.set(resolved, module);
  const localRequire = (specifier) => {
    if (specifier.startsWith('.')) {
      const base = path.resolve(path.dirname(resolved), specifier);
      for (const candidate of [base, `${base}.ts`, `${base}.js`, path.join(base, 'index.ts'), path.join(base, 'index.js')]) {
        if (fsSync.existsSync(candidate) && fsSync.statSync(candidate).isFile()) {
          if (candidate.endsWith('.ts')) return loadTsModule(candidate, cache);
          return require(candidate);
        }
      }
    }
    return require(specifier);
  };
  const sandbox = {
    module,
    exports: module.exports,
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    Buffer,
    console,
    require: localRequire,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: resolved });
  return module.exports;
}
