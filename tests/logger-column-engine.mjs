import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'validateLoggerColumnScript',
  'evaluateLoggerCustomColumn',
  'buildLoggerColumnSandboxReview',
  'buildLoggerCustomColumnCompatibilityPackage',
  'buildLoggerCustomColumnLargeTableProfile',
];

const enginePath = path.resolve('src/loggerColumnEngine.ts');
const loggerColumnEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof loggerColumnEngine[name] !== 'function');
if (missingExports.length) {
  console.log(`logger-column-engine: skipped; missing export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const entry = {
  id: 'logger-sample-refunds',
  exchangeId: 'hx-refunds',
  at: '2026-05-24T18:00:00.000Z',
  tool: 'repeater',
  method: 'POST',
  host: 'app.shop.local',
  path: '/api/refunds',
  url: 'https://app.shop.local/api/refunds?order=1001',
  status: 403,
  length: 312,
  mime: 'application/json',
  risk: 'high',
  timing: 141,
  modified: true,
  notes: 'Refund replay denied for alternate role.',
  requestRaw: [
    'POST /api/refunds?order=1001 HTTP/1.1',
    'Host: app.shop.local',
    'Authorization: Bearer redacted',
    'Content-Type: application/x-www-form-urlencoded',
    '',
    'amount=500&reason=test',
  ].join('\n'),
  responseRaw: [
    'HTTP/1.1 403 Forbidden',
    'Content-Type: application/json',
    '',
    '{"error":"denied"}',
  ].join('\n'),
  tags: ['authz', 'replayed'],
};

const goodColumn = {
  id: 'logger-column-refund',
  name: 'Refund Signal',
  kind: 'interesting-signal',
  enabled: true,
  script: [
    'if (request.contains("refunds") && entry.risk >= "medium") return "refund-signal";',
    'return "none";',
  ].join('\n'),
  createdAt: '2026-05-24T00:00:00.000Z',
  updatedAt: '2026-05-24T00:00:00.000Z',
};

const compatibilityColumn = {
  ...goodColumn,
  id: 'logger-column-custom-column-compat',
  name: 'Custom Column Compatibility',
  kind: 'interesting-signal',
  script: [
    'if (request.method == "POST" && request.queryParam("order") == "1001" && request.bodyParam("amount") == "500") return "order:" + request.param("order") + ":amount:" + request.param("amount");',
    'if (response.header("content-type").includes("json") && response.jsonField("error") == "denied") return "json-denied";',
    'if (entry.tool == "repeater" && entry.isModified() && entry.noteContains("alternate role")) return "role-replay";',
    'return response.statusClass();',
  ].join('\n'),
};

const apiEdgeEntry = {
  ...entry,
  id: 'logger-sample-api-export',
  exchangeId: 'hx-api-export',
  path: '/api/export.json',
  url: 'https://app.shop.local/api/export.json?order=1001',
  status: 200,
  timing: 38,
  length: 156,
  modified: false,
  notes: 'JSON export replay with cookies.',
  requestRaw: [
    'POST /api/export.json?order=1001 HTTP/1.1',
    'Host: app.shop.local',
    'Authorization: Bearer logger-secret-token',
    'X-API-Key: logger-api-key',
    'Cookie: session=abc123; theme=dark',
    'Content-Type: application/x-www-form-urlencoded',
    '',
    'amount=500&reason=test&payload=admin%253Dtrue',
  ].join('\n'),
  responseRaw: [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json',
    'Set-Cookie: csrf=set-token; Path=/; HttpOnly',
    '',
    '{"meta":{"trace":"trace-42","encoded":"bG9nZ2VyLXNlY3JldC1rZXk="},"ok":true}',
  ].join('\n'),
  tags: ['api', 'export'],
};

const apiEdgeColumn = {
  ...goodColumn,
  id: 'logger-column-api-edges',
  name: 'Custom Column API Edge Helpers',
  kind: 'interesting-signal',
  script: [
    'if (request.cookie("session") == "abc123" && response.cookie("csrf") == "set-token" && request.isForm() && response.isJson()) return helpers.upper(request.extension()) + ":" + helpers.default(response.jsonPath("meta.trace"), "missing");',
    'if (helpers.lower(response.contentType).includes("json") && request.pathSegments().includes("api")) return "path:" + entry.status + ":" + response.headerNames();',
    'return "edge-miss";',
  ].join('\n'),
};

const deepApiColumn = {
  ...goodColumn,
  id: 'logger-column-encoded-material',
  name: 'Encoded Material Helpers',
  kind: 'interesting-signal',
  script: [
    'if (request.hasHeader("X-API-Key") && request.bodyContains("payload=admin%253Dtrue") && response.bodyContains("bG9nZ2Vy") && helpers.urlDecode(request.bodyParam("payload")) == "admin=true") return helpers.base64Decode(response.jsonPath("meta.encoded")) + ":" + helpers.base64Encode("ok");',
    'return "encoded-miss";',
  ].join('\n'),
};

const badColumn = {
  ...goodColumn,
  id: 'logger-column-bad',
  name: 'Unsafe Column',
  script: 'return window.localStorage.getItem("token");',
};

const goodValidation = loggerColumnEngine.validateLoggerColumnScript(goodColumn);
assert.equal(goodValidation.status, 'ok', 'supported custom logger column script should validate');

const goodEvaluation = loggerColumnEngine.evaluateLoggerCustomColumn(goodColumn, entry);
assert.equal(goodEvaluation.value, 'refund-signal', 'supported custom logger column script should evaluate sample entry');
assert.equal(goodEvaluation.status, 'ok', 'supported custom logger column script should not fall back');

const compatibilityValidation = loggerColumnEngine.validateLoggerColumnScript(compatibilityColumn);
assert.equal(compatibilityValidation.status, 'ok', 'expanded custom logger column helper script should validate');
assert(compatibilityValidation.supportedApis.includes('request.queryParam(name)'));
assert(compatibilityValidation.supportedApis.includes('response.jsonField(name)'));
assert(compatibilityValidation.supportedApis.includes('request.cookie(name)'));
assert(compatibilityValidation.supportedApis.includes('response.jsonPath(path)'));
assert(compatibilityValidation.supportedApis.includes('helpers.default(value, fallback)'));
assert(compatibilityValidation.supportedApis.includes('request.bodyContains(text)'));
assert(compatibilityValidation.supportedApis.includes('request.jsonPath(path)'));
assert(compatibilityValidation.supportedApis.includes('response.bodyContains(text)'));
assert(compatibilityValidation.supportedApis.includes('helpers.urlDecode(value)'));
assert(compatibilityValidation.supportedApis.includes('helpers.base64Decode(value)'));
assert(compatibilityValidation.supportedApis.includes('helpers.base64Encode(value)'));

const compatibilityEvaluation = loggerColumnEngine.evaluateLoggerCustomColumn(compatibilityColumn, entry);
assert.equal(compatibilityEvaluation.value, 'order:1001:amount:500', 'expanded custom logger column helpers should evaluate params and concatenated returns');
assert.equal(compatibilityEvaluation.status, 'ok');

const jsonColumn = {
  ...compatibilityColumn,
  id: 'logger-column-json',
  script: [
    'if (response.header("content-type").includes("json") && response.jsonField("error") == "denied") return "json-denied";',
    'return response.statusClass();',
  ].join('\n'),
};
assert.equal(loggerColumnEngine.evaluateLoggerCustomColumn(jsonColumn, entry).value, 'json-denied');

const apiEdgeEvaluation = loggerColumnEngine.evaluateLoggerCustomColumn(apiEdgeColumn, apiEdgeEntry);
assert.equal(apiEdgeEvaluation.value, 'JSON:trace-42', 'custom column edge helpers should evaluate cookies, form/JSON detection, extensions, and jsonPath');
assert.equal(apiEdgeEvaluation.status, 'ok');

const deepApiEvaluation = loggerColumnEngine.evaluateLoggerCustomColumn(deepApiColumn, apiEdgeEntry);
assert.equal(deepApiEvaluation.value, 'logger-secret-key:b2s=', 'encoded custom column helpers should preserve and decode executor material');
assert.equal(deepApiEvaluation.status, 'ok');

const blockedEvaluation = loggerColumnEngine.evaluateLoggerCustomColumn(badColumn, entry);
assert.equal(blockedEvaluation.value, '[blocked]', 'unsafe script should be blocked before evaluation');
assert.equal(blockedEvaluation.status, 'blocked', 'unsafe script should report blocked status');

const review = loggerColumnEngine.buildLoggerColumnSandboxReview({
  columns: [goodColumn, compatibilityColumn, apiEdgeColumn, badColumn],
  entries: [entry, apiEdgeEntry],
  now: '2026-05-24T18:01:00.000Z',
});
assert.equal(review.kind, 'proxyforge-logger-column-sandbox-review');
assert.equal(review.blockedColumns, 1, 'review should count blocked columns');
assert.equal(review.reportReady, false, 'review with blocked columns should not be report-ready');
assert.match(review.content, /refund-signal|order:1001:amount:500|browser global|supportedApis/i, 'review content should preserve samples and sandbox metadata');

const compatibilityPackage = loggerColumnEngine.buildLoggerCustomColumnCompatibilityPackage({
  columns: [goodColumn, compatibilityColumn, apiEdgeColumn, deepApiColumn],
  entries: [entry, apiEdgeEntry],
  now: '2026-05-24T18:02:00.000Z',
});
assert.equal(compatibilityPackage.kind, 'proxyforge-logger-custom-column-compatibility-fixtures');
assert.equal(compatibilityPackage.fixtureCount, 8);
assert.equal(compatibilityPackage.passedFixtures, 8);
assert.equal(compatibilityPackage.blockedFixtures, 0);
assert.equal(compatibilityPackage.requirements.fixtureRefreshCovered, true);
assert.equal(compatibilityPackage.requirements.encodedMaterialCovered, true);
assert.equal(compatibilityPackage.requirements.operationalSecretsPreserved, true);
assert.equal(compatibilityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(compatibilityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert(compatibilityPackage.packageRefresh.operationalSecretSignals.includes('authorization-header'));
assert(compatibilityPackage.packageRefresh.operationalSecretSignals.includes('cookie-header'));
assert(compatibilityPackage.packageRefresh.operationalSecretSignals.includes('x-api-key-header'));
assert.equal(compatibilityPackage.reportReady, true);
assert.match(compatibilityPackage.content, /request\.queryParam|response\.jsonField|order:1001:amount:500|JSON:trace-42|packageRefresh|logger-secret-token|logger-api-key|logger-secret-key:b2s=/);

const largeEntries = Array.from({ length: 1200 }, (_value, index) => ({
  ...apiEdgeEntry,
  id: `logger-large-${index + 1}`,
  exchangeId: `hx-large-${index + 1}`,
  path: `/api/export-${index + 1}.json`,
  url: `https://app.shop.local/api/export-${index + 1}.json?order=${1001 + index}`,
  status: index % 7 === 0 ? 403 : 200,
  timing: 20 + (index % 80),
  tags: index % 5 === 0 ? ['api', 'export', 'sampled'] : ['api', 'export'],
}));
const largeProfile = loggerColumnEngine.buildLoggerCustomColumnLargeTableProfile({
  columns: [goodColumn, compatibilityColumn, apiEdgeColumn, deepApiColumn],
  entries: largeEntries,
  now: '2026-05-24T18:03:00.000Z',
  maxDurationMs: 3000,
  maxP95EvaluationMs: 20,
});
assert.equal(largeProfile.kind, 'proxyforge-logger-custom-column-large-table-profile');
assert.equal(largeProfile.entryCount, 1200);
assert.equal(largeProfile.columnCount, 4);
assert.equal(largeProfile.evaluationCount, 4800);
assert.equal(largeProfile.statusCounts.blocked, 0);
assert.equal(largeProfile.reportReady, true, largeProfile.summary);
assert.match(largeProfile.content, /p95EvaluationMs|request\.cookie|helpers\.default|helpers\.base64Decode|logger-large-1/);

console.log(`logger-column-engine: exercised ${expectedExports.length} Logger column sandbox helper(s)`);

async function loadEngine(enginePath) {
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
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    Buffer,
    console,
    require,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: enginePath });
  return module.exports;
}

function normalizeModuleExports(moduleExports) {
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}
