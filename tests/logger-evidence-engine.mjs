import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = ['buildLoggerParityEvidencePackage'];
const enginePath = path.resolve('src/loggerEvidenceEngine.ts');
const loggerEvidenceEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof loggerEvidenceEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `logger-evidence-engine: missing export(s): ${missingExports.join(', ')}`);

const sample = buildSampleContext();
const parityPackage = loggerEvidenceEngine.buildLoggerParityEvidencePackage(sample);
const parityContent = JSON.parse(parityPackage.content);

assert.equal(parityPackage.kind, 'proxyforge-logger-parity-evidence-package');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.reportReady, true);
assert(Object.values(parityPackage.requirements).every(Boolean), 'all Logger parity requirements should be true');
assert.equal(parityPackage.requirements.customColumnPackageRefreshCovered, true);
assert.equal(parityPackage.entryCount, 8);
assert.equal(parityPackage.capturePresetCount, 2);
assert.equal(parityPackage.archiveImportReviewCount, 5);
assert.equal(parityPackage.savedFilterSetCount, 2);
assert.equal(parityPackage.reportAttachmentCount, 2);
assert.equal(parityContent.kind, 'proxyforge-logger-parity-evidence-package');
assert.match(parityPackage.content, /Authorization: Bearer logger-secret-token/);
assert.match(parityPackage.content, /session=logger-session/);
assert.match(parityPackage.content, /X-API-Key: logger-api-key/);
assert.match(parityPackage.content, /exact-duplicate|route-variant|new-route/);
assert.match(parityPackage.content, /proxyforge-logger-custom-column-compatibility-fixtures/);
assert.match(parityPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/logger-evidence-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'logger-parity-evidence-package.json'), parityPackage.content);

console.log('logger-evidence-engine: exercised Logger parity package, capture filters, archive conflict/dedupe review, report attachments, and full-fidelity raw material');

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

function buildSampleContext() {
  const now = '2026-05-25T20:15:00.000Z';
  const tools = ['proxy', 'target', 'repeater', 'scanner', 'intruder', 'exploit', 'automations', 'extensions'];
  const entries = tools.map((tool, index) => makeLoggerEntry(tool, index, now));
  const captureControls = tools.map((tool) => ({ tool, enabled: true, updatedAt: now }));
  const capturePresets = [
    {
      id: 'logger-preset-all-tools',
      name: 'All tool traffic',
      description: 'Capture every Logger source for broad triage.',
      pinned: true,
      controls: captureControls,
      createdAt: now,
      updatedAt: now,
    },
    {
      id: 'logger-preset-replay-review',
      name: 'Replay and scanner review',
      description: 'Focus on replay, scanner, exploit, and automation-generated evidence.',
      pinned: false,
      controls: tools.map((tool) => ({ tool, enabled: ['repeater', 'scanner', 'exploit', 'automations'].includes(tool), updatedAt: now })),
      createdAt: now,
      updatedAt: now,
    },
  ];
  const customColumns = [
    {
      id: 'logger-column-auth-state',
      name: 'Auth State',
      kind: 'auth-state',
      enabled: true,
      script: 'if (request.hasHeader("authorization")) return "auth"; return "anon";',
      createdAt: now,
      updatedAt: now,
    },
  ];
  const columnEvidencePackages = [
    { kind: 'proxyforge-logger-column-sandbox-review', reportReady: true, content: 'supportedApis request.header response.status' },
    { kind: 'proxyforge-logger-custom-column-compatibility-fixtures', reportReady: true, content: 'request.cookie response.jsonPath helpers.default helpers.urlDecode helpers.base64Decode packageRefresh fixtureRefreshCovered operationalSecretSignals logger-secret-token logger-api-key' },
    { kind: 'proxyforge-logger-custom-column-large-table-profile', reportReady: true, content: 'p95EvaluationMs logger-large-1' },
  ];
  const archiveMappingPresets = [
    makeMappingPreset('logger-map-preserve', 'Preserve import', 'proxy', 'preserve', now),
    makeMappingPreset('logger-map-report', 'Report evidence import', 'repeater', 'report-evidence', now),
    makeMappingPreset('logger-map-scanner', 'Scanner triage import', 'scanner', 'scanner-triage', now),
    makeMappingPreset('logger-map-replay', 'Replay proof import', 'proxy', 'replay-proof', now),
  ];
  const archiveImportReviews = [
    makeArchiveReview('logger-review-raw', 'raw-http', archiveMappingPresets[0], [entries[0]], now, {
      addedEntries: 1,
      duplicateEntries: 1,
      changedEntries: 0,
      conflictKinds: ['exact-duplicate'],
      replayCount: 1,
    }),
    makeArchiveReview('logger-review-har', 'har', archiveMappingPresets[1], [entries[1], entries[2]], now, {
      addedEntries: 1,
      duplicateEntries: 0,
      changedEntries: 1,
      conflictKinds: ['route-variant'],
      replayCount: 2,
    }),
    makeArchiveReview('logger-review-legacy-proxy', 'legacy-proxy-xml', archiveMappingPresets[2], [entries[3]], now, {
      addedEntries: 1,
      duplicateEntries: 0,
      changedEntries: 0,
      conflictKinds: ['new-route'],
      replayCount: 0,
    }),
    makeArchiveReview('logger-review-project', 'project', archiveMappingPresets[3], [entries[4]], now, {
      addedEntries: 1,
      duplicateEntries: 0,
      changedEntries: 0,
      conflictKinds: [],
      replayCount: 0,
    }),
    makeArchiveReview('logger-review-text', 'plain-text', archiveMappingPresets[0], [entries[5]], now, {
      addedEntries: 1,
      duplicateEntries: 0,
      changedEntries: 0,
      conflictKinds: [],
      replayCount: 0,
    }),
  ];
  const savedFilterSets = [
    {
      id: 'logger-filter-authz',
      name: 'High-risk authz traffic',
      predicates: {
        tools: ['proxy', 'repeater', 'scanner'],
        risks: ['high'],
        statuses: [403],
        text: 'refund',
        tags: ['authz'],
        modified: true,
      },
      matchedEntryIds: entries.slice(0, 3).map((entry) => entry.id),
      facetCounts: {
        tools: { proxy: 1, repeater: 1, scanner: 1 },
        risks: { high: 3 },
        statuses: { 403: 3 },
        tags: { authz: 3, replay: 1 },
      },
    },
    {
      id: 'logger-filter-generated',
      name: 'Generated tool traffic',
      predicates: {
        tools: ['intruder', 'exploit', 'automations', 'extensions'],
        tags: ['generated'],
      },
      matchedEntryIds: entries.slice(4).map((entry) => entry.id),
      facetCounts: {
        tools: { intruder: 1, exploit: 1, automations: 1, extensions: 1 },
        risks: { medium: 4 },
        statuses: { 200: 2, 403: 2 },
        tags: { generated: 4 },
      },
    },
  ];
  const reportAttachments = archiveImportReviews.slice(0, 2).map((review) => ({
    id: review.id,
    importedAt: review.importedAt,
    format: review.format,
    mappingPresetName: review.mappingPresetName,
    normalization: review.normalization,
    notes: review.notes,
    addedEntries: review.addedEntries,
    changedEntries: review.changedEntries,
    duplicateEntries: review.duplicateEntries,
    sourceHosts: review.sourceHosts,
    replayCount: review.replayCount,
    replayedAt: review.replayedAt,
    exchangeCount: review.exchanges.length,
    provenanceManifest: review.provenanceManifest,
    redactionControl: review.redactionControl,
  }));

  return {
    entries,
    captureControls,
    capturePresets,
    customColumns,
    columnEvidencePackages,
    archiveMappingPresets,
    archiveImportReviews,
    mergeStrategies: ['add-and-variants', 'add-only', 'replace-route'],
    savedFilterSets,
    reportAttachments,
    operationalSecretSamples: ['logger-secret-token', 'logger-session', 'logger-api-key'],
    exportedAt: now,
  };
}

function makeLoggerEntry(tool, index, now) {
  const pathSuffix = index + 1;
  const status = index % 2 === 0 ? 403 : 200;
  return {
    id: `logger-entry-${tool}`,
    exchangeId: `hx-logger-${tool}`,
    at: now,
    tool,
    method: index % 3 === 0 ? 'POST' : 'GET',
    host: 'app.shop.local',
    path: `/api/refunds/${pathSuffix}`,
    url: `https://app.shop.local/api/refunds/${pathSuffix}?trace=logger-api-key`,
    status,
    length: 300 + index,
    mime: 'application/json',
    risk: index < 3 ? 'high' : 'medium',
    timing: 40 + index,
    modified: index < 3,
    notes: `Generated ${tool} Logger traffic with authz and generated evidence.`,
    requestRaw: [
      `${index % 3 === 0 ? 'POST' : 'GET'} /api/refunds/${pathSuffix}?trace=logger-api-key HTTP/1.1`,
      'Host: app.shop.local',
      'Authorization: Bearer logger-secret-token',
      'Cookie: session=logger-session; theme=dark',
      'X-API-Key: logger-api-key',
      '',
      'amount=500&reason=logger-test',
    ].join('\n'),
    responseRaw: [
      `HTTP/1.1 ${status} ${status === 403 ? 'Forbidden' : 'OK'}`,
      'Content-Type: application/json',
      '',
      status === 403 ? '{"error":"denied","token":"logger-secret-token"}' : '{"ok":true}',
    ].join('\n'),
    tags: index < 3 ? ['authz', 'generated'] : ['generated'],
  };
}

function makeMappingPreset(id, name, source, normalization, now) {
  return {
    id,
    name,
    description: `${name} mapping`,
    source,
    normalization,
    tags: ['logger-import', normalization],
    pinned: normalization === 'report-evidence',
    createdAt: now,
    updatedAt: now,
  };
}

function makeArchiveReview(id, format, preset, entries, now, options) {
  const exchanges = entries.map((entry, index) => ({
    id: `${id}-exchange-${index + 1}`,
    method: entry.method,
    host: entry.host,
    path: entry.path,
    url: entry.url,
    status: entry.status,
    length: entry.length,
    mime: entry.mime,
    risk: entry.risk,
    timing: entry.timing,
    notes: entry.notes,
    source: ['proxy', 'repeater', 'scanner'].includes(preset.source) ? preset.source : 'proxy',
    time: '20:15:00',
    requestRaw: entry.requestRaw,
    responseRaw: entry.responseRaw,
    tags: entry.tags,
  }));
  const conflictDetails = options.conflictKinds.map((kind, index) => ({
    id: `${id}-conflict-${kind}`,
    kind,
    importedExchangeId: exchanges[0].id,
    existingExchangeId: kind === 'new-route' ? undefined : 'hx-existing-refund',
    route: `${entries[0].method} ${entries[0].host}${entries[0].path}`,
    statusDelta: kind === 'exact-duplicate' ? 0 : 200,
    lengthDelta: kind === 'exact-duplicate' ? 0 : 22 + index,
    timingDelta: kind === 'exact-duplicate' ? 0 : 7 + index,
    importedSummary: `${format} imported ${entries[0].requestRaw}`,
    existingSummary: 'Existing route summary with previous requestRaw',
    requestPreview: entries[0].requestRaw,
    responsePreview: entries[0].responseRaw,
  }));
  return {
    id,
    importedAt: now,
    format,
    mappingPresetId: preset.id,
    mappingPresetName: preset.name,
    normalization: preset.normalization,
    notes: `${format} import review keeps Logger raw archive evidence and report attachment provenance.`,
    addedEntries: options.addedEntries,
    duplicateEntries: options.duplicateEntries,
    changedEntries: options.changedEntries,
    sourceHosts: ['app.shop.local'],
    fieldMappings: [
      { field: 'requestRaw', before: 'raw request', after: 'requestRaw', action: 'preserved' },
      { field: 'responseRaw', before: 'raw response', after: 'responseRaw', action: 'preserved' },
      { field: 'source', before: format, after: preset.source, action: 'mapped' },
    ],
    conflictDetails,
    replayCount: options.replayCount,
    replayedAt: options.replayCount > 0 ? now : undefined,
    provenanceManifest: {
      id: `${id}-provenance`,
      version: 1,
      generatedAt: now,
      importJobId: id,
      format,
      normalization: preset.normalization,
      exchangeCount: exchanges.length,
      sourceHosts: ['app.shop.local'],
      importedExchangeIds: exchanges.map((exchange) => exchange.id),
      sourceFileName: `${id}.${format}`,
      sourceDigestSha256: 'a'.repeat(64),
      manifestDigestSha256: 'b'.repeat(64),
      signature: {
        status: id.endsWith('raw') ? 'preview-signed' : 'valid',
        signerName: 'ProxyForge Logger',
        signingKeyId: 'logger-key-1',
        signedAt: now,
        algorithm: 'HMAC-SHA256',
        canonicalization: 'json-stable-v1',
        manifestDigestSha256: 'b'.repeat(64),
        signature: 'c'.repeat(64),
      },
    },
    redactionControl: {
      id: `${id}-redaction`,
      importJobId: id,
      mode: 'rules',
      updatedAt: now,
      rules: [
        { id: `${id}-preserve-executor`, target: 'request', selector: '*', action: 'preserve', enabled: true },
        { id: `${id}-mask-report-auth`, target: 'request-header', selector: 'authorization', action: 'mask', replacement: '[redacted-at-report-export]', enabled: true },
      ],
    },
    exchanges,
  };
}
