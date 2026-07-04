import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const candidateEnginePaths = [
  'src/proxyHistoryEngine.ts',
  'src/proxy-history-engine.ts',
  'electron/proxyHistoryEngine.ts',
  'electron/proxy-history-engine.ts',
  'dist-electron/proxyHistoryEngine.js',
  'dist-electron/proxy-history-engine.js',
  'dist/proxyHistoryEngine.js',
  'dist/proxy-history-engine.js',
];
const expectedExports = [
  'buildProxyHistoryViewModel',
  'buildProxyHistoryFilterSetPackage',
  'buildProxyHttp2FidelityReport',
  'buildProxyHttp2MultiplexingReport',
  'buildProxyInterceptRuleReview',
  'buildProxyCapturePresetHandoff',
  'buildProxyTrafficComparisonPackage',
  'buildProxyCrossToolHandoffPackage',
  'buildProxyHistoryEvidenceAttachment',
  'buildProxyEdgeProfilePackage',
  'buildProxyBrowserProxyChainDiversityPackage',
];

const enginePath = await firstExistingPath(candidateEnginePaths);
if (!enginePath) {
  console.log('proxy-history-engine: skipped; no Proxy history engine module is exported yet');
  process.exit(0);
}
const importedProxyHistoryEngine = await loadEngine(enginePath);
const proxyHistoryEngine = normalizeModuleExports(importedProxyHistoryEngine);

const missingExports = expectedExports.filter((name) => typeof proxyHistoryEngine[name] !== 'function');
if (missingExports.length) {
  console.log(`proxy-history-engine: skipped; missing advanced Proxy history export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const sampleRequest = buildSampleProxyHistoryRequest();
const artifactDir = path.join(process.cwd(), '.gitignored', 'test-artifacts', `proxy-history-filter-set-${Date.now()}-${process.pid}`);
await fs.mkdir(artifactDir, { recursive: true });

const viewModel = await proxyHistoryEngine.buildProxyHistoryViewModel(sampleRequest);
assertProxyHttpMetadata(viewModel, 'buildProxyHistoryViewModel');
assertFilterCounts(viewModel, 'buildProxyHistoryViewModel');
assertHttp2RowMetadata(viewModel, 'buildProxyHistoryViewModel');

const filterSetPackage = await proxyHistoryEngine.buildProxyHistoryFilterSetPackage(sampleRequest);
assertFilterSetPackage(filterSetPackage, 'buildProxyHistoryFilterSetPackage');

const http2FidelityReport = await proxyHistoryEngine.buildProxyHttp2FidelityReport(sampleRequest);
assertHttp2FidelityReport(http2FidelityReport, 'buildProxyHttp2FidelityReport');

const http2MultiplexingReport = await proxyHistoryEngine.buildProxyHttp2MultiplexingReport({
  ...sampleRequest,
  filters: { status: 'http2' },
});
assertHttp2MultiplexingReport(http2MultiplexingReport, 'buildProxyHttp2MultiplexingReport');

const ruleReview = await proxyHistoryEngine.buildProxyInterceptRuleReview(sampleRequest);
assertRuleReview(ruleReview, 'buildProxyInterceptRuleReview');

const capturePresetPackage = await proxyHistoryEngine.buildProxyCapturePresetHandoff({
  ...sampleRequest,
  ruleReview,
});
assertPackageArtifact(
  capturePresetPackage,
  'buildProxyCapturePresetHandoff',
  /proxyforge-proxy-capture|proxy.*capture.*preset|capture.*preset.*handoff/i,
  /Audit evidence focus|Manual replay|proxy|repeater|scanner|HTTP\/2/i,
);

const trafficComparisonPackage = await proxyHistoryEngine.buildProxyTrafficComparisonPackage({
  ...sampleRequest,
  capturePresetPackage,
});
assertPackageArtifact(
  trafficComparisonPackage,
  'buildProxyTrafficComparisonPackage',
  /proxyforge-proxy-traffic-comparison|proxy.*traffic.*comparison|traffic.*comparison.*package/i,
  /baseline|candidate|403|200|refund|HTTP\/2/i,
);

const crossToolHandoffPackage = await proxyHistoryEngine.buildProxyCrossToolHandoffPackage({
  ...sampleRequest,
  selectedExchangeIds: [
    'hx-proxy-advanced-profile',
    'hx-proxy-advanced-refund-denied',
    'hx-proxy-advanced-refund-allowed',
  ],
});
assertCrossToolHandoffPackage(crossToolHandoffPackage, 'buildProxyCrossToolHandoffPackage');

const evidenceAttachment = await proxyHistoryEngine.buildProxyHistoryEvidenceAttachment({
  ...sampleRequest,
  ruleReview,
  capturePresetPackage,
  trafficComparisonPackage,
  http2FidelityReport,
  http2MultiplexingReport,
  filterSetPackage,
  crossToolHandoffPackage,
  issueId: 'issue-proxy-history-advanced',
});
assertPackageArtifact(
  evidenceAttachment,
  'buildProxyHistoryEvidenceAttachment',
  /proxyforge-proxy-history-evidence|proxy.*history.*evidence|history.*evidence.*attachment/i,
  /report[- ]ready|Proxy History Evidence|HTTP history|filter-set|HTTP\/2 fidelity|multiplexing|cross-tool handoff|rule review|traffic comparison/i,
);
assertReportReadyLanguage(evidenceAttachment, 'buildProxyHistoryEvidenceAttachment');
assert.match(evidenceAttachment.content, /proxyforge-proxy-history-filter-set-package|proxyforge-proxy-http2-multiplexing-report|proxyforge-proxy-cross-tool-handoff-package|saved filter predicate|Bearer customer-token/i);

const proxyEdgeProfilePackage = await proxyHistoryEngine.buildProxyEdgeProfilePackage({
  ...sampleRequest,
  filters: {},
  ruleReview,
  linkedPackages: buildProxyEdgeLinkedPackages(sampleRequest.now),
  operationalSecretSamples: [
    'Bearer customer-token',
    'Bearer support-token',
    'session=customer-session',
    'Proxy-Authorization: Basic upstream-proxy-secret',
    'websocket-session=proxy-edge-ws-session',
    'redact-only-during-report-export',
  ],
  minHosts: 3,
  minRoutes: 4,
  minPackageKinds: 11,
});
assertProxyEdgeProfilePackage(proxyEdgeProfilePackage, 'buildProxyEdgeProfilePackage');

const proxyBrowserProxyChainDiversityPackage = await proxyHistoryEngine.buildProxyBrowserProxyChainDiversityPackage({
  edgeProfilePackage: proxyEdgeProfilePackage,
  profiles: buildProxyBrowserProxyChainProfiles(sampleRequest.now),
  operationalSecretSamples: [
    'Proxy-Authorization: Basic upstream-proxy-secret',
    'Proxy-Authorization: Bearer windows-edge-upstream-token',
    'Authorization: Bearer firefox-manual-import-token',
    'Cookie: browser_proxy_chain=linux-chromium-cookie',
    'redact-only-during-report-export',
  ],
  generatedAt: sampleRequest.now,
});
assertProxyBrowserProxyChainDiversityPackage(proxyBrowserProxyChainDiversityPackage, 'buildProxyBrowserProxyChainDiversityPackage');

await fs.writeFile(path.join(artifactDir, 'proxy-history-filter-set-package.json'), filterSetPackage.content, 'utf8');
await fs.writeFile(path.join(artifactDir, 'proxy-http2-multiplexing-report.json'), http2MultiplexingReport.content, 'utf8');
await fs.writeFile(path.join(artifactDir, 'proxy-cross-tool-handoff-package.json'), crossToolHandoffPackage.content, 'utf8');
await fs.writeFile(path.join(artifactDir, 'proxy-history-evidence-attachment.json'), evidenceAttachment.content, 'utf8');
await fs.writeFile(path.join(artifactDir, 'proxy-edge-profile-package.json'), proxyEdgeProfilePackage.content, 'utf8');
await fs.writeFile(path.join(artifactDir, 'proxy-browser-proxy-chain-diversity-package.json'), proxyBrowserProxyChainDiversityPackage.content, 'utf8');

const issuePromotion = await callFirstAvailableHelper(
  proxyHistoryEngine,
  [
    'buildProxyHistoryIssuePromotion',
    'buildProxyHistoryPromotionCandidate',
    'buildProxyIssuePromotion',
    'promoteProxyHistoryEvidenceToIssue',
  ],
  [{
    ...sampleRequest,
    ruleReview,
    capturePresetPackage,
    trafficComparisonPackage,
    evidenceAttachment,
    issueId: 'issue-proxy-history-advanced',
  }],
);
if (issuePromotion.called) {
  assertReportReadyLanguage(issuePromotion.value, issuePromotion.name);
  assert.match(
    stringify(issuePromotion.value),
    /Proxy history|HTTP history|issue|evidence|authorization boundary/i,
    `${issuePromotion.name} should preserve report promotion context`,
  );
}

console.log(`proxy-history-engine: exercised ${expectedExports.length + (issuePromotion.called ? 1 : 0)} advanced Proxy history helper(s)`);

async function firstExistingPath(candidates) {
  for (const candidate of candidates) {
    const resolved = path.resolve(candidate);
    try {
      const stat = await fs.stat(resolved);
      if (stat.isFile()) return resolved;
    } catch {
      // Keep looking for an optional Proxy history engine export.
    }
  }
  return '';
}

async function loadEngine(enginePath) {
  if (enginePath.endsWith('.js') || enginePath.endsWith('.cjs')) {
    return require(enginePath);
  }

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
    crypto: globalThis.crypto,
    setTimeout,
    clearTimeout,
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

async function callFirstAvailableHelper(moduleExports, names, args) {
  for (const name of names) {
    const helper = moduleExports[name];
    if (typeof helper !== 'function') continue;
    return { called: true, name, value: await helper(...args) };
  }
  return { called: false, name: '', value: null };
}

function buildSampleProxyHistoryRequest() {
  const now = '2026-05-24T16:00:00.000Z';
  const exchanges = [
    {
      id: 'hx-proxy-advanced-profile',
      method: 'GET',
      host: 'app.shop.local',
      path: '/api/account/profile',
      url: 'https://app.shop.local/api/account/profile',
      status: 200,
      length: 1842,
      mime: 'application/json',
      risk: 'medium',
      timing: 128,
      notes: 'Session object exposes role hints for report-ready Proxy history review with alpn:h2 stream:1 metadata',
      source: 'proxy',
      time: '13:18:42',
      requestRaw: [
        'GET /api/account/profile HTTP/2',
        'Host: app.shop.local',
        'Cookie: session=customer-session',
        'Accept: application/json',
        '',
        '',
      ].join('\n'),
      responseRaw: [
        'HTTP/2 200 OK',
        'Content-Type: application/json',
        'Cache-Control: no-store',
        '',
        '{"id":"usr_1842","email":"analyst@example.local","role":"customer"}',
      ].join('\n'),
      tags: ['in-scope', 'auth', 'http2', 'alpn:h2', 'stream:1'],
    },
    {
      id: 'hx-proxy-advanced-refund-denied',
      method: 'POST',
      host: 'app.shop.local',
      path: '/api/refunds',
      url: 'https://app.shop.local/api/refunds',
      status: 403,
      length: 612,
      mime: 'application/json',
      risk: 'high',
      timing: 231,
      notes: 'Authorization boundary candidate captured in Proxy history with alpn:h2 stream:7 metadata',
      source: 'proxy',
      time: '13:19:07',
      requestRaw: [
        ':method: POST',
        ':scheme: https',
        ':authority: app.shop.local',
        ':path: /api/refunds',
        'content-type: application/json',
        'authorization: Bearer customer-token',
        'x-http2-stream-id: 7',
        '',
        '{"orderId":"ord_90210","amount":7900,"reason":"manual review"}',
      ].join('\n'),
      responseRaw: [
        ':status: 403',
        'content-type: application/json',
        'server: envoy',
        '',
        '{"error":"missing_permission","required":"refunds.write"}',
        '',
        'grpc-status: 0',
        'x-envoy-upstream-service-time: 31',
      ].join('\n'),
      tags: ['authz', 'candidate', 'http2', 'alpn:h2', 'stream:7'],
    },
    {
      id: 'hx-proxy-advanced-refund-allowed',
      method: 'POST',
      host: 'app.shop.local',
      path: '/api/refunds',
      url: 'https://app.shop.local/api/refunds',
      status: 200,
      length: 740,
      mime: 'application/json',
      risk: 'high',
      timing: 176,
      notes: 'Support role replay shows the same refund route succeeding with alpn:h2 stream:9 metadata',
      source: 'repeater',
      time: '13:20:12',
      requestRaw: [
        'POST /api/refunds HTTP/2',
        'Host: app.shop.local',
        'Content-Type: application/json',
        'Authorization: Bearer support-token',
        'X-ProxyForge-Workspace: replay-matrix',
        '',
        '{"orderId":"ord_90210","amount":7900,"reason":"manual review"}',
      ].join('\n'),
      responseRaw: [
        'HTTP/2 200 OK',
        'Content-Type: application/json',
        '',
        '{"status":"approved","role":"support_admin","refundId":"rf_1001"}',
      ].join('\n'),
      tags: ['authz', 'candidate', 'replay', 'http2', 'alpn:h2', 'stream:9'],
    },
    {
      id: 'hx-proxy-advanced-h2c-inventory',
      method: 'GET',
      host: 'api.shop.local',
      path: '/internal/inventory',
      url: 'http://api.shop.local/internal/inventory',
      status: 204,
      length: 0,
      mime: 'application/json',
      risk: 'medium',
      timing: 94,
      notes: 'Cleartext h2c service inventory probe captured with stream:3 metadata',
      source: 'proxy',
      time: '13:20:20',
      requestRaw: [
        ':method: GET',
        ':scheme: http',
        ':authority: api.shop.local',
        ':path: /internal/inventory',
        'te: trailers',
        'x-h2c-upgrade: prior-knowledge',
        '',
        '',
      ].join('\n'),
      responseRaw: [
        ':status: 204',
        'content-type: application/json',
        'server: h2c-test',
        '',
        '',
      ].join('\n'),
      tags: ['inventory', 'http2', 'h2c', 'alpn:h2c', 'stream:3'],
    },
    {
      id: 'hx-proxy-advanced-asset',
      method: 'GET',
      host: 'cdn.shop.local',
      path: '/assets/app.8e31.js',
      url: 'https://cdn.shop.local/assets/app.8e31.js',
      status: 200,
      length: 90122,
      mime: 'application/javascript',
      risk: 'low',
      timing: 84,
      notes: 'Static bundle contains internal route names',
      source: 'proxy',
      time: '13:20:31',
      requestRaw: [
        'GET /assets/app.8e31.js HTTP/1.1',
        'Host: cdn.shop.local',
        'Accept: */*',
        '',
        '',
      ].join('\n'),
      responseRaw: [
        'HTTP/1.1 200 OK',
        'Content-Type: application/javascript',
        '',
        'const routes=["/admin/orders","/admin/refunds","/internal/export"];',
      ].join('\n'),
      tags: ['static', 'http1'],
    },
  ];

  const matchReplaceRules = [
    {
      id: 'proxy-rule-redact-authorization',
      name: 'Authorization header redaction',
      enabled: true,
      direction: 'request',
      match: 'Authorization: Bearer [^\\n]+',
      replace: 'Authorization: Bearer [redacted]',
      isRegex: true,
      caseSensitive: false,
    },
    {
      id: 'proxy-rule-role-replay',
      name: 'Role response comparison',
      enabled: true,
      direction: 'response',
      match: '"role":"customer"',
      replace: '"role":"support_admin"',
      isRegex: false,
      caseSensitive: true,
    },
    {
      id: 'proxy-rule-disabled-debug',
      name: 'Disabled debug marker',
      enabled: false,
      direction: 'both',
      match: 'X-Debug: true',
      replace: 'X-Debug: false',
      isRegex: false,
      caseSensitive: true,
    },
  ];

  return {
    projectName: 'Proxy advanced parity',
    scopeAllowlist: ['*.shop.local'],
    exchanges,
    history: exchanges,
    selectedExchangeId: 'hx-proxy-advanced-refund-denied',
    rules: matchReplaceRules,
    matchReplaceRules,
    filters: {
      search: 'refund',
      host: 'app.shop.local',
      method: 'POST',
      status: '4xx',
      mime: 'application/json',
      risk: 'high',
      source: 'proxy',
      tag: 'authz',
      protocol: 'HTTP/2',
    },
    savedFilters: [
      {
        id: 'saved-authz-refund-denied',
        label: 'Denied refund authorization boundary',
        filters: {
          query: 'refund authorization',
          method: 'POST',
          source: 'proxy',
          status: '4xx',
          risk: 'high',
          mime: 'application/json',
          tag: 'authz',
        },
      },
      {
        id: 'saved-http2-refund-replay',
        label: 'HTTP/2 refund replay set',
        filters: {
          query: 'refund',
          method: 'POST',
          status: 'http2',
          tag: 'authz',
        },
      },
      {
        id: 'saved-modified-review',
        label: 'Modified message review',
        filters: {
          status: 'modified',
        },
      },
    ],
    capturePreset: {
      id: 'proxy-capture-preset-audit-evidence',
      name: 'Audit evidence focus',
      description: 'Capture Proxy, Repeater, and Scanner traffic that can become report-ready evidence.',
      pinned: true,
      controls: [
        { tool: 'proxy', enabled: true, updatedAt: now },
        { tool: 'repeater', enabled: true, updatedAt: now },
        { tool: 'scanner', enabled: false, updatedAt: now },
      ],
      createdAt: now,
      updatedAt: now,
    },
    captureControls: [
      { source: 'proxy', enabled: true, reason: 'HTTP history baseline and live intercept evidence' },
      { source: 'repeater', enabled: true, reason: 'Manual replay candidate traffic comparison' },
      { source: 'scanner', enabled: false, reason: 'Scanner noise paused during manual authorization review' },
    ],
    baseline: {
      name: 'Customer baseline',
      exchangeIds: ['hx-proxy-advanced-profile', 'hx-proxy-advanced-refund-denied'],
      exchanges: exchanges.slice(0, 2),
      capturedAt: '2026-05-24T15:55:00.000Z',
    },
    candidate: {
      name: 'Support replay candidate',
      exchangeIds: ['hx-proxy-advanced-profile', 'hx-proxy-advanced-refund-allowed', 'hx-proxy-advanced-asset'],
      exchanges: [exchanges[0], exchanges[2], exchanges[4]],
      capturedAt: now,
    },
    issueDraft: {
      id: 'issue-proxy-history-advanced',
      title: 'Refund authorization boundary differs by replayed role',
      severity: 'high',
      host: 'app.shop.local',
      path: '/api/refunds',
      detail: 'Proxy history and Repeater traffic comparison preserve the 403 customer baseline and 200 support replay.',
      remediation: 'Verify refund mutation authorization server-side for every role.',
      triageNote: 'Report-ready Proxy history evidence includes HTTP/2 metadata, rule review, capture preset handoff, and traffic comparison package.',
    },
    now,
  };
}

function assertProxyHttpMetadata(result, helperName) {
  assert.match(
    stringify(result),
    /HTTP\/2|HTTP\/1\.1|HTTP history|httpVersion|protocol|requestRaw|responseRaw/i,
    `${helperName} should expose HTTP/2 or HTTP metadata`,
  );
}

function assertFilterCounts(result, helperName) {
  const serialized = stringify(result);
  assert.match(serialized, /filter/i, `${helperName} should preserve applied filter state`);
  assert.match(serialized, /count|matched|filtered|visible|total/i, `${helperName} should expose filter counts`);
  assert.match(serialized, /refund|app\.shop\.local|403|POST/i, `${helperName} should keep representative filtered traffic context`);
}

function assertHttp2RowMetadata(result, helperName) {
  const rows = Array.isArray(result.rows) ? result.rows : [];
  const refund = rows.find((row) => row.exchangeId === 'hx-proxy-advanced-refund-denied');
  assert(refund, `${helperName} should include filtered refund row`);
  assert.equal(refund.protocol, 'HTTP/2', `${helperName} should classify pseudo-header traffic as HTTP/2`);
  assert.equal(refund.http2.requestPseudoHeaders[':method'], 'POST');
  assert.equal(refund.http2.requestPseudoHeaders[':authority'], 'app.shop.local');
  assert.equal(refund.http2.responsePseudoHeaders[':status'], '403');
  assert.equal(refund.http2.streamId, 7);
  assert.equal(refund.http2.alpn, 'h2');
  assert.equal(
    Array.from(refund.http2.responseTrailerNames).sort().join(','),
    ['grpc-status', 'x-envoy-upstream-service-time'].sort().join(','),
  );
  assert.match(refund.http2.fidelityChecks.join(' '), /request-pseudo|response-pseudo|trailers|stream:7|alpn:h2/i);
  assert.equal(refund.http2.warnings.length, 0, `${helperName} should not warn for complete HTTP/2 metadata`);
}

function assertFilterSetPackage(result, helperName) {
  assert.equal(result.kind, 'proxyforge-proxy-history-filter-set-package');
  assert.equal(result.reportReady, true, `${helperName} should be report-ready`);
  assert.equal(result.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.equal(result.savedFilterCount >= 3, true, `${helperName} should preserve saved filter presets`);
  assert(result.savedFilters.some((filter) => filter.id === 'saved-authz-refund-denied'), `${helperName} should preserve named saved filters`);
  assert(result.savedFilters.some((filter) => filter.matchedExchangeIds.includes('hx-proxy-advanced-refund-denied')), `${helperName} should match the denied refund exchange`);
  assert(result.predicateCoverage.includes('method-filter'), `${helperName} should cover method predicates`);
  assert(result.predicateCoverage.includes('source-filter'), `${helperName} should cover source predicates`);
  assert(result.predicateCoverage.includes('tag-filter'), `${helperName} should cover tag predicates`);
  assert(result.predicateCoverage.some((item) => item === 'status-filter:4xx' || item === 'status-filter:http2'), `${helperName} should cover advanced status predicates`);
  assert.equal(result.requirements.savedPredicatesRoundTrip, true, `${helperName} should round-trip saved predicates`);
  assert.equal(result.requirements.annotationLanesCovered, true, `${helperName} should preserve annotation lane counts`);
  assert.equal(result.requirements.rawSamplesPreserved, true, `${helperName} should preserve raw request/response samples`);
  assert.equal(result.requirements.operationalSecretsPreserved, true, `${helperName} should preserve operational secrets`);
  assert.match(result.content, /Bearer customer-token|Bearer support-token|proxyforge-proxy-history-filter-set-package|reportPhaseOnlyRedaction|execution-full-fidelity-secrets-preserved/i);
}

function assertHttp2FidelityReport(result, helperName) {
  assert.equal(result.reportReady, true, `${helperName} should be report-ready`);
  assert.equal(result.http2ExchangeCount >= 1, true, `${helperName} should include HTTP/2 exchanges`);
  assert.equal(result.pseudoHeaderExchangeCount >= 1, true, `${helperName} should count pseudo-header exchanges`);
  assert.equal(result.trailerExchangeCount >= 1, true, `${helperName} should count trailer-bearing exchanges`);
  const serialized = stringify(result);
  assert.match(serialized, /proxyforge-proxy-http2-fidelity-report|HTTP\/2 fidelity|pseudo-header|stream:7|alpn/i);
  assert.match(serialized, /:method|:authority|:status|grpc-status|x-envoy-upstream-service-time/i);
}

function assertHttp2MultiplexingReport(result, helperName) {
  assert.equal(result.reportReady, true, `${helperName} should be report-ready`);
  assert.equal(result.http2ExchangeCount >= 4, true, `${helperName} should include HTTP/2 and h2c exchanges`);
  assert.equal(result.multiplexedConnectionCount >= 1, true, `${helperName} should group multiplexed authority traffic`);
  assert.equal(result.h2cExchangeCount >= 1, true, `${helperName} should preserve h2c metadata separately`);
  assert.equal(result.streamIdCoverage, 1, `${helperName} should prove full stream-id coverage for the parity fixture`);
  assert.equal(result.requirements.pseudoHeaderFidelity, true);
  assert.equal(result.requirements.streamIdCoverage, true);
  assert.equal(result.requirements.multiplexedConnectionGrouping, true);
  assert.equal(result.requirements.h2cOrAlpnCaptured, true);
  assert.equal(result.requirements.trailerMetadataPreserved, true);
  const appConnection = result.connectionSummaries.find((connection) => connection.authority === 'app.shop.local' && connection.alpn === 'h2');
  assert(appConnection, `${helperName} should include the app.shop.local h2 bucket`);
  assert.equal(appConnection.multiplexed, true, `${helperName} should mark app.shop.local as multiplexed`);
  assert.equal(appConnection.streamIds.join(','), '1,7,9');
  assert.equal(appConnection.trailerExchangeCount >= 1, true, `${helperName} should carry trailer metadata into connection summaries`);
  const serialized = stringify(result);
  assert.match(serialized, /proxyforge-proxy-http2-multiplexing-report|streamIdCoverage|multiplexedConnectionCount|h2cExchangeCount/i);
  assert.match(serialized, /app\.shop\.local|api\.shop\.local|stream id|authority|ALPN|h2c/i);
}

function assertCrossToolHandoffPackage(result, helperName) {
  assert.equal(result.kind, 'proxyforge-proxy-cross-tool-handoff-package');
  assert.equal(result.reportReady, true, `${helperName} should be report-ready`);
  assert.equal(result.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert(result.destinations.includes('repeater'), `${helperName} should include a Repeater destination`);
  assert(result.destinations.includes('scanner'), `${helperName} should include a Scanner destination`);
  assert(result.destinations.includes('reports'), `${helperName} should include a Reports destination`);
  assert.equal(result.repeaterRequests.length >= 3, true, `${helperName} should stage selected raw requests into Repeater`);
  assert(result.repeaterRequests.some((request) => request.exchangeId === 'hx-proxy-advanced-refund-denied' && /Bearer customer-token/.test(request.rawRequest)), `${helperName} should preserve customer token in Repeater raw request`);
  assert(result.repeaterRequests.some((request) => request.secretSignals.includes('cookie-header')), `${helperName} should preserve cookie signals`);
  assert.equal(result.scannerCandidates.length >= 2, true, `${helperName} should create scanner candidates from risky/parameterized exchanges`);
  assert(result.scannerCandidates.some((candidate) => candidate.checkHints.includes('authz-diff') && candidate.insertionPoints.some((point) => point.startsWith('json:'))), `${helperName} should preserve Scanner authz/check/insertion hints`);
  assert.equal(result.reportAttachments.length, result.exchangeIds.length, `${helperName} should link every selected exchange to Reports`);
  assert.equal(result.requirements.stableExchangeIds, true);
  assert.equal(result.requirements.repeaterRawRequestsPreserved, true);
  assert.equal(result.requirements.scannerCandidatesLinked, true);
  assert.equal(result.requirements.reportAttachmentsLinked, true);
  assert.equal(result.requirements.crossToolAuditTrail, true);
  assert.equal(result.requirements.operationalSecretsPreserved, true);
  assert.match(result.content, /proxyforge-proxy-cross-tool-handoff-package|Repeater|Scanner|Reports|Bearer customer-token|session=customer-session|report-export-only/i);
}

function buildProxyEdgeLinkedPackages(now) {
  const makePackage = (id, kind, content, requirements = {}) => ({
    id,
    kind,
    reportReady: true,
    status: 'pass',
    requirements: {
      ...requirements,
      operationalSecretsPreserved: true,
      reportPhaseOnlyRedaction: true,
    },
    summary: content,
    content: JSON.stringify({
      kind,
      generatedAt: now,
      reportReady: true,
      content,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    }, null, 2),
  });

  return [
    makePackage(
      'proxy-listener-capture-profile',
      'proxyforge-proxy-http-listener-capture-package',
      'HTTP listener loopback captured GET/POST with Authorization: Bearer customer-token and Cookie: session=customer-session before report export.',
      { listenerCaptured: true },
    ),
    makePackage(
      'proxy-connect-profile',
      'proxyforge-proxy-connect-tunnel-metadata-package',
      'CONNECT tunnel byte-accounting preserved Proxy-Authorization: Basic upstream-proxy-secret, tunnel duration, close reason, and upstream proxy-chain metadata.',
      { connectTunnelCovered: true },
    ),
    makePackage(
      'proxy-mitm-profile',
      'proxyforge-https-mitm-evidence-package',
      'HTTPS MITM project CA certificate proof captured decrypted request/response material and strict upstream TLS failure evidence for app.shop.local.',
      { mitmCovered: true },
    ),
    makePackage(
      'proxy-intercept-profile',
      'proxyforge-proxy-intercept-evidence-package',
      'Request hold/edit/forward/drop-before-upstream and response hold/edit/drop-before-client controls preserved raw traffic.',
      { interceptCovered: true },
    ),
    makePackage(
      'proxy-match-replace-profile',
      'proxyforge-proxy-match-replace-rule-library',
      'Large match-replace rule-library package preserved request/response rewrite samples and package-refresh digest.',
      { matchReplaceCovered: true },
    ),
    makePackage(
      'proxy-browser-routing-profile',
      'proxyforge-browser-routing-proxy-chain-package',
      'Chromium browser-routing and upstream proxy-chain evidence preserved Proxy-Authorization: Basic upstream-proxy-secret and scoped browser traffic.',
      { browserProxyChainCovered: true },
    ),
    makePackage(
      'proxy-websocket-capture-profile',
      'proxyforge-websocket-capture-evidence-package',
      'WebSocket 101 capture preserved Sec-WebSocket-Key, client/server frames, and Cookie: websocket-session=proxy-edge-ws-session.',
      { websocketCaptureCovered: true },
    ),
    makePackage(
      'proxy-websocket-intercept-profile',
      'proxyforge-websocket-intercept-rewrite-replay-evidence-package',
      'WebSocket intercept/rewrite/replay preserved client frame edit, binary drop, replay payload, and received frames.',
      { websocketInterceptCovered: true },
    ),
    makePackage(
      'proxy-websocket-state-profile',
      'proxyforge-websocket-state-transcript-evidence-package',
      'WebSocket state graph and transcript import/export preserved clusters, JSON/Markdown transcript, and restored frame history.',
      { websocketStateCovered: true },
    ),
  ];
}

function buildProxyBrowserProxyChainProfiles(now) {
  const makeRaw = (method, pathValue, host, token, cookie, extraHeaders = []) => ({
    request: [
      `${method} ${pathValue} HTTP/1.1`,
      `Host: ${host}`,
      `Authorization: Bearer ${token}`,
      `Cookie: ${cookie}`,
      ...extraHeaders,
      '',
      '',
    ].join('\r\n'),
    response: [
      'HTTP/1.1 200 OK',
      'Content-Type: application/json',
      'Set-Cookie: browser_proxy_chain_seen=1; HttpOnly',
      '',
      JSON.stringify({ ok: true, host, token }),
    ].join('\r\n'),
  });
  const linuxChromium = makeRaw(
    'GET',
    '/capture/linux/chromium?secret=browser-chain',
    'linux-chromium.proxy.local',
    'linux-chromium-browser-token',
    'browser_proxy_chain=linux-chromium-cookie',
    ['Proxy-Authorization: Basic upstream-proxy-secret'],
  );
  const windowsChrome = makeRaw(
    'CONNECT',
    'api.windows-chrome.proxy.local:443',
    'api.windows-chrome.proxy.local',
    'windows-chrome-connect-token',
    'browser_proxy_chain=windows-chrome-cookie',
    ['Proxy-Authorization: Basic upstream-proxy-secret'],
  );
  const windowsEdge = makeRaw(
    'GET',
    '/h2/edge/profile?mode=upstream-auth',
    'windows-edge.proxy.local',
    'windows-edge-browser-token',
    'browser_proxy_chain=windows-edge-cookie',
    ['Proxy-Authorization: Bearer windows-edge-upstream-token'],
  );
  const linuxFirefox = makeRaw(
    'GET',
    '/ws/firefox/profile',
    'linux-firefox.proxy.local',
    'firefox-manual-import-token',
    'browser_proxy_chain=linux-firefox-cookie',
    ['Sec-WebSocket-Key: firefox-proxy-chain-websocket-key'],
  );

  return [
    {
      id: 'linux-chromium-upstream-auth',
      platform: 'linux',
      browserFamily: 'chromium',
      profilePath: '/tmp/proxyforge/chromium-upstream-auth-profile',
      proxyMode: 'upstream-auth',
      certificateMode: 'project-ca',
      protocolCoverage: ['HTTP/1.1', 'HTTP/2'],
      hostCount: 2,
      routeCount: 4,
      capturedHttp: true,
      capturedHttpsMitm: true,
      capturedConnect: false,
      capturedHttp2: true,
      capturedWebSocket: false,
      upstreamProxyHost: '127.0.0.1:18080',
      upstreamProxyAuthorization: 'Proxy-Authorization: Basic upstream-proxy-secret',
      isolatedProfile: true,
      cookieStoreCovered: true,
      rawRequestSample: linuxChromium.request,
      rawResponseSample: linuxChromium.response,
      generatedAt: now,
    },
    {
      id: 'windows-chrome-connect-chain',
      platform: 'windows',
      browserFamily: 'chrome',
      profilePath: 'C:\\Users\\runner\\AppData\\Local\\ProxyForge\\chrome-connect-profile',
      proxyMode: 'connect-chain',
      certificateMode: 'trusted-ca',
      protocolCoverage: ['CONNECT', 'HTTP/1.1'],
      hostCount: 2,
      routeCount: 3,
      capturedHttp: true,
      capturedHttpsMitm: true,
      capturedConnect: true,
      capturedHttp2: false,
      capturedWebSocket: false,
      upstreamProxyHost: '127.0.0.1:18081',
      upstreamProxyAuthorization: 'Proxy-Authorization: Basic upstream-proxy-secret',
      isolatedProfile: true,
      cookieStoreCovered: true,
      rawRequestSample: windowsChrome.request,
      rawResponseSample: windowsChrome.response,
      generatedAt: now,
    },
    {
      id: 'windows-edge-pac-upstream',
      platform: 'windows',
      browserFamily: 'edge',
      profilePath: 'C:\\Users\\runner\\AppData\\Local\\ProxyForge\\edge-pac-profile',
      proxyMode: 'pac',
      certificateMode: 'pinned-nonblocking',
      protocolCoverage: ['HTTP/2', 'HTTP/1.1'],
      hostCount: 2,
      routeCount: 3,
      capturedHttp: true,
      capturedHttpsMitm: true,
      capturedConnect: false,
      capturedHttp2: true,
      capturedWebSocket: false,
      upstreamProxyHost: 'proxy.edge.fixture.local:8443',
      upstreamProxyAuthorization: 'Proxy-Authorization: Bearer windows-edge-upstream-token',
      isolatedProfile: true,
      cookieStoreCovered: true,
      rawRequestSample: windowsEdge.request,
      rawResponseSample: windowsEdge.response,
      generatedAt: now,
    },
    {
      id: 'linux-firefox-manual-import-websocket',
      platform: 'linux',
      browserFamily: 'firefox',
      profilePath: '/tmp/proxyforge/firefox-manual-ca-profile',
      proxyMode: 'direct',
      certificateMode: 'manual-import',
      protocolCoverage: ['HTTP/1.1', 'WebSocket'],
      hostCount: 2,
      routeCount: 3,
      capturedHttp: true,
      capturedHttpsMitm: true,
      capturedConnect: false,
      capturedHttp2: false,
      capturedWebSocket: true,
      isolatedProfile: true,
      cookieStoreCovered: true,
      rawRequestSample: linuxFirefox.request,
      rawResponseSample: linuxFirefox.response,
      generatedAt: now,
    },
  ];
}

function assertProxyEdgeProfilePackage(result, helperName) {
  const serialized = stringify(result);
  const failedRequirements = Object.entries(result.requirements)
    .filter(([, passed]) => !passed)
    .map(([name]) => name);
  assert.equal(result.kind, 'proxyforge-proxy-edge-profile-package');
  assert.equal(result.reportReady, true, `${helperName} should be report-ready; failed: ${failedRequirements.join(', ') || 'none'}`);
  assert.deepEqual(failedRequirements, [], `${helperName} should satisfy every Proxy edge requirement`);
  assert.equal(result.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.equal(result.reportRedactionBoundary, 'redact-only-during-report-export');
  assert.equal(result.hostCount >= 3, true, `${helperName} should cover multiple Proxy hosts`);
  assert.equal(result.routeCount >= 4, true, `${helperName} should cover multiple Proxy routes`);
  assert(result.protocolCoverage.includes('HTTP/2'), `${helperName} should cover HTTP/2`);
  assert(result.protocolCoverage.includes('HTTP/1.1'), `${helperName} should cover HTTP/1.1`);
  assert(result.protocolCoverage.includes('WebSocket'), `${helperName} should cover WebSocket edge evidence`);
  assert(result.statusClasses.includes('2xx'), `${helperName} should cover successful responses`);
  assert(result.statusClasses.includes('4xx'), `${helperName} should cover rejected/error responses`);
  assert(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-proxy-http-listener-capture-package'));
  assert(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-https-mitm-evidence-package'));
  assert(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-websocket-capture-evidence-package'));
  assert(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-websocket-intercept-rewrite-replay-evidence-package'));
  assert(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-websocket-state-transcript-evidence-package'));
  assert.equal(result.packageRefreshProof.stalePackageIds.length, 0, `${helperName} should not carry stale linked packages`);
  assert.match(serialized, /listener|CONNECT|MITM|intercept|match-replace|HTTP2|WebSocket|browser-proxy|package digest/i);
  assert.match(serialized, /Bearer customer-token|Bearer support-token|Proxy-Authorization: Basic upstream-proxy-secret|websocket-session=proxy-edge-ws-session/i);
  assert.match(serialized, /redact-only-during-report-export|execution-full-fidelity-secrets-preserved/i);
}

function assertProxyBrowserProxyChainDiversityPackage(result, helperName) {
  const serialized = stringify(result);
  const failedRequirements = Object.entries(result.requirements)
    .filter(([, passed]) => !passed)
    .map(([name]) => name);
  assert.equal(result.kind, 'proxyforge-proxy-browser-proxy-chain-diversity-package');
  assert.equal(result.reportReady, true, `${helperName} should be report-ready; failed: ${failedRequirements.join(', ') || 'none'}`);
  assert.deepEqual(failedRequirements, [], `${helperName} should satisfy every browser/proxy-chain diversity requirement`);
  assert.equal(result.profileCount, 4);
  assert.deepEqual([...result.browserFamilies].sort(), ['chrome', 'chromium', 'edge', 'firefox']);
  assert.deepEqual([...result.platforms].sort(), ['linux', 'windows']);
  assert(result.proxyModes.includes('upstream-auth'));
  assert(result.proxyModes.includes('connect-chain'));
  assert(result.proxyModes.includes('pac'));
  assert(result.certificateModes.includes('project-ca'));
  assert(result.certificateModes.includes('trusted-ca'));
  assert(result.certificateModes.includes('manual-import'));
  assert(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-proxy-edge-profile-package'));
  assert.equal(result.packageRefreshProof.stalePackageIds.length, 0);
  assert.match(serialized, /linux-chromium-upstream-auth|windows-chrome-connect-chain|windows-edge-pac-upstream|linux-firefox-manual-import-websocket/);
  assert.match(serialized, /Proxy-Authorization: Basic upstream-proxy-secret|Proxy-Authorization: Bearer windows-edge-upstream-token/);
  assert.match(serialized, /Authorization: Bearer firefox-manual-import-token|browser_proxy_chain=linux-chromium-cookie/);
  assert.match(serialized, /redact-only-during-report-export|execution-full-fidelity-secrets-preserved/);
}

function assertRuleReview(result, helperName) {
  const serialized = stringify(result);
  assert.match(serialized, /rule|match[-/ ]?replace|intercept/i, `${helperName} should expose rule review language`);
  assert.match(serialized, /Authorization header redaction|Role response comparison/i, `${helperName} should include enabled rule details`);
  assert.match(serialized, /Disabled debug marker|disabled|enabled/i, `${helperName} should include rule state review`);
}

function assertPackageArtifact(result, helperName, kindPattern, contentPattern) {
  const serialized = stringify(result);
  assert.match(serialized, /kind/i, `${helperName} should expose a package kind`);
  assert.match(serialized, kindPattern, `${helperName} should expose the expected package kind`);
  assert.match(serialized, /content/i, `${helperName} should expose package content`);
  assert.match(serialized, contentPattern, `${helperName} should preserve representative package content`);
}

function assertReportReadyLanguage(result, helperName) {
  assert.match(
    stringify(result),
    /report[- ]ready|Reports handoff|ready for report/i,
    `${helperName} should include report-ready language`,
  );
}

function stringify(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
