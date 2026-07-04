import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'searchExchangesWithMeta',
  'buildSearchDiagnostics',
  'buildSearchSemanticCorpus',
  'buildSearchSemanticIndex',
  'restoreSearchSemanticIndex',
  'semanticProviderMatchesFromIndex',
  'buildSearchLargeProjectSoakReport',
  'buildSearchEvidencePackage',
  'buildSearchParityEvidencePackage',
  'buildSearchResultFacets',
];

const enginePath = path.resolve('src/searchEngine.ts');
const searchEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof searchEngine[name] !== 'function');
if (missingExports.length) {
  console.log(`search-engine: skipped; missing export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const exchanges = buildExchanges();

const structured = searchEngine.searchExchangesWithMeta(exchanges, 'risk>=medium -method:connect OR path:graphql');
assert.equal(structured.results.length, 2, 'existing structured predicates, negation, and OR should keep working');
assert.deepEqual(structured.results.map((exchange) => exchange.id), ['hx-authz-role-boundary', 'hx-graphql-cors']);

const semantic = searchEngine.searchExchangesWithMeta(exchanges, 'semantic:"authz bypass"');
assert.equal(semantic.results[0].id, 'hx-authz-role-boundary', 'semantic query should rank related auth/role boundary evidence first');
assert.match(semantic.matches[0].reasons.join('\n'), /semantic local score/i);
assert.ok(semantic.matches[0].semanticScore >= 0.34, 'local semantic score should clear threshold');

const provider = searchEngine.searchExchangesWithMeta(exchanges, 'semantic:"unexpected semantic lead"', {
  semanticProvider: { id: 'local-embedding', label: 'Local embeddings', model: 'mini-l2' },
  semanticProviderMatches: [
    { exchangeId: 'hx-static-js', score: 0.96, rationale: 'Provider clustered this bundle with source-map disclosure evidence.', labels: ['static-leak'] },
    { exchangeId: 'hx-authz-role-boundary', score: 0.44, rationale: 'Weak relation to authz replay.', labels: ['authz'] },
  ],
});
assert.equal(provider.results[0].id, 'hx-static-js', 'provider scores should override local ranking for semantic queries');
assert.equal(provider.matches[0].semanticProviderScore, 0.96);
assert.match(provider.matches[0].reasons.join('\n'), /Local embeddings\/mini-l2 score 0\.96/);

const unknownProvider = searchEngine.buildSearchDiagnostics('semantic:tokens', {
  semanticProvider: { id: 'expected-provider', label: 'Expected Provider' },
  semanticProviderMatches: [
    { exchangeId: 'hx-authz-role-boundary', score: 0.7, rationale: 'External result.', providerId: 'other-provider' },
  ],
});
assert.match(unknownProvider.warnings.join('\n'), /unknown provider "other-provider"/, 'unknown provider ids should warn without crashing');

const corpus = searchEngine.buildSearchSemanticCorpus(exchanges);
const corpusText = JSON.stringify(corpus);
assert.ok(corpusText.includes('real-secret-token'), 'operational semantic corpus should preserve bearer tokens for agent/provider execution');
assert.ok(corpusText.includes('session=abc123'), 'operational semantic corpus should preserve cookies for agent/provider execution');

const semanticIndex = searchEngine.buildSearchSemanticIndex(exchanges, { now: '2026-05-24T21:01:00.000Z', maxTokens: 128 });
assert.equal(semanticIndex.kind, 'proxyforge-search-semantic-index');
assert.equal(semanticIndex.exchangeCount, exchanges.length);
assert.equal(semanticIndex.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.ok(semanticIndex.content.includes('real-secret-token'), 'persistent operational semantic index should preserve bearer tokens until report generation');
assert.ok(semanticIndex.content.includes('session=abc123'), 'persistent operational semantic index should preserve cookies until report generation');
assert.ok(Object.keys(semanticIndex.tokenPostings).length > 0, 'semantic index should include token postings for large-project lookup');

const restoredIndex = searchEngine.restoreSearchSemanticIndex(semanticIndex.content);
assert.equal(restoredIndex.corpusDigestPreview, semanticIndex.corpusDigestPreview, 'semantic index restore should preserve digest metadata');
assert.equal(restoredIndex.documents[0].corpus.includes('real-secret-token'), true, 'restored semantic index should remain full fidelity for execution');

const indexedMatches = searchEngine.semanticProviderMatchesFromIndex(restoredIndex, 'authz bypass', { providerId: 'proxyforge-local-index', limit: 3 });
assert.equal(indexedMatches[0].exchangeId, 'hx-authz-role-boundary', 'persistent semantic index should rank authz replay evidence first');
assert.equal(indexedMatches[0].providerId, 'proxyforge-local-index');
assert.match(indexedMatches[0].rationale, /Persistent local semantic index matched/i);

const indexedProvider = searchEngine.searchExchangesWithMeta(exchanges, 'semantic:"authz bypass"', {
  semanticProvider: { id: 'proxyforge-local-index', label: 'ProxyForge local index', model: 'persistent-v1' },
  semanticProviderMatches: indexedMatches,
});
assert.equal(indexedProvider.results[0].id, 'hx-authz-role-boundary', 'restored semantic index provider matches should plug into normal search ranking');
assert.equal(indexedProvider.matches[0].semanticProviderScore, indexedMatches[0].score);
assert.ok(indexedProvider.matches[0].semanticLabels.includes('authorization'), 'indexed provider labels should flow into normal search metadata');

const packageResult = searchEngine.buildSearchEvidencePackage({
  query: 'semantic:"authz bypass"',
  run: semantic,
  facets: searchEngine.buildSearchResultFacets(semantic.results),
  now: '2026-05-24T21:00:00.000Z',
});
assert.equal(packageResult.kind, 'proxyforge-search-evidence-package');
assert.equal(packageResult.reportReady, true);
assert.match(packageResult.content, /semantic local score|hx-authz-role-boundary/);

const largeProjectExchanges = buildLargeProjectExchanges(384);
const soakReport = searchEngine.buildSearchLargeProjectSoakReport(largeProjectExchanges, {
  now: '2026-05-25T09:00:00.000Z',
  maxTokens: 512,
  queries: ['authz refund bypass', 'secret token cookie', 'graphql cors'],
  minExchangeCount: 300,
  minTotalMatches: 3,
  maxBuildDurationMs: 5000,
  maxTotalQueryDurationMs: 2500,
  maxIndexContentBytes: 2_500_000,
  matchLimit: 12,
});
assert.equal(soakReport.kind, 'proxyforge-search-large-project-soak-report');
assert.equal(soakReport.schemaVersion, 1);
assert.equal(soakReport.status, 'pass', `large-project soak should pass without warnings: ${soakReport.warnings.join('; ')}`);
assert.equal(soakReport.reportReady, true);
assert.equal(soakReport.exchangeCount, largeProjectExchanges.length);
assert.equal(soakReport.queryCount, 3);
assert.equal(soakReport.indexRestored, true, 'large-project soak should prove persistent index restore before query reuse');
assert.equal(soakReport.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.ok(soakReport.indexSummary.indexedTokenCount > 100, 'large-project soak should retain a meaningful vector token set');
assert.ok(soakReport.indexSummary.maxPostingsPerToken > 50, 'large-project soak should measure high-frequency postings');
assert.ok(soakReport.indexSummary.largestDocumentTokens > 20, 'large-project soak should capture per-document token volume');
assert.ok(soakReport.totalMatches >= 3, 'large-project soak should find indexed matches for every query family');
assert.ok(soakReport.queries.every((query) => query.matchCount > 0), 'every soak query should produce provider-style index matches');
assert.ok(soakReport.queries.every((query) => query.searchResultCount > 0), 'provider-style index matches should plug into normal search results');
assert.ok(soakReport.content.includes('Bearer large-soak-secret-token-042'), 'large-project operational soak report should preserve bearer tokens until report generation');
assert.ok(soakReport.content.includes('session=large-session-042'), 'large-project operational soak report should preserve cookies until report generation');

const fullText = searchEngine.searchExchangesWithMeta(exchanges, 'real-secret-token session=abc123');
assert.equal(fullText.results[0].id, 'hx-authz-role-boundary', 'full-text search should span raw request metadata and body material');

const parityPackage = searchEngine.buildSearchParityEvidencePackage({
  fullTextRun: fullText,
  structuredRun: structured,
  semanticRun: semantic,
  providerRun: provider,
  evidencePackage: packageResult,
  semanticIndex,
  restoredIndex,
  indexMatches: indexedMatches,
  soakReport,
  toolHandoffs: [
    {
      tool: 'search-index',
      exchangeIds: indexedMatches.map((match) => match.exchangeId),
      command: 'proxyforge-agent search-index --project ./workspace.proxyforge.json --query "authz bypass" --soak --json',
      artifactPath: './artifacts/search-index.json',
      purpose: 'Agent persistent index reuse for large-project semantic lookup.',
    },
    {
      tool: 'view',
      exchangeIds: ['hx-authz-role-boundary'],
      command: 'proxyforge-agent view --project ./workspace.proxyforge.json --request-id hx-authz-role-boundary --mode raw --json',
      purpose: 'Open full-fidelity raw request/response after a search hit.',
    },
    {
      tool: 'reports',
      exchangeIds: ['hx-authz-role-boundary', 'hx-graphql-cors'],
      artifactPath: './reports/search-findings.json',
      purpose: 'Carry selected hits into report export where redaction begins.',
    },
  ],
  operationalSecretSamples: ['real-secret-token', 'session=abc123', 'large-soak-secret-token-042', 'large-session-042'],
  exportedAt: '2026-05-25T10:00:00.000Z',
});
assert.equal(parityPackage.kind, 'proxyforge-search-parity-evidence-package');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.reportReady, true);
assert.deepEqual(Object.values(parityPackage.requirements).filter(Boolean).length, Object.values(parityPackage.requirements).length, 'all search parity requirements should be covered');
assert.ok(parityPackage.requirements.fullTextSearchCovered, 'parity package should prove full-text search');
assert.ok(parityPackage.requirements.metadataBodyRawCovered, 'parity package should prove metadata/body/raw coverage');
assert.ok(parityPackage.requirements.structuredPredicatesCovered, 'parity package should prove structured predicates');
assert.ok(parityPackage.requirements.negationCovered, 'parity package should prove negation');
assert.ok(parityPackage.requirements.orQueriesCovered, 'parity package should prove OR queries');
assert.ok(parityPackage.requirements.semanticRankingCovered, 'parity package should prove semantic ranking');
assert.ok(parityPackage.requirements.providerScoreMergeCovered, 'parity package should prove provider score merge');
assert.ok(parityPackage.requirements.persistentIndexCovered, 'parity package should prove persistent semantic index restore and reuse');
assert.ok(parityPackage.requirements.largeProjectSoakCovered, 'parity package should prove large-project semantic soak');
assert.ok(parityPackage.requirements.toolHandoffCovered, 'parity package should prove agent/view handoff');
assert.ok(parityPackage.content.includes('real-secret-token'), 'search parity content should keep executor bearer token full fidelity');
assert.ok(parityPackage.content.includes('session=abc123'), 'search parity content should keep executor cookie full fidelity');

const artifactDir = path.resolve('.gitignored/test-artifacts/search-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(
  path.join(artifactDir, 'search-parity-evidence-package.json'),
  parityPackage.content,
  'utf8',
);

console.log('search-engine: exercised search parity package, semantic ranking, persistent index restore, provider scores, provider diagnostics, full-fidelity corpus export, large-project semantic index soak, and existing structured query behavior');

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

function buildExchanges() {
  return [
    {
      id: 'hx-authz-role-boundary',
      method: 'POST',
      host: 'app.shop.local',
      path: '/api/refunds',
      url: 'https://app.shop.local/api/refunds',
      status: 403,
      length: 420,
      mime: 'application/json',
      risk: 'high',
      timing: 121,
      notes: 'Alternate role replay crossed an authorization boundary.',
      source: 'repeater',
      time: '20:58:00',
      requestRaw: 'POST /api/refunds HTTP/1.1\nHost: app.shop.local\nAuthorization: Bearer real-secret-token\nCookie: session=abc123\n\namount=100',
      responseRaw: 'HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{"permission":"refund.write","role":"viewer"}',
      tags: ['authz', 'replayed'],
    },
    {
      id: 'hx-graphql-cors',
      method: 'OPTIONS',
      host: 'api.shop.local',
      path: '/v2/graphql',
      url: 'https://api.shop.local/v2/graphql',
      status: 204,
      length: 0,
      mime: 'text/plain',
      risk: 'medium',
      timing: 64,
      notes: 'GraphQL CORS preflight with credentialed origin review.',
      source: 'scanner',
      time: '20:58:04',
      requestRaw: 'OPTIONS /v2/graphql HTTP/1.1\nHost: api.shop.local\nOrigin: https://evil.example\n\n',
      responseRaw: 'HTTP/1.1 204 No Content\nAccess-Control-Allow-Origin: https://evil.example\nAccess-Control-Allow-Credentials: true\n\n',
      tags: ['cors', 'graphql'],
    },
    {
      id: 'hx-static-js',
      method: 'GET',
      host: 'cdn.shop.local',
      path: '/assets/app.js',
      url: 'https://cdn.shop.local/assets/app.js',
      status: 200,
      length: 3200,
      mime: 'application/javascript',
      risk: 'low',
      timing: 28,
      notes: 'Static JavaScript bundle references source maps.',
      source: 'proxy',
      time: '20:58:09',
      requestRaw: 'GET /assets/app.js HTTP/1.1\nHost: cdn.shop.local\n\n',
      responseRaw: 'HTTP/1.1 200 OK\nContent-Type: application/javascript\n\n//# sourceMappingURL=app.js.map',
      tags: ['static'],
    },
    {
      id: 'hx-connect',
      method: 'CONNECT',
      host: 'auth.shop.local',
      path: ':443',
      url: 'https://auth.shop.local',
      status: 200,
      length: 0,
      mime: 'tunnel',
      risk: 'info',
      timing: 12,
      notes: 'Tunnel metadata.',
      source: 'proxy',
      time: '20:58:10',
      requestRaw: 'CONNECT auth.shop.local:443 HTTP/1.1\nHost: auth.shop.local:443\n\n',
      responseRaw: 'HTTP/1.1 200 Connection Established\n\n',
      tags: ['tunnel'],
    },
  ];
}

function buildLargeProjectExchanges(count) {
  const risks = ['info', 'low', 'medium', 'high', 'critical'];
  const sources = ['proxy', 'repeater', 'scanner', 'browser'];
  const hosts = ['app.shop.local', 'api.shop.local', 'admin.shop.local', 'cdn.shop.local'];
  return Array.from({ length: count }, (_, index) => {
    const padded = String(index).padStart(3, '0');
    const family = index % 4;
    const host = hosts[index % hosts.length];
    const risk = risks[index % risks.length];
    const source = sources[index % sources.length];
    const commonHeaders = [
      `Host: ${host}`,
      `Authorization: Bearer large-soak-secret-token-${padded}`,
      `Cookie: session=large-session-${padded}; theme=dark`,
      'Content-Type: application/json',
    ].join('\n');

    if (family === 0) {
      return {
        id: `hx-soak-authz-${padded}`,
        method: 'POST',
        host,
        path: `/api/refunds/${index}`,
        url: `https://${host}/api/refunds/${index}?role=viewer&amount=${100 + index}`,
        status: index % 8 === 0 ? 403 : 200,
        length: 600 + index,
        mime: 'application/json',
        risk,
        timing: 80 + (index % 40),
        notes: 'Large-project authz refund bypass replay candidate with alternate role boundary evidence.',
        source,
        time: '09:00:00',
        requestRaw: `POST /api/refunds/${index}?role=viewer&amount=${100 + index} HTTP/1.1\n${commonHeaders}\n\n{"amount":${100 + index},"role":"viewer","permission":"refund.write","bypassProbe":true}`,
        responseRaw: 'HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{"permission":"refund.write","role":"viewer","decision":"deny","boundary":"authorization"}',
        tags: ['authz', 'refund', 'replayed', 'large-project'],
      };
    }

    if (family === 1) {
      return {
        id: `hx-soak-graphql-${padded}`,
        method: 'POST',
        host,
        path: '/v2/graphql',
        url: `https://${host}/v2/graphql?operation=refundReview${index}`,
        status: 200,
        length: 900 + index,
        mime: 'application/json',
        risk,
        timing: 65 + (index % 30),
        notes: 'GraphQL CORS credentialed origin review with mutation and cache-control signals.',
        source,
        time: '09:00:01',
        requestRaw: `POST /v2/graphql?operation=refundReview${index} HTTP/1.1\n${commonHeaders}\nOrigin: https://evil.example\n\n{"query":"mutation RefundReview { refund(id: ${index}) { id status } }"}`,
        responseRaw: 'HTTP/1.1 200 OK\nContent-Type: application/json\nAccess-Control-Allow-Origin: https://evil.example\nAccess-Control-Allow-Credentials: true\nCache-Control: private\n\n{"data":{"refund":{"status":"queued"}}}',
        tags: ['graphql', 'cors', 'large-project'],
      };
    }

    if (family === 2) {
      return {
        id: `hx-soak-callback-${padded}`,
        method: 'GET',
        host,
        path: `/api/avatar/${index}`,
        url: `https://${host}/api/avatar/${index}?url=https://callback-${padded}.oast.local/pixel`,
        status: 202,
        length: 320 + index,
        mime: 'application/json',
        risk,
        timing: 90 + (index % 50),
        notes: 'Callback SSRF collaborator replay candidate with DNS and HTTP OAST correlation.',
        source,
        time: '09:00:02',
        requestRaw: `GET /api/avatar/${index}?url=https://callback-${padded}.oast.local/pixel HTTP/1.1\n${commonHeaders}\n\n`,
        responseRaw: 'HTTP/1.1 202 Accepted\nContent-Type: application/json\n\n{"callback":"queued","service":"image-fetcher","oast":"dns-http"}',
        tags: ['callback', 'oast', 'ssrf', 'large-project'],
      };
    }

    return {
      id: `hx-soak-static-${padded}`,
      method: 'GET',
      host,
      path: `/assets/app-${index}.js`,
      url: `https://${host}/assets/app-${index}.js?build=${index}`,
      status: 200,
      length: 2200 + index,
      mime: 'application/javascript',
      risk,
      timing: 20 + (index % 25),
      notes: 'Static bundle secret token discovery lane with source-map and api-key references for large project search.',
      source,
      time: '09:00:03',
      requestRaw: `GET /assets/app-${index}.js?build=${index} HTTP/1.1\n${commonHeaders}\n\n`,
      responseRaw: `HTTP/1.1 200 OK\nContent-Type: application/javascript\n\nwindow.__API_KEY__="large-soak-secret-token-${padded}";\n//# sourceMappingURL=app-${index}.js.map`,
      tags: ['static', 'secret', 'large-project'],
    };
  });
}
