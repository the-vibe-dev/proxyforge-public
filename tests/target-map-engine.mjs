import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const candidateEnginePaths = [
  'src/targetMapEngine.ts',
  'src/target-map-engine.ts',
  'electron/targetMapEngine.ts',
  'electron/target-map-engine.ts',
  'dist-electron/targetMapEngine.js',
  'dist-electron/target-map-engine.js',
];

const sampleCrawl = {
  startUrl: 'https://app.shop.local/',
  routes: [
    {
      id: 'route-home',
      method: 'GET',
      url: 'https://app.shop.local/',
      host: 'app.shop.local',
      path: '/',
      status: 200,
      mime: 'text/html',
      depth: 0,
      source: 'link',
      title: 'Shop Home',
      discoveredAt: '2026-05-24T12:00:00.000Z',
      insertionPoints: [],
    },
    {
      id: 'route-refunds',
      method: 'POST',
      url: 'https://app.shop.local/api/refunds',
      host: 'app.shop.local',
      path: '/api/refunds',
      status: 403,
      mime: 'application/json',
      depth: 1,
      source: 'form',
      title: 'Refund API',
      discoveredAt: '2026-05-24T12:00:01.000Z',
      insertionPoints: ['point-order-id', 'point-amount', 'point-reason', 'point-csrf', 'point-session'],
    },
    {
      id: 'route-orders',
      method: 'GET',
      url: 'https://app.shop.local/admin/orders?status=open',
      host: 'app.shop.local',
      path: '/admin/orders?status=open',
      status: 200,
      mime: 'text/html',
      depth: 1,
      source: 'link',
      title: 'Orders',
      discoveredAt: '2026-05-24T12:00:02.000Z',
      insertionPoints: ['point-status', 'point-order-path'],
    },
    {
      id: 'route-graphql',
      method: 'POST',
      url: 'https://api.shop.local/v2/graphql',
      host: 'api.shop.local',
      path: '/v2/graphql',
      status: 200,
      mime: 'application/json',
      depth: 1,
      source: 'script',
      title: 'GraphQL API',
      discoveredAt: '2026-05-24T12:00:03.000Z',
      insertionPoints: ['point-query'],
    },
  ],
  insertionPoints: [
    {
      id: 'point-status',
      routeId: 'route-orders',
      type: 'query',
      name: 'status',
      method: 'GET',
      url: 'https://app.shop.local/admin/orders?status=open',
      evidence: 'query parameter status=open',
    },
    {
      id: 'point-order-path',
      routeId: 'route-orders',
      type: 'path',
      name: 'orderId',
      method: 'GET',
      url: 'https://app.shop.local/admin/orders/100',
      evidence: 'path segment orderId=100',
    },
    {
      id: 'point-order-id',
      routeId: 'route-refunds',
      type: 'form',
      name: 'orderId',
      method: 'POST',
      url: 'https://app.shop.local/api/refunds',
      evidence: 'refund form field orderId',
    },
    {
      id: 'point-amount',
      routeId: 'route-refunds',
      type: 'form',
      name: 'amount',
      method: 'POST',
      url: 'https://app.shop.local/api/refunds',
      evidence: 'refund form field amount',
    },
    {
      id: 'point-reason',
      routeId: 'route-refunds',
      type: 'form',
      name: 'reason',
      method: 'POST',
      url: 'https://app.shop.local/api/refunds',
      evidence: 'refund form field reason',
    },
    {
      id: 'point-csrf',
      routeId: 'route-refunds',
      type: 'header',
      name: 'x-csrf-token',
      method: 'POST',
      url: 'https://app.shop.local/api/refunds',
      evidence: 'header x-csrf-token from authenticated form submission',
    },
    {
      id: 'point-session',
      routeId: 'route-refunds',
      type: 'cookie',
      name: 'session',
      method: 'POST',
      url: 'https://app.shop.local/api/refunds',
      evidence: 'cookie session reused from authenticated crawler profile',
    },
    {
      id: 'point-query',
      routeId: 'route-graphql',
      type: 'body',
      name: 'query',
      method: 'POST',
      url: 'https://api.shop.local/v2/graphql',
      evidence: 'GraphQL query payload',
    },
  ],
  exchanges: [],
  blocked: false,
  totalRequests: 4,
  message: 'Crawler discovered 4 routes and 5 insertion points',
};

const sampleTargetMapRequest = {
  crawl: sampleCrawl,
  baseline: {
    name: 'Target baseline',
    routeIds: ['route-home', 'route-orders'],
    capturedAt: '2026-05-24T12:00:00.000Z',
  },
  candidate: {
    name: 'Target candidate',
    routeIds: ['route-home', 'route-orders', 'route-refunds', 'route-graphql'],
    capturedAt: '2026-05-24T12:05:00.000Z',
  },
  filters: {
    url: '/api/refunds',
    source: 'form',
    status: '403',
    mime: 'application/json',
  },
  accessControlProfiles: ['customer', 'support_admin', 'finance_admin'],
  accessControlRoleMaps: [
    {
      role: 'customer',
      visibleRouteIds: ['route-home', 'route-orders'],
      deniedRouteIds: ['route-refunds'],
      statusByRoute: {
        'route-home': 200,
        'route-orders': 200,
        'route-refunds': 403,
        'route-graphql': 403,
      },
      exchangeIds: ['hx-customer-home', 'hx-customer-orders', 'hx-customer-refunds'],
      capturedAt: '2026-05-24T12:02:00.000Z',
    },
    {
      role: 'support_admin',
      visibleRouteIds: ['route-home', 'route-orders', 'route-refunds', 'route-graphql'],
      statusByRoute: {
        'route-home': 200,
        'route-orders': 200,
        'route-refunds': 202,
        'route-graphql': 200,
      },
      exchangeIds: ['hx-support-home', 'hx-support-orders', 'hx-support-refunds', 'hx-support-graphql'],
      capturedAt: '2026-05-24T12:04:00.000Z',
    },
  ],
  now: '2026-05-24T12:10:00.000Z',
};

const optionalChecks = [
  {
    names: ['buildTargetSiteMapViewModel', 'buildAdvancedTargetSiteMap', 'buildTargetMapViewModel'],
    pattern: /URL view|Crawl-path|site map|route|crawler|filter/i,
  },
  {
    names: ['buildTargetContentDiscoveryHandoff', 'buildContentDiscoveryHandoff'],
    pattern: /content discovery|handoff|wordlist|candidate path|route/i,
  },
  {
    names: ['buildTargetAnalyzerInventory', 'buildTargetAnalyzer', 'analyzeTargetSiteMap'],
    pattern: /target analyzer|technology|parameter|inventory|GraphQL|JavaScript|JSON/i,
  },
  {
    names: ['buildTargetTechnologyInventory', 'detectTargetTechnologies'],
    pattern: /technology|GraphQL|JavaScript|JSON|HTTP|React/i,
  },
  {
    names: ['buildTargetParameterInventory', 'inventoryTargetParameters'],
    pattern: /parameter|status|orderId|amount|reason|query/i,
  },
  {
    names: ['buildTargetAccessControlReview', 'reviewTargetAccessControl'],
    pattern: /access-control|authorization|customer|support_admin|matrix|review/i,
  },
  {
    names: ['buildTargetSiteMapComparisonPackage', 'buildSiteMapComparisonPackage'],
    pattern: /proxyforge-target-site-map-comparison|comparison|baseline|candidate|digest/i,
  },
  {
    names: ['buildTargetSiteMapReportAttachment', 'buildTargetReportAttachment'],
    pattern: /Target Site Map Evidence|Target site-map evidence|report-ready|attachment/i,
  },
];

const enginePath = await firstExistingPath(candidateEnginePaths);
if (!enginePath) {
  console.log('target-map-engine: skipped; no Target map engine module is exported yet');
  process.exit(0);
}

const targetMapEngine = await loadEngine(enginePath);
let exercisedHelpers = 0;

for (const check of optionalChecks) {
  const result = await callFirstAvailableHelper(targetMapEngine, check.names, [sampleTargetMapRequest]);
  if (!result.called) continue;
  exercisedHelpers += 1;
  assert.match(
    stringify(result.value),
    check.pattern,
    `${result.name} should expose advanced Target site-map parity evidence`,
  );
}

if (typeof targetMapEngine.buildTargetAccessControlReview === 'function') {
  const lanes = targetMapEngine.buildTargetAccessControlReview(sampleTargetMapRequest);
  const customer = lanes.find((lane) => lane.role === 'customer');
  const support = lanes.find((lane) => lane.role === 'support_admin');
  assert(customer, 'customer access-control lane should exist');
  assert(support, 'support_admin access-control lane should exist');
  assert.equal(customer.requirements.packageRefreshCovered, true, 'customer access-control lane should carry refresh proof');
  assert.equal(customer.requirements.rawExchangeLinksCovered, true, 'customer access-control lane should preserve exchange links');
  assert(customer.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-access-control-role-map'));
  assert(customer.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-access-control-decisions'));
  assert.equal(customer.packageRefreshProof.stalePackageIds.length, 0);
  assert.equal(customer.routeDecisions.some((decision) => decision.routeId === 'route-orders' && decision.drift === 'overexposed'), true);
  assert.equal(customer.overexposedCount >= 1, true);
  assert.equal(customer.deniedRouteCount >= 1, true);
  assert.match(customer.evidenceSummary, /visible|denied|overexposed|missing observation/i);
  assert.equal(support.routeDecisions.some((decision) => decision.routeId === 'route-refunds' && decision.observed === 'visible'), true);
  assert.match(JSON.stringify(lanes), /Scanner authz-diff|Comparer response deltas|hx-support-refunds/);
}

if (typeof targetMapEngine.buildTargetSiteMapComparisonPackage === 'function') {
  const comparison = targetMapEngine.buildTargetSiteMapComparisonPackage(sampleTargetMapRequest);
  assert.equal(comparison.normalization.includes('parameter-names'), true);
  assert.equal(comparison.requirements.packageRefreshCovered, true);
  assert(comparison.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-comparison-baseline-routes'));
  assert(comparison.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-comparison-candidate-routes'));
  assert(comparison.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-comparison-deltas'));
  assert.equal(comparison.packageRefreshProof.stalePackageIds.length, 0);
  assert.equal(comparison.parameterChanged >= 1, true);
  assert.equal(comparison.authzSensitiveChanged >= 1, true);
  assert.equal(comparison.highRiskDeltaCount >= 1, true);
  assert(
    comparison.deltas.some((delta) => delta.changeTypes?.includes('authz') && delta.evidence?.some((entry) => /authzSensitive=true/.test(entry))),
    'comparison package should retain authz-sensitive delta evidence',
  );
  assert.match(JSON.stringify(comparison), /form:orderId|body:query|parameter-names|authz-sensitive-route/);
}

if (typeof targetMapEngine.buildTargetParityEvidencePackage === 'function') {
  const viewModel = targetMapEngine.buildTargetSiteMapViewModel(sampleTargetMapRequest);
  const analysisPackage = targetMapEngine.buildTargetAnalyzerInventory(sampleTargetMapRequest);
  const comparisonPackage = targetMapEngine.buildTargetSiteMapComparisonPackage(sampleTargetMapRequest);
  assert.equal(analysisPackage.requirements.contentDiscoveryPackageRefreshCovered, true);
  assert.equal(analysisPackage.requirements.accessControlPackageRefreshCovered, true);
  assert.equal(analysisPackage.requirements.inventoryPackageRefreshCovered, true);
  assert(analysisPackage.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-content-discovery-handoff'));
  assert(analysisPackage.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-access-control-review'));
  assert.equal(analysisPackage.packageRefreshProof.stalePackageIds.length, 0);
  const evidenceAttachment = targetMapEngine.buildTargetSiteMapReportAttachment({
    ...sampleTargetMapRequest,
    analysisPackage,
    comparisonPackage,
    issueId: 'issue-target-parity',
  });
  assert.equal(evidenceAttachment.requirements.packageRefreshCovered, true);
  assert(evidenceAttachment.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-site-map-analysis'));
  assert(evidenceAttachment.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-site-map-comparison'));
  const parityPackage = targetMapEngine.buildTargetParityEvidencePackage({
    ...sampleTargetMapRequest,
    scopeAllowlist: ['app.shop.local', 'api.shop.local'],
    viewModel,
    analysisPackage,
    comparisonPackage,
    evidenceAttachment,
    authenticatedSessionEvidence: {
      profileIds: ['customer-session', 'support-admin-session'],
      refreshedCookieNames: ['session', 'csrf'],
      reusedExchangeIds: ['hx-support-refunds', 'hx-support-graphql'],
      scannerProfileIds: ['support-admin-session'],
      crawlerProfileIds: ['customer-session'],
      notes: ['Crawler, Repeater, Scanner, and Target maps reuse full-fidelity authenticated session material until reporting.'],
    },
    operationalSecretSamples: [
      'Cookie: session=target-live-session; csrf=target-live-csrf',
      'Authorization: Bearer target-live-token',
      'X-CSRF-Token: target-live-csrf',
    ],
  });
  assert.equal(parityPackage.kind, 'proxyforge-target-parity-evidence-package');
  assert.equal(parityPackage.reportReady, true);
  assert.equal(parityPackage.routeCount, sampleCrawl.routes.length);
  assert.equal(parityPackage.insertionPointCount, sampleCrawl.insertionPoints.length);
  assert.equal(parityPackage.requirements.packageRefreshCovered, true);
  assert(parityPackage.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-site-map-analysis'));
  assert(parityPackage.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-content-discovery-handoff'));
  assert(parityPackage.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-access-control-review'));
  assert(parityPackage.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-site-map-comparison'));
  assert(parityPackage.packageRefreshProof.linkedPackageKinds.includes('proxyforge-target-site-map-evidence'));
  assert.equal(parityPackage.packageRefreshProof.stalePackageIds.length, 0);
  for (const [name, covered] of Object.entries(parityPackage.requirements)) {
    assert.equal(covered, true, `Target parity requirement ${name} should be covered`);
  }
  assert.match(parityPackage.content, /target-live-session|target-live-token|target-live-csrf/);
  assert.match(parityPackage.content, /packageRefreshProof|proxyforge-target-content-discovery-handoff|proxyforge-target-access-control-review/);
  assert.match(parityPackage.content, /redact-only-during-report-export/);
  assert.match(parityPackage.content, /query|form|path|header|cookie|GraphQL|JSON API|Target Site Map Evidence/i);

  const artifactDir = path.resolve('.gitignored/test-artifacts/target-map-engine');
  await fs.mkdir(artifactDir, { recursive: true });
  await fs.writeFile(
    path.join(artifactDir, 'target-parity-evidence-package.json'),
    JSON.stringify(parityPackage, null, 2),
  );
}

if (exercisedHelpers === 0) {
  console.log(`target-map-engine: skipped; ${path.relative(process.cwd(), enginePath)} does not export advanced Target site-map helpers yet`);
} else {
  console.log(`target-map-engine: exercised ${exercisedHelpers} advanced Target site-map helper(s)`);
}

async function firstExistingPath(candidates) {
  for (const candidate of candidates) {
    const resolved = path.resolve(candidate);
    try {
      const stat = await fs.stat(resolved);
      if (stat.isFile()) return resolved;
    } catch {
      // Keep looking for an optional Target map engine export.
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
  };
  vm.runInNewContext(transpiled, sandbox, { filename: enginePath });
  return module.exports;
}

async function callFirstAvailableHelper(moduleExports, names, args) {
  for (const name of names) {
    const helper = moduleExports[name];
    if (typeof helper !== 'function') continue;
    return { called: true, name, value: await helper(...args) };
  }
  return { called: false, name: '', value: null };
}

function stringify(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
