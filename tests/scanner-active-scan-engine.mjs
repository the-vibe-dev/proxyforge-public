import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const candidateEnginePaths = [
  'src/scannerActiveScanEngine.ts',
  'src/scanner-active-scan-engine.ts',
  'src/scanner/activeScanEngine.ts',
  'src/scanner/active-scan-engine.ts',
  'electron/scannerActiveScanEngine.ts',
  'electron/scanner-active-scan-engine.ts',
  'electron/scanner/activeScanEngine.ts',
  'electron/scanner/active-scan-engine.ts',
  'dist-electron/scannerActiveScanEngine.js',
  'dist-electron/scanner-active-scan-engine.js',
  'dist-electron/src/scanner/activeScanEngine.js',
  'dist-electron/src/scanner/active-scan-engine.js',
  'dist/scannerActiveScanEngine.js',
  'dist/scanner-active-scan-engine.js',
  'dist/scanner/activeScanEngine.js',
  'dist/scanner/active-scan-engine.js',
];
const expectedExports = [
  'buildScannerActiveScanPlan',
  'buildScannerInsertionPointReview',
  'buildScannerAuthenticatedStateMatrix',
  'buildScannerReplayCheckPackage',
  'buildScannerActiveScanEvidencePackage',
  'buildScannerLiveTargetProfilePackage',
  'buildScannerOastIssuePromotionPackage',
];

const enginePath = await firstExistingPath(candidateEnginePaths);
if (!enginePath) {
  console.log('scanner-active-scan-engine: skipped; no Scanner active scan engine module is exported yet');
  process.exit(0);
}
const importedScannerActiveScanEngine = await loadEngine(enginePath);
const scannerActiveScanEngine = normalizeModuleExports(importedScannerActiveScanEngine);

const missingExports = expectedExports.filter((name) => typeof scannerActiveScanEngine[name] !== 'function');
if (missingExports.length) {
  console.log(`scanner-active-scan-engine: skipped; missing Scanner active scan export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const sampleRequest = buildSampleScannerActiveScanRequest();

const activeScanPlan = await scannerActiveScanEngine.buildScannerActiveScanPlan(sampleRequest);
assertActiveScanPlan(activeScanPlan, 'buildScannerActiveScanPlan');

const insertionPointReview = await scannerActiveScanEngine.buildScannerInsertionPointReview({
  ...sampleRequest,
  activeScanPlan,
});
assertInsertionPointReview(insertionPointReview, 'buildScannerInsertionPointReview');

const inferredInsertionPointReview = await scannerActiveScanEngine.buildScannerInsertionPointReview({
  ...sampleRequest,
  insertionPoints: [],
  activeScanPlan,
});
assert(
  inferredInsertionPointReview.rows.some((row) => row.type === 'json' && /amount|orderId|reason/i.test(row.label)),
  'Scanner should infer JSON body insertion points from raw selected requests',
);
assert(
  inferredInsertionPointReview.rows.some((row) => row.type === 'header' && /Authorization|Idempotency/i.test(row.label)),
  'Scanner should infer header insertion points from raw selected requests',
);
assert(
  inferredInsertionPointReview.rows.some((row) => row.type === 'graphql' && /query|operationName/i.test(row.label)),
  'Scanner should infer GraphQL insertion points from raw selected requests',
);

const authenticatedStateMatrix = await scannerActiveScanEngine.buildScannerAuthenticatedStateMatrix({
  ...sampleRequest,
  activeScanPlan,
  insertionPointReview,
});
assertAuthenticatedStateMatrix(authenticatedStateMatrix, 'buildScannerAuthenticatedStateMatrix');

const replayCheckPackage = await scannerActiveScanEngine.buildScannerReplayCheckPackage({
  ...sampleRequest,
  activeScanPlan,
  insertionPointReview,
  authenticatedStateMatrix,
});
assertPackageArtifact(
  replayCheckPackage,
  'buildScannerReplayCheckPackage',
  /proxyforge-scanner-replay-check|scanner.*replay.*check|replay.*check.*package|check[- ]?pack/i,
  /replay[- ]derived|GraphQL|\/api\/refunds|idempotency|authz|active scan/i,
);

const evidencePackage = await scannerActiveScanEngine.buildScannerActiveScanEvidencePackage({
  ...sampleRequest,
  activeScanPlan,
  insertionPointReview,
  authenticatedStateMatrix,
  replayCheckPackage,
  issueId: 'issue-scanner-active-scan-authz',
});
assertPackageArtifact(
  evidencePackage,
  'buildScannerActiveScanEvidencePackage',
  /proxyforge-scanner-active-scan-evidence|scanner.*active.*scan.*evidence|active.*scan.*evidence.*package/i,
  /report[- ]ready|evidence|check[- ]?pack|authenticated[- ]state|\/api\/refunds|GraphQL/i,
);
assertReportReadyLanguage(evidencePackage, 'buildScannerActiveScanEvidencePackage');
assertScannerActiveScanEvidenceRequirements(evidencePackage, 'buildScannerActiveScanEvidencePackage');

const artifactDir = path.resolve('.gitignored/test-artifacts/scanner-active-scan-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(
  path.join(artifactDir, 'scanner-active-scan-evidence-package.json'),
  JSON.stringify(evidencePackage, null, 2),
  'utf8',
);

const ciReportHandoff = await callFirstAvailableHelper(
  scannerActiveScanEngine,
  [
    'buildScannerCiReportHandoff',
    'buildScannerHeadlessReportHandoff',
    'buildScannerActiveScanCiHandoff',
  ],
  [{
    ...sampleRequest,
    activeScanPlan,
    insertionPointReview,
    authenticatedStateMatrix,
    replayCheckPackage,
    evidencePackage,
    issueId: 'issue-scanner-active-scan-authz',
  }],
);
if (ciReportHandoff.called) {
  assertCiHandoff(ciReportHandoff.value, ciReportHandoff.name);
}

const issuePromotion = await callFirstAvailableHelper(
  scannerActiveScanEngine,
  [
    'buildScannerActiveScanIssuePromotion',
    'buildScannerIssuePromotion',
    'buildScannerPromotionCandidate',
    'promoteScannerActiveScanEvidenceToIssue',
  ],
  [{
    ...sampleRequest,
    activeScanPlan,
    insertionPointReview,
    authenticatedStateMatrix,
    replayCheckPackage,
    evidencePackage,
    ciReportHandoff: ciReportHandoff.value,
    issueId: 'issue-scanner-active-scan-authz',
  }],
);
if (issuePromotion.called) {
  assertReportReadyLanguage(issuePromotion.value, issuePromotion.name);
  assert.match(
    stringify(issuePromotion.value),
    /active scan|Scanner|issue|evidence|authenticated[- ]state|authorization boundary/i,
    `${issuePromotion.name} should preserve Scanner issue promotion context`,
  );
}

const oastIssuePromotionPackage = await scannerActiveScanEngine.buildScannerOastIssuePromotionPackage(buildSampleScannerOastIssuePromotionRequest(sampleRequest));
assertScannerOastIssuePromotionPackage(oastIssuePromotionPackage, 'buildScannerOastIssuePromotionPackage');

const scannerLiveTargetProfilePackage = await scannerActiveScanEngine.buildScannerLiveTargetProfilePackage({
  activeScanEvidencePackages: [evidencePackage],
  activeScanSummaries: [sampleRequest.activeScanSummary],
  passiveDedupePackages: [buildSyntheticScannerPassiveDedupePackage(sampleRequest.now)],
  insertionInventoryPackages: [buildSyntheticInsertionInventoryPackage(sampleRequest.now)],
  oastIssuePromotionPackages: [oastIssuePromotionPackage],
  anvilCompatibilityPackages: [buildSyntheticAnvilCompatibilityPackage(sampleRequest.now)],
  retestPackages: [buildSyntheticScannerRetestPackage(sampleRequest.now)],
  calibrationPackages: [buildSyntheticScannerCalibrationPackage(sampleRequest.activeScanSummary, sampleRequest.now)],
  minTargetHosts: 2,
  minRoutes: 3,
  minRequests: 10,
  minCheckFamilies: 8,
  minTuningProfiles: 1,
  operationalSecretSamples: [
    'Authorization: Bearer customer-token',
    'Authorization: Bearer scanner-oast-agent-token',
    'Authorization: Bearer anvil-headless-token',
    'session=scanner-oast-session',
    'redact-only-during-report-export',
  ],
  generatedAt: sampleRequest.now,
});
assertScannerLiveTargetProfilePackage(scannerLiveTargetProfilePackage, 'buildScannerLiveTargetProfilePackage');

await fs.writeFile(
  path.join(artifactDir, 'scanner-live-target-profile-package.json'),
  JSON.stringify(scannerLiveTargetProfilePackage, null, 2),
  'utf8',
);

console.log(`scanner-active-scan-engine: exercised ${expectedExports.length + (ciReportHandoff.called ? 1 : 0) + (issuePromotion.called ? 1 : 0)} Scanner active scan helper(s)`);

async function firstExistingPath(candidates) {
  for (const candidate of candidates) {
    const resolved = path.resolve(candidate);
    try {
      const stat = await fs.stat(resolved);
      if (stat.isFile()) return resolved;
    } catch {
      // Keep looking for an optional Scanner active scan engine export.
    }
  }
  return '';
}

async function loadEngine(enginePath) {
  if (enginePath.endsWith('.js') || enginePath.endsWith('.cjs')) {
    return require(enginePath);
  }

  return loadTsModule(enginePath);
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
    crypto: globalThis.crypto,
    setTimeout,
    clearTimeout,
    require: localRequire,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: resolved });
  return module.exports;
}

async function loadEngineLegacy(enginePath) {
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

function buildSampleScannerActiveScanRequest() {
  const now = '2026-05-24T17:10:00.000Z';
  const exchanges = [
    {
      id: 'hx-scan-profile-baseline',
      method: 'GET',
      host: 'app.shop.local',
      path: '/api/account/profile',
      url: 'https://app.shop.local/api/account/profile',
      status: 200,
      length: 1842,
      mime: 'application/json',
      risk: 'medium',
      timing: 118,
      source: 'proxy',
      time: '14:02:03',
      requestRaw: [
        'GET /api/account/profile HTTP/2',
        'Host: app.shop.local',
        'Authorization: Bearer customer-token',
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
      notes: 'Customer baseline captures account role before Scanner active scan planning.',
      tags: ['baseline', 'auth', 'http2'],
    },
    {
      id: 'hx-scan-refund-denied',
      method: 'POST',
      host: 'app.shop.local',
      path: '/api/refunds',
      url: 'https://app.shop.local/api/refunds',
      status: 403,
      length: 612,
      mime: 'application/json',
      risk: 'high',
      timing: 231,
      source: 'proxy',
      time: '14:03:18',
      requestRaw: [
        'POST /api/refunds HTTP/2',
        'Host: app.shop.local',
        'Content-Type: application/json',
        'Authorization: Bearer customer-token',
        'Idempotency-Key: pf-base-001',
        '',
        '{"orderId":"ord_90210","amount":7900,"reason":"manual review"}',
      ].join('\n'),
      responseRaw: [
        'HTTP/2 403 Forbidden',
        'Content-Type: application/json',
        '',
        '{"error":"missing_permission","required":"refunds.write"}',
      ].join('\n'),
      notes: 'Customer refund attempt is denied and becomes an active scan insertion point candidate.',
      tags: ['authz', 'candidate', 'http2'],
    },
    {
      id: 'hx-scan-refund-replay-allowed',
      method: 'POST',
      host: 'app.shop.local',
      path: '/api/refunds',
      url: 'https://app.shop.local/api/refunds',
      status: 200,
      length: 744,
      mime: 'application/json',
      risk: 'high',
      timing: 188,
      source: 'repeater',
      time: '14:04:12',
      requestRaw: [
        'POST /api/refunds HTTP/2',
        'Host: app.shop.local',
        'Content-Type: application/json',
        'Authorization: Bearer support-token',
        'Idempotency-Key: pf-replay-001',
        'X-ProxyForge-Active-Scan: authz-diff',
        '',
        '{"orderId":"ord_90210","amount":7900,"reason":"manual review"}',
      ].join('\n'),
      responseRaw: [
        'HTTP/2 200 OK',
        'Content-Type: application/json',
        '',
        '{"status":"approved","role":"support_admin","refundId":"rf_1001"}',
      ].join('\n'),
      notes: 'Repeater replay shows privileged refund behavior for Scanner replay-derived checks.',
      tags: ['authz', 'replay', 'active-scan', 'http2'],
    },
    {
      id: 'hx-scan-graphql-introspection',
      method: 'POST',
      host: 'api.shop.local',
      path: '/graphql',
      url: 'https://api.shop.local/graphql',
      status: 200,
      length: 2460,
      mime: 'application/json',
      risk: 'high',
      timing: 205,
      source: 'scanner',
      time: '14:05:27',
      requestRaw: [
        'POST /graphql HTTP/2',
        'Host: api.shop.local',
        'Content-Type: application/json',
        'Authorization: Bearer customer-token',
        'X-ProxyForge-Active-Scan: graphql-introspection',
        '',
        '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } } }"}',
      ].join('\n'),
      responseRaw: [
        'HTTP/2 200 OK',
        'Content-Type: application/json',
        '',
        '{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"},"types":[{"name":"RefundMutation"}]}}}',
      ].join('\n'),
      notes: 'GraphQL introspection exchange provides a scanner-generated check result.',
      tags: ['graphql', 'active-scan', 'scanner'],
    },
  ];

  const insertionPoints = [
    {
      id: 'ip-refund-body-amount',
      exchangeId: 'hx-scan-refund-denied',
      name: 'Refund amount JSON body',
      route: 'POST /api/refunds',
      location: 'json-body',
      parameter: 'amount',
      originalValue: 7900,
      coverage: ['authz-diff', 'business-logic', 'replay-derived'],
      risk: 'high',
      notes: 'Exercise amount tampering while preserving idempotency and authorization state.',
    },
    {
      id: 'ip-refund-auth-header',
      exchangeId: 'hx-scan-refund-denied',
      name: 'Refund Authorization header',
      route: 'POST /api/refunds',
      location: 'header',
      parameter: 'Authorization',
      originalValue: 'Bearer customer-token',
      coverage: ['authenticated-state-comparison', 'header-swap'],
      risk: 'high',
      notes: 'Compare customer and support state without leaking raw tokens into reports.',
    },
    {
      id: 'ip-graphql-query',
      exchangeId: 'hx-scan-graphql-introspection',
      name: 'GraphQL operation body',
      route: 'POST /graphql',
      location: 'json-body',
      parameter: 'query',
      originalValue: 'IntrospectionQuery',
      coverage: ['graphql-introspection', 'schema-discovery'],
      risk: 'medium',
      notes: 'Verify introspection is represented as Scanner insertion point coverage.',
    },
  ];

  const checkPacks = [
    {
      id: 'check-pack-authz-replay',
      name: 'Active scan authorization replay check-pack',
      checks: ['authz-diff', 'method-options', 'idempotency-key-replay'],
      routes: ['/api/refunds'],
      insertionPointIds: ['ip-refund-body-amount', 'ip-refund-auth-header'],
      source: 'replay-derived',
      headless: true,
    },
    {
      id: 'check-pack-graphql',
      name: 'GraphQL schema exposure check-pack',
      checks: ['graphql-introspection', 'graphql-mutation-probe'],
      routes: ['/graphql'],
      insertionPointIds: ['ip-graphql-query'],
      source: 'scanner',
      headless: true,
    },
  ];

  return {
    projectName: 'Scanner active scan parity',
    scopeAllowlist: ['*.shop.local'],
    exchanges,
    history: exchanges,
    selectedExchangeId: 'hx-scan-refund-denied',
    checks: [
      'security-headers',
      'cors-origin',
      'cache-key',
      'method-options',
      'authz-diff',
      'jwt-claims',
      'graphql-introspection',
      'oast-ssrf',
      'reflected-xss',
      'sql-injection',
      'path-traversal',
      'open-redirect',
      'command-injection',
    ],
    insertionPoints,
    checkPacks,
    activeScanPolicy: {
      id: 'scanner-policy-active-parity',
      name: 'Report-ready active scan parity',
      mode: 'active-scan',
      throttleMs: 0,
      maxRequests: 24,
      checks: ['authz-diff', 'graphql-introspection', 'method-options', 'idempotency-key-replay'],
      preserveEvidence: true,
      headlessCi: true,
    },
    activeScanSummary: {
      id: 'active-scan-summary-authz-graphql',
      targetUrl: 'https://app.shop.local/api/refunds',
      startedAt: '2026-05-24T17:08:00.000Z',
      completedAt: now,
      totalRequests: 12,
      blocked: false,
      message: 'Active scanner completed authz replay and GraphQL introspection checks with report-ready evidence.',
      findings: [
        {
          id: 'finding-scanner-authz-refund',
          checkId: 'authz-diff',
          title: 'Refund authorization boundary differs by authenticated state',
          severity: 'high',
          confidence: 'firm',
          host: 'app.shop.local',
          path: '/api/refunds',
          detail: 'Customer refund request is denied while support-state replay with the same body is approved.',
          remediation: 'Enforce refund authorization server-side for every authenticated state and idempotency-key replay path.',
          evidenceExchangeId: 'hx-scan-refund-replay-allowed',
          dedupeKey: 'authz-diff:app.shop.local:/api/refunds',
          confidenceReason: 'Same method, path, idempotency key class, and body moved from 403 to 200 across authenticated states.',
        },
        {
          id: 'finding-scanner-graphql-introspection',
          checkId: 'graphql-introspection',
          title: 'GraphQL introspection data exposed to authenticated users',
          severity: 'medium',
          confidence: 'firm',
          host: 'api.shop.local',
          path: '/graphql',
          detail: 'Scanner replay preserved __schema query output for authenticated users.',
          remediation: 'Disable GraphQL introspection outside approved development and support roles.',
          evidenceExchangeId: 'hx-scan-graphql-introspection',
          dedupeKey: 'graphql-introspection:api.shop.local:/graphql',
          confidenceReason: 'The response includes queryType, mutationType, and schema type names.',
        },
      ],
      suppressedFindings: [
        {
          id: 'suppressed-security-header-refund',
          checkId: 'security-headers',
          title: 'Missing hardening header on JSON API response',
          host: 'app.shop.local',
          path: '/api/refunds',
          evidenceExchangeId: 'hx-scan-refund-denied',
          dedupeKey: 'security-headers:app.shop.local:/api/refunds',
          reason: 'Suppressed as noisy JSON API hardening signal while authz replay evidence is higher value.',
        },
      ],
      tuning: {
        profile: 'browser-app-calibration',
        falsePositiveControls: ['error-page-security-header-suppression', 'authz-state-pairing'],
        suppressedFindingCount: 1,
        dedupedFindingCount: 2,
        findingDedupeKeys: [
          'authz-diff:app.shop.local:/api/refunds',
          'graphql-introspection:api.shop.local:/graphql',
        ],
        calibrationNotes: ['Report package must preserve raw executor traffic until export redaction.'],
      },
      exchanges,
    },
    authenticatedStates: [
      {
        id: 'state-customer',
        label: 'Customer baseline',
        role: 'customer',
        exchangeIds: ['hx-scan-profile-baseline', 'hx-scan-refund-denied'],
        statusByRoute: {
          '/api/account/profile': 200,
          '/api/refunds': 403,
        },
      },
      {
        id: 'state-support',
        label: 'Support alternate',
        role: 'support_admin',
        exchangeIds: ['hx-scan-refund-replay-allowed'],
        statusByRoute: {
          '/api/refunds': 200,
        },
      },
    ],
    replayEvidence: [
      {
        id: 'replay-refund-authz-diff',
        sourceExchangeId: 'hx-scan-refund-denied',
        replayExchangeId: 'hx-scan-refund-replay-allowed',
        route: 'POST /api/refunds',
        baselineStatus: 403,
        alternateStatus: 200,
        derivedChecks: ['authz-diff', 'idempotency-key-replay'],
        findingTitle: 'Refund authorization boundary differs by authenticated state',
        confidenceReason: 'Same route and body changed from 403 customer baseline to 200 support replay.',
      },
      {
        id: 'replay-graphql-introspection',
        sourceExchangeId: 'hx-scan-graphql-introspection',
        replayExchangeId: 'hx-scan-graphql-introspection',
        route: 'POST /graphql',
        baselineStatus: 200,
        alternateStatus: 200,
        derivedChecks: ['graphql-introspection'],
        findingTitle: 'GraphQL introspection data exposed to authenticated users',
        confidenceReason: 'Scanner replay preserved __schema queryType and mutationType output.',
      },
    ],
    ciHandoff: {
      id: 'ci-scanner-active-parity',
      mode: 'headless',
      command: 'npm test -- tests/scanner-active-scan-engine.mjs',
      artifacts: ['scanner-active-scan-plan.json', 'scanner-active-scan-evidence.md'],
      gates: ['report-ready-evidence', 'check-pack-coverage', 'authenticated-state-comparison'],
    },
    issueDraft: {
      id: 'issue-scanner-active-scan-authz',
      title: 'Refund active scan replay confirms authorization boundary difference',
      severity: 'high',
      host: 'app.shop.local',
      path: '/api/refunds',
      detail: 'Scanner active scan combines insertion point coverage, authenticated-state comparison, replay-derived checks, and report-ready evidence.',
      remediation: 'Require server-side refund authorization for every authenticated state and replay path.',
      triageNote: 'Evidence package should be ready for Reports and CI/headless handoff.',
    },
    now,
  };
}

function buildSampleScannerOastIssuePromotionRequest(sampleRequest) {
  const sourceExchange = sampleRequest.exchanges[0];
  const scannerExchange = {
    ...sourceExchange,
    id: 'hx-scan-oast-probe',
    source: 'scanner',
    tags: ['scanner', 'check:oast-ssrf', 'oast'],
    requestRaw: [
      'GET /api/fetch?url=https://callbacks.shop.local/probe/pf-oast-secret-token HTTP/1.1',
      'Host: app.shop.local',
      'Authorization: Bearer scanner-oast-agent-token',
      'Cookie: session=scanner-oast-session',
      '',
      '',
    ].join('\n'),
    responseRaw: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"callbackStatus":204,"token":"pf-oast-secret-token"}',
  };
  return {
    projectName: 'Scanner active scan parity',
    sourceExchange,
    scannerExchange,
    payload: {
      id: 'cb-oast-active-scan',
      token: 'pf-oast-secret-token',
      label: 'Scanner OAST SSRF payload',
      protocol: 'http',
      endpoint: 'https://callbacks.shop.local/probe/pf-oast-secret-token',
      createdAt: sampleRequest.now,
      status: 'observed',
      sourceExchangeId: sourceExchange.id,
      sourceHost: sourceExchange.host,
      sourcePath: sourceExchange.path,
      notes: 'Synthetic active-scan OAST payload for issue promotion parity.',
    },
    interaction: {
      id: 'int-oast-active-scan',
      payloadId: 'cb-oast-active-scan',
      protocol: 'http',
      observedAt: sampleRequest.now,
      sourceIp: '127.0.0.1',
      sourceHost: 'callbacks.shop.local',
      requestLine: 'GET /probe/pf-oast-secret-token HTTP/1.1',
      userAgent: 'ProxyForge OAST',
      raw: 'GET /probe/pf-oast-secret-token HTTP/1.1\nAuthorization: Bearer scanner-oast-agent-token\nCookie: session=scanner-oast-session\n\n',
      severity: 'high',
      tags: ['oast', 'scanner', 'ssrf'],
    },
    finding: {
      id: 'finding-oast-active-scan',
      checkId: 'oast-ssrf',
      title: 'Out-of-band callback was triggered',
      severity: 'high',
      confidence: 'certain',
      host: sourceExchange.host,
      path: sourceExchange.path,
      detail: 'Scanner injected an OAST callback URL and observed the callback token in the listener.',
      remediation: 'Restrict server-side fetches and retest with a fresh OAST payload.',
      evidenceExchangeId: scannerExchange.id,
      dedupeKey: 'oast-ssrf:app.shop.local:/api/refunds:pf-oast-secret-token',
      confidenceReason: 'Listener observed the same token generated by the scanner probe.',
    },
    activeScanSummary: {
      id: 'active-scan-summary-oast',
      targetUrl: scannerExchange.url,
      totalRequests: 1,
      message: 'OAST SSRF callback observed.',
    },
    scopeAllowlist: ['app.shop.local'],
    generatedAt: sampleRequest.now,
  };
}

function assertActiveScanPlan(result, helperName) {
  const serialized = stringify(result);
  assert.match(serialized, /active[- ]scan|Scanner/i, `${helperName} should expose Scanner active scan context`);
  assert.match(serialized, /check[- ]?pack|authz-diff|graphql-introspection|method-options/i, `${helperName} should include active scan check-pack coverage`);
  assert.match(serialized, /\/api\/refunds|\/graphql|GraphQL/i, `${helperName} should keep representative active scan routes`);
  assert.match(serialized, /insertion point|insertionPoint|parameter|Authorization|amount/i, `${helperName} should preserve insertion point planning`);
}

function assertInsertionPointReview(result, helperName) {
  const serialized = stringify(result);
  assert.match(serialized, /insertion point|insertionPoint|coverage/i, `${helperName} should expose insertion point coverage`);
  assert.match(serialized, /Refund amount JSON body|Refund Authorization header|GraphQL operation body/i, `${helperName} should include representative insertion point details`);
  assert.match(serialized, /\/api\/refunds|GraphQL|Authorization|json-body/i, `${helperName} should preserve routes and parameter locations`);
}

function assertAuthenticatedStateMatrix(result, helperName) {
  const serialized = stringify(result);
  assert.match(serialized, /authenticated[- ]state|Customer baseline|Support alternate|support_admin/i, `${helperName} should compare authenticated states`);
  assert.match(serialized, /403|200|\/api\/refunds|authorization boundary|authz/i, `${helperName} should preserve baseline and alternate state outcomes`);
}

function assertPackageArtifact(result, helperName, kindPattern, contentPattern) {
  const serialized = stringify(result);
  assert.match(serialized, /kind/i, `${helperName} should expose a package kind`);
  assert.match(serialized, kindPattern, `${helperName} should expose the expected package kind`);
  assert.match(serialized, /content|artifact|markdown|json/i, `${helperName} should expose package content or artifacts`);
  assert.match(serialized, contentPattern, `${helperName} should preserve representative package content`);
}

function assertCiHandoff(result, helperName) {
  const serialized = stringify(result);
  assert.match(serialized, /CI|headless|handoff|pipeline|artifact/i, `${helperName} should expose CI/headless handoff context`);
  assert.match(serialized, /active[- ]scan|scanner-active-scan|report[- ]ready|check[- ]?pack/i, `${helperName} should preserve Scanner active scan report gates`);
  assert.match(serialized, /\/api\/refunds|GraphQL|authenticated[- ]state/i, `${helperName} should keep representative routes or state comparison in handoff`);
}

function assertReportReadyLanguage(result, helperName) {
  assert.match(
    stringify(result),
    /report[- ]ready|Reports handoff|ready for report|issue/i,
    `${helperName} should include report-ready language`,
  );
}

function assertScannerActiveScanEvidenceRequirements(result, helperName) {
  assert.equal(result.kind, 'proxyforge-scanner-active-scan-evidence-package', `${helperName} should expose the Scanner active scan package kind`);
  assert.equal(result.secretHandling, 'execution-full-fidelity-secrets-preserved', `${helperName} should preserve executor secrets until reporting`);
  assert.equal(result.reportRedactionBoundary, 'redact-only-during-report-export', `${helperName} should defer redaction until report export`);
  assert.equal(result.requirements.activeScanPlanLinked, true, `${helperName} should link the active scan plan`);
  assert.equal(result.requirements.insertionPointReviewLinked, true, `${helperName} should link insertion point review`);
  assert.equal(result.requirements.authenticatedStateMatrixLinked, true, `${helperName} should link authenticated-state matrix evidence`);
  assert.equal(result.requirements.replayChecksLinked, true, `${helperName} should link replay-derived scanner checks`);
  assert.equal(result.requirements.ciHeadlessHandoffCovered, true, `${helperName} should preserve CI/headless report handoff`);
  assert.equal(result.requirements.reportAttachmentsLinked, true, `${helperName} should link report attachments`);
  assert.equal(result.requirements.issueConfidencePreserved, true, `${helperName} should preserve issue confidence evidence`);
  assert.equal(result.requirements.rawExchangeSamplesPreserved, true, `${helperName} should preserve raw request/response samples`);
  assert.equal(result.requirements.operationalSecretsPreserved, true, `${helperName} should preserve operational secrets`);
  assert.equal(result.requirements.reportPhaseOnlyRedaction, true, `${helperName} should record report-phase-only redaction`);
  assert(result.operationalSecretSignals.includes('authorization-header'), `${helperName} should detect authorization headers`);
  assert(result.operationalSecretSignals.includes('idempotency-key-header'), `${helperName} should detect idempotency keys`);
  assert.equal(result.findingStatusSummary.total, 2, `${helperName} should preserve active finding counts`);
  assert.equal(result.findingStatusSummary.suppressedFindingCount, 1, `${helperName} should preserve suppressed finding counts`);
  assert(result.reportAttachments.length >= 5, `${helperName} should attach plan/review/matrix/replay/summary artifacts`);
  assert.match(
    stringify(result),
    /Bearer customer-token|Bearer support-token|Idempotency-Key|reportPhaseOnlyRedaction|active-scan-summary-authz-graphql/i,
    `${helperName} should keep full-fidelity executor material and redaction boundary in package content`,
  );
}

function assertScannerLiveTargetProfilePackage(result, helperName) {
  const serialized = stringify(result);
  const failedRequirements = Object.entries(result.requirements).filter(([, value]) => !value).map(([name]) => name);
  assert.equal(result.kind, 'proxyforge-scanner-live-target-profile-package', `${helperName} should expose Scanner live-target profile package kind`);
  assert.equal(result.reportReady, true, `${helperName} should mark passing Scanner profiles report-ready`);
  assert.deepEqual(failedRequirements, [], `${helperName} should satisfy every Scanner production profile requirement`);
  assert.ok(result.targetHostCount >= 2, `${helperName} should prove multiple target hosts`);
  assert.ok(result.routeCount >= 3, `${helperName} should prove route diversity`);
  assert.ok(result.statusClasses.includes('2xx') && result.statusClasses.includes('4xx'), `${helperName} should prove status diversity`);
  assert.ok(result.totalRequests >= 10, `${helperName} should preserve long-running scan request counts`);
  assert.ok(result.checkCoverage.length >= 8, `${helperName} should preserve broad Scanner check-pack depth`);
  assert.ok(result.falsePositiveControls.some((control) => /suppression|authz|confidence/i.test(control)), `${helperName} should preserve false-positive tuning controls`);
  assert.equal(result.requirements.passiveDedupeCovered, true, `${helperName} should link passive dedupe packages`);
  assert.equal(result.requirements.insertionInventoryCovered, true, `${helperName} should link insertion inventory packages`);
  assert.ok(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-scanner-passive-dedupe-parity-package'), `${helperName} should link passive Scanner dedupe packages`);
  assert.ok(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-insertion-point-inventory-package'), `${helperName} should link insertion inventory packages`);
  assert.ok(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-scanner-active-scan-evidence-package'), `${helperName} should link active scan evidence packages`);
  assert.ok(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-anvil-custom-check-parity-package'), `${helperName} should link Anvil compatibility packages`);
  assert.ok(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-scanner-oast-issue-promotion-package'), `${helperName} should link Scanner OAST promotion packages`);
  assert.ok(result.packageRefreshProof.linkedPackageKinds.includes('proxyforge-scanner-retest-evidence-delta-package'), `${helperName} should link Scanner retest packages`);
  assert.equal(result.packageRefreshProof.stalePackageIds.length, 0, `${helperName} should not carry stale Scanner packages`);
  assert.match(serialized, /Authorization: Bearer customer-token|anvil-headless-token|scanner-oast-agent-token|session=scanner-oast-session/, `${helperName} should preserve executor tokens before report export`);
  assert.match(serialized, /redact-only-during-report-export|execution-full-fidelity-secrets-preserved/, `${helperName} should preserve the report-phase redaction boundary`);
}

function buildSyntheticScannerPassiveDedupePackage(now) {
  return {
    id: 'scanner-passive-dedupe-profile',
    kind: 'proxyforge-scanner-passive-dedupe-parity-package',
    reportReady: true,
    status: 'pass',
    requirements: {
      passiveChecksCovered: true,
      dedupeCovered: true,
      routeVariantDedupeCovered: true,
      confidenceSummaryCovered: true,
      severityNormalizationCovered: true,
      falsePositiveTuningCovered: true,
      activeScannerHandoffCovered: true,
      rawRequestResponsePreserved: true,
      operationalSecretsPreserved: true,
      reportPhaseOnlyRedaction: true,
    },
    content: JSON.stringify({
      kind: 'proxyforge-scanner-passive-dedupe-parity-package',
      exportedAt: now,
      checkCoverage: ['security-headers', 'cookie-flags', 'cors-policy', 'cache-control', 'mixed-content', 'information-disclosure', 'authz-metadata', 'server-error'],
      dedupeClusters: [{ key: 'GET app.shop.local /account/:id', exactDuplicateCount: 1, routeVariantCount: 2 }],
      confidenceSummary: { certain: 1, firm: 4, tentative: 1 },
      falsePositiveControls: ['dedupe-key-required-before-report', 'suppression-review-preserved'],
      activeScannerHandoff: 'scanner-run --checks security-headers,cors-origin,authz-diff',
      rawExchangeSamples: [{
        requestRaw: 'GET /account/101 HTTP/2\nAuthorization: Bearer customer-token\nCookie: session=scanner-passive-session\n\n',
        responseRaw: 'HTTP/2 200 OK\nSet-Cookie: session=scanner-passive-session\n\n{"role":"customer"}',
      }],
      requirements: {
        passiveChecksCovered: true,
        routeVariantDedupeCovered: true,
        confidenceSummaryCovered: true,
        falsePositiveTuningCovered: true,
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    }, null, 2),
  };
}

function buildSyntheticInsertionInventoryPackage(now) {
  return {
    id: 'scanner-insertion-inventory-profile',
    kind: 'proxyforge-insertion-point-inventory-package',
    reportReady: true,
    status: 'pass',
    requirements: {
      queryParametersCovered: true,
      pathParametersCovered: true,
      headerParametersCovered: true,
      cookieParametersCovered: true,
      formParametersCovered: true,
      jsonParametersCovered: true,
      xmlParametersCovered: true,
      multipartParametersCovered: true,
      graphqlParametersCovered: true,
      scannerReadyCorpus: true,
      rawExecutorMaterialPreserved: true,
      operationalSecretsPreserved: true,
      reportPhaseOnlyRedaction: true,
    },
    content: JSON.stringify({
      kind: 'proxyforge-insertion-point-inventory-package',
      createdAt: now,
      coverage: [
        { type: 'query', count: 1 },
        { type: 'path', count: 1 },
        { type: 'header', count: 1 },
        { type: 'cookie', count: 1 },
        { type: 'form', count: 1 },
        { type: 'json', count: 1 },
        { type: 'xml', count: 1 },
        { type: 'multipart', count: 1 },
        { type: 'graphql', count: 1 },
      ],
      points: [{ type: 'graphql', name: 'variables.orderId', evidence: 'GraphQL variable promoted into Scanner insertion corpus.' }],
      rawExchanges: [{
        requestRaw: 'POST /graphql?debug=true HTTP/2\nAuthorization: Bearer customer-token\nCookie: session=scanner-insertion-session\nContent-Type: application/json\n\n{"variables":{"orderId":"ord_100"}}',
        responseRaw: 'HTTP/2 200 OK\n\n{"ok":true}',
      }],
      requirements: {
        queryParametersCovered: true,
        headerParametersCovered: true,
        graphqlParametersCovered: true,
        scannerReadyCorpus: true,
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    }, null, 2),
  };
}

function buildSyntheticAnvilCompatibilityPackage(now) {
  return {
    id: 'anvil-profile-authz-depth',
    kind: 'proxyforge-anvil-custom-check-parity-package',
    reportReady: true,
    status: 'pass',
    requirements: {
      plainTextDefinitionPreserved: true,
      reusableLibraryCovered: true,
      positiveNegativeFixturesCovered: true,
      fixtureValidationPassed: true,
      headlessCustomOnlyCovered: true,
      signedPackageReviewCovered: true,
      scannerIssueHandoffCovered: true,
      reportsHandoffCovered: true,
      rawExecutorMaterialPreserved: true,
      operationalSecretsPreserved: true,
      reportPhaseOnlyRedaction: true,
    },
    content: JSON.stringify({
      kind: 'proxyforge-anvil-custom-check-parity-package',
      generatedAt: now,
      definition: {
        source: 'metadata:\n  language: v2-beta\ngiven response then\n  if {latest.response.body} matches "support_admin" then\n    report issue:',
      },
      fixtureCoverage: {
        positiveFixtureCount: 1,
        negativeFixtureCount: 1,
      },
      headless: {
        status: 'complete',
        builtInChecksDisabled: true,
        extensionChecksDisabled: true,
        requestRaw: 'GET /api/refunds HTTP/2\nAuthorization: Bearer anvil-headless-token\nCookie: session=anvil-headless-session\n\n',
      },
      packageReview: {
        signature: { status: 'verified' },
      },
      requirements: {
        plainTextDefinitionPreserved: true,
        positiveNegativeFixturesCovered: true,
        headlessCustomOnlyCovered: true,
        signedPackageReviewCovered: true,
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    }, null, 2),
  };
}

function buildSyntheticScannerRetestPackage(now) {
  return {
    id: 'scanner-retest-delta-authz-profile',
    kind: 'proxyforge-scanner-retest-evidence-delta-package',
    reportReady: true,
    status: 'pass',
    requirements: {
      baselineProofLinked: true,
      retestProofLinked: true,
      outcomeHistoryCovered: true,
      reportPhaseOnlyRedaction: true,
    },
    content: JSON.stringify({
      kind: 'proxyforge-scanner-retest-evidence-delta-package',
      createdAt: now,
      outcome: 'still-vulnerable',
      baselineExchange: {
        requestRaw: 'POST /api/refunds HTTP/2\nAuthorization: Bearer customer-token\n\n{"amount":7900}',
        responseRaw: 'HTTP/2 403 Forbidden\n\n{"error":"missing_permission"}',
      },
      retestExchange: {
        requestRaw: 'POST /api/refunds HTTP/2\nAuthorization: Bearer support-token\n\n{"amount":7900}',
        responseRaw: 'HTTP/2 200 OK\n\n{"status":"approved"}',
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    }, null, 2),
  };
}

function buildSyntheticScannerCalibrationPackage(summary, now) {
  return {
    id: 'agent-scanner-calibration-profile',
    kind: 'proxyforge-agent-scanner-live-calibration-soak-package',
    reportReady: true,
    status: 'pass',
    requirements: {
      requestFloorCovered: true,
      falsePositiveTuningCovered: true,
      reportPhaseOnlyRedaction: true,
    },
    content: JSON.stringify({
      kind: 'proxyforge-agent-scanner-live-calibration-soak-package',
      generatedAt: now,
      observed: {
        targetUrl: summary.targetUrl,
        totalRequests: summary.totalRequests,
        findingCount: summary.findings.length,
        suppressedFindingCount: summary.suppressedFindings.length,
      },
      scannerTuning: [summary.tuning],
      falsePositiveControls: summary.tuning.falsePositiveControls,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    }, null, 2),
  };
}

function assertScannerOastIssuePromotionPackage(result, helperName) {
  assert.equal(result.kind, 'proxyforge-scanner-oast-issue-promotion-package', `${helperName} should expose the Scanner OAST promotion package kind`);
  assert.equal(result.secretHandling, 'execution-full-fidelity-secrets-preserved', `${helperName} should preserve executor secrets until reporting`);
  assert.equal(result.reportRedactionBoundary, 'redact-only-during-report-export', `${helperName} should defer redaction until report export`);
  assert.equal(result.requirements.sourceExchangeLinked, true, `${helperName} should link the source exchange`);
  assert.equal(result.requirements.scannerExchangeLinked, true, `${helperName} should link the scanner probe exchange`);
  assert.equal(result.requirements.callbackPayloadLinked, true, `${helperName} should link callback payload ownership`);
  assert.equal(result.requirements.callbackInteractionLinked, true, `${helperName} should link callback interaction evidence`);
  assert.equal(result.requirements.activeFindingLinked, true, `${helperName} should link active scanner finding confidence`);
  assert.equal(result.requirements.oastTokenObserved, true, `${helperName} should prove the OAST token was observed`);
  assert.equal(result.requirements.rawScannerRequestPreserved, true, `${helperName} should keep the raw scanner request`);
  assert.equal(result.requirements.rawScannerResponsePreserved, true, `${helperName} should keep the raw scanner response`);
  assert.equal(result.requirements.rawCallbackInteractionPreserved, true, `${helperName} should keep the raw callback interaction`);
  assert.equal(result.requirements.reportPhaseOnlyRedaction, true, `${helperName} should keep report-phase-only redaction`);
  assert(result.reportAttachments.length >= 5, `${helperName} should attach source/scanner/payload/interaction/issue artifacts`);
  assert.match(
    stringify(result),
    /scanner-oast-agent-token|scanner-oast-session|pf-oast-secret-token|scanner-oast-promote|report-export-only/i,
    `${helperName} should preserve full-fidelity OAST issue promotion context and agent command handoff`,
  );
}

function stringify(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
