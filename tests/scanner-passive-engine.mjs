import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = ['buildPassiveIssueCandidates', 'buildScannerPassiveParityEvidencePackage'];
const enginePath = path.resolve('src/scannerPassiveEngine.ts');
const scannerPassiveEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof scannerPassiveEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `scanner-passive-engine: missing export(s): ${missingExports.join(', ')}`);

const exchanges = buildSampleExchanges();
const candidates = scannerPassiveEngine.buildPassiveIssueCandidates(exchanges);
assert(candidates.length >= 16, 'sample exchanges should generate broad passive Scanner candidate coverage');

const suppressCandidate = candidates.find((candidate) => candidate.title === 'Technology version header exposed') ?? candidates.at(-1);
const reportCandidates = candidates.slice(0, 4);
const sample = {
  exchanges,
  candidates,
  issueRules: buildIssueRules(),
  suppressions: [
    {
      id: 'scanner-passive-suppression-x-powered-by',
      reason: 'Technology disclosure remains supporting intel until version-specific exploitability is proved.',
      match: 'Technology version header exposed',
      affectedCandidateIds: suppressCandidate ? [suppressCandidate.id] : [],
      createdAt: '2026-05-25T21:20:00.000Z',
    },
  ],
  reportAttachments: reportCandidates.map((candidate, index) => ({
    id: `scanner-passive-attachment-${index + 1}`,
    issueCandidateId: candidate.id,
    exchangeId: candidate.exchangeId,
    fileName: `scanner-passive-${candidate.checkId}-${index + 1}.json`,
    description: `Full-fidelity passive Scanner evidence for ${candidate.title}.`,
    redactionControl: 'report-export-only',
  })),
  operationalSecretSamples: [
    'scanner-secret-token',
    'scanner-session',
    'scanner-api-key',
    'AKIA-SCANNER-KEY',
  ],
  exportedAt: '2026-05-25T21:20:00.000Z',
};

const parityPackage = scannerPassiveEngine.buildScannerPassiveParityEvidencePackage(sample);
const parityContent = JSON.parse(parityPackage.content);

assert.equal(parityPackage.kind, 'proxyforge-scanner-passive-dedupe-parity-package');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.reportReady, true);
assert(Object.values(parityPackage.requirements).every(Boolean), 'all Scanner passive/dedupe parity requirements should be true');
assert.equal(parityPackage.exchangeCount, exchanges.length);
assert(parityPackage.candidateCount >= 16, 'parity package should retain generated candidates');
assert(parityPackage.findingCount > 0, 'parity package should retain representative findings');
assert(parityPackage.duplicateCandidateCount > 0, 'parity package should account for duplicate passive signals');
assert(parityPackage.dedupeClusters.some((cluster) => cluster.exactDuplicateCount > 0), 'dedupe clusters should include exact duplicates');
assert(parityPackage.dedupeClusters.some((cluster) => cluster.routeVariantCount > 0), 'dedupe clusters should include route variants');
assert.equal(
  JSON.stringify(parityPackage.checkCoverage.map((row) => row.id)),
  JSON.stringify(['security-headers', 'cookie-flags', 'cors-policy', 'cache-control', 'mixed-content', 'information-disclosure', 'authz-metadata', 'server-error']),
);
assert(parityPackage.confidenceSummary.certain > 0, 'certain confidence findings should be summarized');
assert(parityPackage.confidenceSummary.firm > 0, 'firm confidence findings should be summarized');
assert(parityPackage.confidenceSummary.tentative > 0, 'tentative confidence findings should be summarized');
assert(parityPackage.severityReviews.some((review) => review.originalSeverity !== review.normalizedSeverity), 'severity normalization should change some findings');
assert(parityPackage.severityReviews.some((review) => review.originalSeverity === review.normalizedSeverity), 'severity normalization should preserve some findings');
assert.equal(parityContent.kind, 'proxyforge-scanner-passive-dedupe-parity-package');
assert.match(parityPackage.content, /Authorization: Bearer scanner-secret-token/);
assert.match(parityPackage.content, /session=scanner-session/);
assert.match(parityPackage.content, /X-API-Key: scanner-api-key/);
assert.match(parityPackage.content, /AKIA-SCANNER-KEY/);
assert.match(parityPackage.content, /scanner-run --checks security-headers|scanner-run --checks cors-origin|scanner-run --checks authz-diff/);
assert.match(parityPackage.content, /dedupe-key-required-before-report|suppression-review-preserved/);
assert.match(parityPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/scanner-passive-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'scanner-passive-dedupe-parity-package.json'), parityPackage.content);

console.log('scanner-passive-engine: exercised passive checks, dedupe clusters, route variants, confidence/severity policy, suppressions, report attachments, and full-fidelity raw exchanges');

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

function buildSampleExchanges() {
  return [
    makeHtmlAccountExchange('hx-passive-account-101', '/account/101', 101),
    makeHtmlAccountExchange('hx-passive-account-101-duplicate', '/account/101', 101),
    makeHtmlAccountExchange('hx-passive-account-102', '/account/102', 102),
    {
      id: 'hx-passive-error-500',
      method: 'GET',
      host: 'app.shop.local',
      path: '/api/debug/500',
      url: 'https://app.shop.local/api/debug/500',
      status: 500,
      length: 890,
      mime: 'text/plain',
      risk: 'high',
      timing: 131,
      source: 'proxy',
      time: '16:15:06',
      notes: 'Noisy error page with real diagnostic material for passive Scanner false-positive control.',
      tags: ['scanner', 'passive', 'error'],
      requestRaw: [
        'GET /api/debug/500 HTTP/1.1',
        'Host: app.shop.local',
        'Authorization: Bearer scanner-secret-token',
        'Cookie: session=scanner-session; csrf=scanner-csrf',
        'X-API-Key: scanner-api-key',
        '',
        '',
      ].join('\n'),
      responseRaw: [
        'HTTP/1.1 500 Internal Server Error',
        'Content-Type: text/plain',
        '',
        'Exception: refund workflow failed',
        'Stack trace: RefundController.handle line 77',
        'AWS_SECRET_ACCESS_KEY=AKIA-SCANNER-KEY',
      ].join('\n'),
    },
  ];
}

function makeHtmlAccountExchange(id, requestPath, accountId) {
  return {
    id,
    method: 'GET',
    host: 'app.shop.local',
    path: requestPath,
    url: `https://app.shop.local${requestPath}?api_key=scanner-api-key`,
    status: 200,
    length: 2400 + accountId,
    mime: 'text/html',
    risk: 'medium',
    timing: 84,
    source: 'proxy',
    time: '16:14:11',
    notes: 'Authenticated account page used for passive Scanner dedupe and route-variant review.',
    tags: ['scanner', 'passive', 'authz'],
    requestRaw: [
      `GET ${requestPath}?api_key=scanner-api-key HTTP/1.1`,
      'Host: app.shop.local',
      'Origin: https://evil.example',
      'Authorization: Bearer scanner-secret-token',
      'Cookie: session=scanner-session; csrf=scanner-csrf',
      'X-API-Key: scanner-api-key',
      '',
      '',
    ].join('\n'),
    responseRaw: [
      'HTTP/1.1 200 OK',
      'Content-Type: text/html; charset=utf-8',
      'Access-Control-Allow-Origin: https://evil.example',
      'Access-Control-Allow-Credentials: true',
      'Set-Cookie: session=scanner-session; Path=/',
      'X-Powered-By: Express 4.18.2',
      '',
      '<html>',
      `<body data-account="${accountId}">`,
      '<script src="http://cdn.shop.local/app.js"></script>',
      '<div data-featureflags="support_admin,internal/export">Privileged workflow metadata</div>',
      '{"email":"analyst@example.local","role":"admin","permission":"refund:approve","token":"scanner-secret-token"}',
      '</body>',
      '</html>',
    ].join('\n'),
  };
}

function buildIssueRules() {
  const createdAt = '2026-05-25T21:20:00.000Z';
  return [
    {
      id: 'scanner-passive-rule-raise-low',
      name: 'Raise low confidence browser checks',
      createdAt,
      checkId: 'all',
      severity: 'medium',
      confidence: 'firm',
      action: 'raise',
      status: 'active',
      summary: 'Raise weak passive browser findings to medium while they await review.',
    },
    {
      id: 'scanner-passive-rule-lower-info',
      name: 'Lower informational disclosures',
      createdAt,
      checkId: 'all',
      severity: 'low',
      confidence: 'tentative',
      action: 'lower',
      status: 'active',
      summary: 'Lower supporting intel when no exploit path is proved.',
    },
    {
      id: 'scanner-passive-rule-suppress-noise',
      name: 'Suppress tuned noisy pages',
      createdAt,
      checkId: 'all',
      severity: 'info',
      confidence: 'tentative',
      action: 'suppress',
      status: 'active',
      summary: 'Suppress known noisy error-page patterns after manual review.',
    },
    {
      id: 'scanner-passive-rule-review-authz',
      name: 'Require review for authorization metadata',
      createdAt,
      checkId: 'all',
      severity: 'medium',
      confidence: 'firm',
      action: 'require-review',
      status: 'active',
      summary: 'Require review for authorization metadata before report export.',
    },
  ];
}
