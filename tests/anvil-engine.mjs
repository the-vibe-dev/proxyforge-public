import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const anvilEngine = await loadEngine(path.resolve('src/anvilEngine.ts'));
const anvilCompatibility = await loadEngine(path.resolve('src/anvilCompatibility.ts'));

assert.equal(typeof anvilEngine.buildAnvilParityEvidencePackage, 'function');
assert.equal(typeof anvilCompatibility.evaluateAnvilSource, 'function');

const compatibilitySource = [
  'metadata:',
  '  language: v2-beta',
  '  name: "Compatibility operator coverage"',
  'define:',
  '  role_marker = "support_admin"',
  'given response then',
  '  if {latest.response.status_code} == 200 then',
  '  if {latest.response.body} matches "${role_marker}" then',
  '  if not {latest.response.headers} contains "content-security-policy" then',
  '    report issue:',
  '      name: "Role marker without CSP"',
].join('\n');
const compatibilityMatch = anvilCompatibility.evaluateAnvilSource(compatibilitySource, {
  requestRaw: 'GET /api/profile HTTP/2\nHost: app.shop.local\nAuthorization: Bearer anvil-fixture-token\n\n',
  responseRaw: 'HTTP/2 200 OK\nContent-Type: application/json\n\n{"role":"support_admin"}',
});
assert.equal(compatibilityMatch.matched, true);
assert.equal(compatibilityMatch.conditionCount, 3);
assert.equal(JSON.stringify(compatibilityMatch.operators), JSON.stringify(['==', 'matches', 'not contains']));
assert(compatibilityMatch.fields.includes('response.status_code'));
const compatibilityMiss = anvilCompatibility.evaluateAnvilSource(compatibilitySource, {
  requestRaw: 'GET /api/profile HTTP/2\nHost: app.shop.local\n\n',
  responseRaw: 'HTTP/2 200 OK\nContent-Type: application/json\nContent-Security-Policy: default-src self\n\n{"role":"customer"}',
});
assert.equal(compatibilityMiss.matched, false);

const generatedAt = '2026-05-25T17:15:00.000Z';
const definition = {
  id: 'anvil-privileged-workflow-metadata',
  name: 'Privileged workflow metadata exposure',
  language: 'v2-beta',
  createdAt: generatedAt,
  updatedAt: generatedAt,
  author: 'ProxyForge',
  description: 'Flags support_admin and internal export markers in responses.',
  tags: ['proxyforge', 'anvil', 'authz'],
  phase: 'passive',
  runScope: 'per-request',
  enabled: true,
  severity: 'medium',
  confidence: 'firm',
  libraryId: 'anvil-library-authz',
  fixtureIds: ['fixture-positive', 'fixture-negative'],
  lastValidationRunId: 'anvil-validation-authz',
  headlessRunIds: ['anvil-headless-authz'],
  packageReviewId: 'anvil-package-authz',
  reportReady: true,
  summary: 'Privileged metadata Anvil is validated, packaged, and ready for Scanner handoff.',
  source: [
    'metadata:',
    '  language: v2-beta',
    '  name: "Privileged workflow metadata exposure"',
    '  author: "ProxyForge"',
    '  tags: "proxyforge", "anvil", "authz"',
    '',
    'given response then',
    '  if {latest.response.body} matches "support_admin|internal/export" then',
    '    report issue:',
    '      name: "Privileged workflow metadata exposed"',
    '      severity: medium',
    '      confidence: firm',
    '  end if',
  ].join('\n'),
};
const library = {
  id: 'anvil-library-authz',
  name: 'Authorization workflow Anvil library',
  description: 'Reusable Anvil library for authorization workflow metadata.',
  createdAt: generatedAt,
  updatedAt: generatedAt,
  ruleIds: [definition.id],
  tags: ['anvil', 'authz'],
  trust: 'signed',
  summary: 'Signed reusable custom scan-check library.',
  content: JSON.stringify({
    kind: 'proxyforge-anvil-rule-library',
    checks: [{ id: definition.id, source: definition.source }],
    Authorization: 'Bearer anvil-library-token',
  }, null, 2),
};
const fixtures = [
  {
    id: 'fixture-positive',
    checkId: definition.id,
    name: 'Positive support workflow fixture',
    createdAt: generatedAt,
    enabled: true,
    requestRaw: [
      'GET /api/refunds HTTP/2',
      'Host: app.shop.local',
      'Authorization: Bearer anvil-fixture-token',
      'Cookie: session=anvil-fixture-session',
      'X-API-Key: anvil-fixture-key',
      '',
      '',
    ].join('\n'),
    responseRaw: 'HTTP/2 200 OK\nContent-Type: application/json\n\n{"role":"support_admin","path":"internal/export"}',
    expected: 'match',
    status: 'passed',
    summary: 'Positive fixture matched privileged workflow metadata.',
    evidence: '{"matched":"support_admin","secret":"anvil-fixture-secret"}',
  },
  {
    id: 'fixture-negative',
    checkId: definition.id,
    name: 'Negative customer workflow fixture',
    createdAt: generatedAt,
    enabled: true,
    requestRaw: [
      'GET /api/refunds HTTP/2',
      'Host: app.shop.local',
      'Authorization: Bearer anvil-negative-token',
      'Cookie: session=anvil-negative-session',
      '',
      '',
    ].join('\n'),
    responseRaw: 'HTTP/2 200 OK\nContent-Type: application/json\n\n{"role":"customer","path":"orders"}',
    expected: 'no-match',
    status: 'passed',
    summary: 'Negative fixture did not match privileged workflow metadata.',
    evidence: '{"matched":false}',
  },
];
const validationRun = {
  id: 'anvil-validation-authz',
  checkId: definition.id,
  checkName: definition.name,
  createdAt: generatedAt,
  status: 'passed',
  fixtureCount: 2,
  passedCount: 2,
  failedCount: 0,
  requestCount: 2,
  issueCount: 1,
  errorCount: 0,
  auditItemCount: 2,
  loggerCount: 3,
  reportReady: true,
  summary: 'Anvil fixture validation passed with positive and negative coverage.',
  fixtureResults: [
    { fixtureId: 'fixture-positive', name: 'Positive support workflow fixture', expected: 'match', matched: true, status: 'passed', evidence: 'Matched expected issue.' },
    { fixtureId: 'fixture-negative', name: 'Negative customer workflow fixture', expected: 'no-match', matched: false, status: 'passed', evidence: 'No issue raised.' },
  ],
  content: '{"kind":"proxyforge-anvil-validation","auditItems":2,"loggerEntries":3}',
};
const headlessRun = {
  id: 'anvil-headless-authz',
  checkId: definition.id,
  checkName: definition.name,
  createdAt: generatedAt,
  targetUrl: 'https://app.shop.local/api/refunds',
  status: 'complete',
  requestCount: 2,
  issueCount: 1,
  auditItemCount: 2,
  loggerCount: 3,
  builtInChecksDisabled: true,
  extensionChecksDisabled: true,
  issueIds: ['anvil-issue-authz'],
  exchangeIds: ['hx-anvil-headless'],
  reportReady: true,
  summary: 'Headless custom-only Anvil run completed with built-in and extension checks disabled.',
  content: '{"kind":"proxyforge-anvil-headless-run","customOnlyScan":true,"builtInChecksDisabled":true,"extensionChecksDisabled":true}',
};
const packageReview = {
  id: 'anvil-package-authz',
  checkId: definition.id,
  libraryId: library.id,
  title: 'Authorization Anvil signed package review',
  fileName: 'proxyforge-anvil-package-authz.json',
  path: 'scanner/proxyforge-anvil-package-authz.json',
  reviewedAt: generatedAt,
  status: 'trusted',
  packageDigest: 'anvildigest0001',
  signature: {
    algorithm: 'HMAC-SHA256',
    signerName: 'ProxyForge custom checks',
    keyId: 'anvil-local',
    status: 'verified',
    digestPreview: 'anvildigest0001',
  },
  reusableRuleCount: 1,
  fixtureCount: 2,
  findingCount: 1,
  summary: 'Signed package review trusted the reusable Anvil library.',
  content: '{"kind":"proxyforge-anvil-package-review","signature":{"status":"verified"}}',
};
const promotedIssue = {
  id: 'anvil-promoted-authz',
  title: 'Anvil: Privileged workflow metadata exposed',
  severity: 'medium',
  host: 'app.shop.local',
  path: '/api/refunds',
  confidence: 'firm',
  status: 'open',
  detail: 'Custom Anvil matched support_admin workflow metadata in a client response.',
  remediation: 'Avoid returning privileged workflow metadata to clients.',
};
const exchanges = [
  {
    id: 'hx-anvil-headless',
    method: 'GET',
    host: 'app.shop.local',
    path: '/api/refunds',
    url: 'https://app.shop.local/api/refunds',
    status: 200,
    length: 92,
    mime: 'application/json',
    risk: 'medium',
    timing: 88,
    source: 'scanner',
    time: '17:15:00',
    requestRaw: [
      'GET /api/refunds HTTP/2',
      'Host: app.shop.local',
      'Authorization: Bearer anvil-headless-token',
      'Cookie: session=anvil-headless-session',
      'Idempotency-Key: anvil-headless-idempotency',
      '',
      '',
    ].join('\n'),
    responseRaw: 'HTTP/2 200 OK\nContent-Type: application/json\n\n{"role":"support_admin","path":"internal/export"}',
    tags: ['scanner', 'anvil', 'headless'],
    notes: 'Headless Anvil exchange preserves raw executor material.',
  },
];

const packageResult = anvilEngine.buildAnvilParityEvidencePackage({
  definition,
  library,
  fixtures,
  validationRun,
  headlessRun,
  packageReview,
  promotedIssue,
  exchanges,
  generatedAt,
});

assert.equal(packageResult.kind, 'proxyforge-anvil-custom-check-parity-package');
assert.equal(packageResult.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(packageResult.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(packageResult.requirements.plainTextDefinitionPreserved, true);
assert.equal(packageResult.requirements.reusableLibraryCovered, true);
assert.equal(packageResult.requirements.positiveNegativeFixturesCovered, true);
assert.equal(packageResult.requirements.fixtureValidationPassed, true);
assert.equal(packageResult.requirements.headlessCustomOnlyCovered, true);
assert.equal(packageResult.requirements.signedPackageReviewCovered, true);
assert.equal(packageResult.requirements.scannerIssueHandoffCovered, true);
assert.equal(packageResult.requirements.reportsHandoffCovered, true);
assert.equal(packageResult.requirements.rawExecutorMaterialPreserved, true);
assert.equal(packageResult.requirements.operationalSecretsPreserved, true);
assert.equal(packageResult.requirements.reportPhaseOnlyRedaction, true);
assert.equal(packageResult.fixtureCoverage.fixtureCount, 2);
assert.equal(packageResult.fixtureCoverage.positiveFixtureCount, 1);
assert.equal(packageResult.fixtureCoverage.negativeFixtureCount, 1);
assert.equal(packageResult.headless.builtInChecksDisabled, true);
assert.equal(packageResult.headless.extensionChecksDisabled, true);
assert.equal(packageResult.packageReview.signature.status, 'verified');
assert(packageResult.operationalSecretSignals.includes('authorization-header'));
assert(packageResult.operationalSecretSignals.includes('cookie-header'));
assert(packageResult.operationalSecretSignals.includes('x-api-key-header'));
assert(packageResult.operationalSecretSignals.includes('idempotency-key-header'));
assert.match(
  packageResult.content,
  /Bearer anvil-fixture-token|session=anvil-fixture-session|anvil-headless-token|anvil-fixture-key|reportPhaseOnlyRedaction|support_admin/i,
);

const artifactDir = path.resolve('.gitignored/test-artifacts/anvil-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(
  path.join(artifactDir, 'anvil-custom-check-parity-package.json'),
  JSON.stringify(packageResult, null, 2),
  'utf8',
);

console.log('anvil-engine: built Anvil custom scan-check parity package with fixture, headless, package-review, Scanner, and Reports handoff evidence');

async function loadEngine(resolvedPath) {
  const source = await fs.readFile(resolvedPath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: resolvedPath,
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
  vm.runInNewContext(transpiled, sandbox, { filename: resolvedPath });
  return module.exports;
}
