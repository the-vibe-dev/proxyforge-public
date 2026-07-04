import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildFullNightlyProductionEvidencePackage',
  'buildFullNightlyTrendDashboard',
];
const enginePath = path.resolve('src/fullNightlyProductionEngine.ts');
const fullNightlyEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof fullNightlyEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `full-nightly-production-engine: missing export(s): ${missingExports.join(', ')}`);

const context = buildFullNightlyProductionContext();
const trendDashboard = fullNightlyEngine.buildFullNightlyTrendDashboard(context.trendRuns, context.generatedAt);
const productionPackage = fullNightlyEngine.buildFullNightlyProductionEvidencePackage(context);
const packageContent = JSON.parse(productionPackage.content);

assert.equal(trendDashboard.kind, 'proxyforge-full-nightly-trend-dashboard');
assert.equal(trendDashboard.runCount, 3);
assert.equal(trendDashboard.failedRunCount, 0);
assert.equal(trendDashboard.modeCounts.full, 2);
assert.equal(trendDashboard.modeCounts['skip-browser'], 1);
assert.equal(trendDashboard.zeroFlakeViolations, 0);
assert.equal(productionPackage.kind, 'proxyforge-full-nightly-production-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, true);
assert(Object.values(productionPackage.requirements).every(Boolean), 'all Full/Nightly production requirements should be true');
assert.equal(packageContent.kind, 'proxyforge-full-nightly-production-evidence-package');
assert.match(productionPackage.content, /proxyforge-full-nightly-trend-dashboard/);
assert.match(productionPackage.content, /test-results\/ci-full-suite-summary\.json/);
assert.match(productionPackage.content, /test-results\/ci-full-suite-history\/run-003-summary\.json/);
assert.match(productionPackage.content, /actions\/cache\/restore@v4/);
assert.match(productionPackage.content, /actions\/cache\/save@v4/);
assert.match(productionPackage.content, /proxyforge-full-suite-history-\$\{\{ github\.ref_name \}\}-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/);
assert.equal(packageContent.requirements.scheduledHistoryContinuityCovered, true);
assert.match(productionPackage.content, /Full\/Nightly production evidence engine/);
assert.match(productionPackage.content, /Platform Shell production evidence engine/);
assert.match(productionPackage.content, /UI Scale production evidence engine/);
assert.match(productionPackage.content, /Agent Control production evidence engine/);
assert.match(productionPackage.content, /AI Provider production evidence engine/);
assert.match(productionPackage.content, /Release Security production evidence engine/);
assert.match(productionPackage.content, /Release Trust production evidence engine/);
assert.match(productionPackage.content, /Fast regression production evidence engine/);
assert.match(productionPackage.content, /Full\/Nightly retained history engine/);
assert.match(productionPackage.content, /Project import compatibility engine/);
assert.match(productionPackage.content, /Customer-scale interop profiling engine/);
assert.match(productionPackage.content, /Extension third-party compatibility engine/);
assert.match(productionPackage.content, /Automation installed-host service smoke/);
assert.match(productionPackage.content, /Full browser workflow suite/);
assert.match(productionPackage.content, /Authorization: Bearer full-nightly-secret-token/);
assert.match(productionPackage.content, /session=full-nightly-session/);
assert.match(productionPackage.content, /X-API-Key: full-nightly-api-key/);
assert.match(productionPackage.content, /callbackToken=full-nightly-callback-token/);
assert.match(productionPackage.content, /redact-only-during-report-export/);
assert.equal(packageContent.notes.planOnlyBoundary, 'A plan-only summary validates metadata but does not claim runtime completion.');

const artifactDir = path.resolve('.gitignored/test-artifacts/full-nightly-production-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'full-nightly-production-evidence-package.json'), productionPackage.content);

console.log('full-nightly-production-engine: verified nightly plan coverage, trend dashboard, retained runtime history, and full-fidelity secret boundary');

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

function buildFullNightlyProductionContext() {
  const generatedAt = '2026-05-26T04:15:00.000Z';
  const rawRequest = [
    'POST /api/full-nightly HTTP/2',
    'Host: app.shop.local',
    'Authorization: Bearer full-nightly-secret-token',
    'Cookie: session=full-nightly-session',
    'X-API-Key: full-nightly-api-key',
    '',
    '{"rawRequest":true,"callbackToken":"full-nightly-callback-token"}',
  ].join('\n');
  const rawResponse = [
    'HTTP/2 200 OK',
    'Content-Type: application/json',
    '',
    '{"ok":true,"rawResponse":"full-nightly"}',
  ].join('\n');
  const stepNames = [
    ['Build renderer and Electron runtime', 'build', 'release/platform'],
    ['Live vulnerable fixture app', 'runtime', 'fixtures/live-target'],
    ['Release readiness verifier', 'release', 'release/platform'],
    ['Release smoke runner plan', 'release', 'release/platform'],
    ['CI nightly policy gate', 'release', 'release/ci-policy'],
    ['Release runtime workflow smoke', 'release', 'release/runtime'],
    ['Platform Release parity evidence engine', 'release', 'release/platform'],
    ['UI Scale production evidence engine', 'release', 'release/ui-scale'],
    ['Platform Shell production evidence engine', 'release', 'release/platform-shell'],
    ['Agent Control production evidence engine', 'runtime', 'ai/agentic-control'],
    ['AI Provider production evidence engine', 'engine', 'ai/provider-production'],
    ['Release Security production evidence engine', 'release', 'release/security-production'],
    ['Release Trust production evidence engine', 'release', 'release/trust-production'],
    ['Fast regression production evidence engine', 'release', 'release/ci-fast'],
    ['Full/Nightly production evidence engine', 'release', 'release/ci-full-nightly'],
    ['Full/Nightly retained history engine', 'release', 'release/ci-full-nightly'],
    ['Install docs production evidence engine', 'release', 'release/docs'],
    ['Windows package production evidence engine', 'release', 'release/windows-package'],
    ['Linux package production evidence engine', 'release', 'release/linux-package'],
    ['Enterprise policy transport engine', 'engine', 'enterprise/governance'],
    ['Safety and enterprise parity evidence engine', 'engine', 'enterprise/safety'],
    ['Project parity evidence engine', 'engine', 'project/persistence'],
    ['Project import compatibility engine', 'engine', 'project/import-compatibility'],
    ['Customer-scale interop profiling engine', 'engine', 'project/customer-scale-interop'],
    ['Extension third-party compatibility engine', 'engine', 'extensions/third-party-compatibility'],
    ['Project Store v2 persistence engine', 'engine', 'project/store-v2'],
    ['Project Store settings workflow engine', 'engine', 'project/settings'],
    ['Project Store cookie jar workflow engine', 'engine', 'project/cookie-jar'],
    ['Proxy Project Store workflow engine', 'engine', 'project/proxy-store-workflow'],
    ['Project Store OAST workflow engine', 'engine', 'project/oast-store-workflow'],
    ['Project Store signed OAST evidence engine', 'engine', 'project/oast-signed-evidence'],
    ['Scanner OAST SSRF workflow engine', 'engine', 'scanner/oast-correlation'],
    ['Agent option audit gate', 'runtime', 'ai/agentic-control'],
    ['Certificate manager engine', 'engine', 'proxy-platform'],
    ['Browser launcher and cookie extraction engine', 'engine', 'platform/session'],
    ['Session profile live refresh engine', 'engine', 'target/session'],
    ['Shared session cookie jar engine', 'engine', 'session/cookie-jar'],
    ['Session macro token refresh engine', 'engine', 'session/macro-refresh'],
    ['Session replay runtime engine', 'engine', 'session/runtime'],
    ['Proxy HTTP listener capture engine', 'engine', 'proxy-core'],
    ['CONNECT tunnel metadata engine', 'engine', 'proxy-core'],
    ['HTTPS MITM engine', 'engine', 'proxy-core'],
    ['Proxy intercept engine', 'engine', 'proxy-core'],
    ['Proxy history analysis engine', 'engine', 'proxy-history'],
    ['Crawler engine', 'engine', 'target/crawler'],
    ['Crawl insertion audit engine', 'engine', 'target/scanner'],
    ['Target map engine', 'engine', 'target/map'],
    ['Scanner passive dedupe engine', 'engine', 'scanner/evidence'],
    ['Active scanner engine', 'engine', 'scanner/runtime'],
    ['Scanner live calibration engine', 'engine', 'scanner/runtime'],
    ['Scanner active evidence engine', 'engine', 'scanner/evidence'],
    ['Scanner retest evidence delta engine', 'engine', 'scanner/evidence'],
    ['Anvil custom scan-check engine', 'engine', 'scanner/evidence'],
    ['Repeater transport engine', 'engine', 'repeater/runtime'],
    ['Repeater workspace parity engine', 'engine', 'repeater/workspace'],
    ['Repeater OAST workflow engine', 'engine', 'repeater/oast-workflow'],
    ['Repeater desync race socket engine', 'engine', 'repeater/desync-race'],
    ['Intruder engine', 'engine', 'intruder/runtime'],
    ['Intruder OAST row correlation engine', 'engine', 'intruder/oast-correlation'],
    ['Sequencer large-sample reliability engine', 'engine', 'sequencer/runtime'],
    ['Decoder token workflow engine', 'engine', 'decoder/runtime'],
    ['Comparer engine', 'engine', 'comparer/runtime'],
    ['Analysis tool refresh evidence engine', 'engine', 'analysis/package-refresh'],
    ['Report export engine', 'engine', 'reports/runtime'],
    ['Report PDF visual QA smoke', 'engine', 'reports/runtime'],
    ['Release security review engine', 'release', 'release/security'],
    ['Headless CLI runtime smoke', 'runtime', 'automation/ci'],
    ['Agentic control CLI smoke', 'runtime', 'ai/agentic-control'],
    ['Logger custom column engine', 'engine', 'logger/runtime'],
    ['Logger parity evidence engine', 'engine', 'logger/evidence'],
    ['Organizer parity evidence engine', 'engine', 'organizer/evidence'],
    ['Search semantic ranking engine', 'engine', 'search/runtime'],
    ['Viewer parity engine', 'engine', 'viewer/runtime'],
    ['Automation scheduler engine', 'engine', 'automation/runtime'],
    ['Automation installed-host service smoke', 'runtime', 'automation/service-smoke'],
    ['Sandboxed extension runtime engine', 'engine', 'extensions/runtime'],
    ['Callback listener backend engine', 'engine', 'collaborator/runtime'],
    ['Callback live backend engine', 'engine', 'collaborator/evidence'],
    ['Exploit backend execution engine', 'engine', 'exploit/runtime'],
    ['WebSocket engine', 'engine', 'proxy/websocket'],
    ['AI provider engine', 'engine', 'ai/runtime'],
    ['AI controlled action execution engine', 'engine', 'ai/actions'],
    ['Full browser workflow suite', 'e2e', 'frontend/workflows'],
  ];
  const uploadPolicy = {
    summary: 'Upload test-results/ci-full-suite-summary.json, Playwright artifacts, trend history, and generated report/headless artifacts from nightly runs.',
    artifactDirectory: 'test-results',
    requiredArtifacts: [
      'test-results/ci-full-suite-summary.json',
      'test-results/ci-full-suite-plan.json',
      'test-results/.last-run.json',
      'test-results/ci-full-suite-history/',
      'test-results/ci-full-suite-history/dashboard.json',
      'test-results/playwright-artifacts/',
      'playwright-report/',
    ],
    retentionDays: 14,
    failureRetentionDays: 30,
  };
  const flakeBudget = {
    maxFlakySteps: 0,
    maxRetriesPerStep: 1,
    browserRetryBudget: 1,
    ownerRequired: true,
  };
  const coverageOwnership = stepNames.map(([name, kind, owner], index) => ({
    name,
    kind,
    owner,
    artifactPaths: index % 5 === 0
      ? ['test-results/ci-full-suite-summary.json', 'test-results/playwright-artifacts/', 'playwright-report/']
      : ['test-results/ci-full-suite-summary.json'],
    retryBudget: name === 'Full browser workflow suite' ? 1 : 0,
  }));
  const plan = {
    kind: 'proxyforge-ci-full-suite-plan',
    suite: 'full-nightly',
    generatedAt,
    stepCount: coverageOwnership.length,
    uploadPolicy,
    flakeBudget,
    coverageOwnership,
  };
  const currentSummary = {
    kind: 'proxyforge-ci-full-suite-summary',
    mode: 'plan-only',
    passed: true,
    startedAt: generatedAt,
    completedAt: generatedAt,
    durationMs: 122,
    totalSteps: plan.stepCount,
    completedSteps: 0,
    uploadPolicy,
    flakeBudget,
    coverageOwnership,
    results: [],
  };
  const trendRuns = [
    trendRun('run-001', 'full', plan.stepCount, 1290000, '2026-05-24T08:17:00.000Z'),
    trendRun('run-002', 'skip-browser', plan.stepCount - 1, 860000, '2026-05-25T08:17:00.000Z'),
    trendRun('run-003', 'full', plan.stepCount, 1320000, '2026-05-26T08:17:00.000Z'),
  ];
  const fastNames = [
    'Build renderer and Electron runtime',
    'Release readiness verifier',
    'Release Security production evidence engine',
    'Release Trust production evidence engine',
    'Fast regression production evidence engine',
    'Full/Nightly production evidence engine',
    'Full/Nightly retained history engine',
    'UI Scale production evidence engine',
    'Project import compatibility engine',
    'Customer-scale interop profiling engine',
    'Extension third-party compatibility engine',
    'Automation installed-host service smoke',
    'Focused browser workflow smoke',
  ];
  while (fastNames.length < 82) fastNames.push(`Fast regression coverage step ${fastNames.length + 1}`);
  const fastSummary = {
    kind: 'proxyforge-ci-fast-suite-summary',
    passed: true,
    totalSteps: fastNames.length,
    completedSteps: fastNames.length,
    durationMs: 184000,
    results: fastNames.map((name, index) => ({
      name,
      kind: index === 0 ? 'build' : index < 5 ? 'release' : 'engine',
      status: 'passed',
      exitCode: 0,
      command: `node tests/${name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.mjs`,
      stdoutTail: `${name} passed\n${rawRequest}\n${rawResponse}`,
      stderrTail: '',
    })),
  };
  return {
    plan,
    currentSummary,
    trendRuns,
    fastSummary,
    docs: [
      'OPERATOR_GUIDE requires proxyforge-full-nightly-production-evidence-package with trend dashboard and report-export-only redaction.',
      'OPERATOR_GUIDE documents retained full/nightly history, zero-flake policy, and full-fidelity executor material.',
      'SCHEMAS.md documents proxyforge-full-nightly-production-evidence-package requirements.',
      'Operational submission/report artifacts redact only at redact-only-during-report-export.',
    ],
    workflowText: [
      'uses: actions/cache/restore@v4',
      'with:',
      '  path: test-results/ci-full-suite-history/',
      '  key: proxyforge-full-suite-history-${{ github.ref_name }}-${{ github.run_id }}-${{ github.run_attempt }}',
      '  restore-keys: |',
      '    proxyforge-full-suite-history-${{ github.ref_name }}-',
      'run: npm run test:ci:full',
      'if: always() && github.event.inputs.plan_only != \'true\'',
      'uses: actions/cache/save@v4',
      'with:',
      '  path: test-results/ci-full-suite-history/',
      '  key: proxyforge-full-suite-history-${{ github.ref_name }}-${{ github.run_id }}-${{ github.run_attempt }}',
    ].join('\n'),
    artifactPath: 'test-results/ci-full-suite-summary.json',
    historyArtifactPath: 'test-results/ci-full-suite-history/dashboard.json',
    retentionDays: 30,
    generatedAt,
    operationalSecretSamples: [
      'Authorization: Bearer full-nightly-secret-token',
      'session=full-nightly-session',
      'X-API-Key: full-nightly-api-key',
      'callbackToken=full-nightly-callback-token',
    ],
  };

  function trendRun(runId, mode, completedSteps, durationMs, startedAt) {
    return {
      runId,
      source: 'github-actions',
      mode,
      startedAt,
      completedAt: new Date(Date.parse(startedAt) + durationMs).toISOString(),
      passed: true,
      totalSteps: completedSteps,
      completedSteps,
      durationMs,
      artifactPath: `test-results/ci-full-suite-history/${runId}-summary.json`,
      failedStepNames: [],
      flakeViolations: 0,
    };
  }
}
