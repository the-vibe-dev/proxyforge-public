import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildFullNightlyRetainedHistoryDashboard',
  'buildFullNightlyRetainedHistoryEvidencePackage',
  'buildFullNightlyHostedRetainedHistoryEvidencePackage',
  'normalizeRetainedSummary',
];
const enginePath = path.resolve('src/fullNightlyHistoryEngine.ts');
const historyEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof historyEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `full-nightly-history-engine: missing export(s): ${missingExports.join(', ')}`);

const context = buildRetainedHistoryContext();
const dashboard = historyEngine.buildFullNightlyRetainedHistoryDashboard(
  context.retainedSummaries,
  context.historyArtifactPath,
  context.generatedAt,
);
const productionPackage = historyEngine.buildFullNightlyRetainedHistoryEvidencePackage(context);
const hostedPackage = historyEngine.buildFullNightlyHostedRetainedHistoryEvidencePackage({
  plan: context.plan,
  retainedSummaries: context.retainedSummaries,
  hostedRuns: context.hostedRuns,
  workflowName: 'ProxyForge Nightly Full Suite',
  branch: 'main',
  historyArtifactPath: context.historyArtifactPath,
  retentionDays: context.retentionDays,
  generatedAt: context.generatedAt,
  operationalSecretSamples: context.operationalSecretSamples,
});
const packageContent = JSON.parse(productionPackage.content);
const hostedPackageContent = JSON.parse(hostedPackage.content);

assert.equal(dashboard.kind, 'proxyforge-full-nightly-retained-history-dashboard');
assert.equal(dashboard.retainedRunCount, 3);
assert.equal(dashboard.runtimeRunCount, 3);
assert.equal(dashboard.fullRunCount, 2);
assert.equal(dashboard.skipBrowserRunCount, 1);
assert.equal(dashboard.planOnlyRunCount, 0);
assert.equal(dashboard.failedRunCount, 0);
assert.equal(dashboard.consecutiveRuntimePasses, 3);
assert.equal(dashboard.latestRuntimeRun.runId, 'run-003');
assert.equal(dashboard.latestRuntimeRun.summaryDigest, context.retainedSummaries[2].summaryDigest);
assert.equal(productionPackage.kind, 'proxyforge-full-nightly-retained-history-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, true);
assert(Object.values(productionPackage.requirements).every(Boolean), 'all retained full/nightly history requirements should be true');
assert.equal(packageContent.kind, 'proxyforge-full-nightly-retained-history-evidence-package');
assert.match(productionPackage.content, /proxyforge-full-nightly-retained-history-dashboard/);
assert.match(productionPackage.content, /test-results\/ci-full-suite-history\/dashboard\.json/);
assert.match(productionPackage.content, /test-results\/ci-full-suite-history\/run-003-summary\.json/);
assert.match(productionPackage.content, /Full\/Nightly retained history engine/);
assert.match(productionPackage.content, /Full\/Nightly production evidence engine/);
assert.match(productionPackage.content, /Customer-scale interop profiling engine/);
assert.match(productionPackage.content, /Extension third-party compatibility engine/);
assert.match(productionPackage.content, /Proxy HTTP listener capture engine/);
assert.match(productionPackage.content, /Repeater workspace parity engine/);
assert.match(productionPackage.content, /Intruder engine/);
assert.match(productionPackage.content, /Full browser workflow suite/);
assert.match(productionPackage.content, /Authorization: Bearer retained-history-secret-token/);
assert.match(productionPackage.content, /session=retained-history-session/);
assert.match(productionPackage.content, /X-API-Key: retained-history-api-key/);
assert.match(productionPackage.content, /callbackToken=retained-history-callback-token/);
assert.match(productionPackage.content, /redact-only-during-report-export/);
assert.equal(packageContent.notes.runtimeOnlyHistory, 'Plan-only summaries are kept as metadata artifacts but are not counted as retained runtime history.');
assert.equal(hostedPackage.kind, 'proxyforge-full-nightly-hosted-retained-history-evidence-package');
assert.equal(hostedPackage.productionReady, true);
assert.equal(hostedPackage.hostedRunCount, 3);
assert.equal(hostedPackage.scheduledRunCount, 2);
assert(Object.values(hostedPackage.requirements).every(Boolean), 'all hosted retained full/nightly history requirements should be true');
assert.equal(hostedPackageContent.notes.scheduledBoundary, 'Manual workflow_dispatch runs are useful warmups, but Production Ready for this gate requires scheduled run receipts linked to retained history.');
assert.match(hostedPackage.content, /"eventName": "schedule"/);
assert.match(hostedPackage.content, /"eventName": "workflow_dispatch"/);
assert.match(hostedPackage.content, /proxyforge-full-suite-run-003/);
assert.match(hostedPackage.content, /ci-full-suite-history\/dashboard\.json/);
assert.match(hostedPackage.content, /Authorization: Bearer retained-history-secret-token/);
assert.match(hostedPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/full-nightly-history-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'full-nightly-retained-history-evidence-package.json'), productionPackage.content);
await fs.writeFile(path.join(artifactDir, 'full-nightly-hosted-retained-history-evidence-package.json'), hostedPackage.content);

console.log('full-nightly-history-engine: verified retained runtime summaries, hosted scheduled receipts, dashboard history, digest integrity, and full-fidelity secret boundary');

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

function buildRetainedHistoryContext() {
  const generatedAt = '2026-05-26T14:30:00.000Z';
  const rawRequest = [
    'POST /api/full-nightly-history HTTP/2',
    'Host: app.shop.local',
    'Authorization: Bearer retained-history-secret-token',
    'Cookie: session=retained-history-session',
    'X-API-Key: retained-history-api-key',
    '',
    '{"rawRequest":true,"callbackToken":"retained-history-callback-token"}',
  ].join('\n');
  const rawResponse = [
    'HTTP/2 200 OK',
    'Content-Type: application/json',
    '',
    '{"ok":true,"rawResponse":"retained-history"}',
  ].join('\n');
  const stepNames = [
    ['Build renderer and Electron runtime', 'build', 'release/platform'],
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
    ['Project import compatibility engine', 'engine', 'project/import-compatibility'],
    ['Customer-scale interop profiling engine', 'engine', 'project/customer-scale-interop'],
    ['Extension third-party compatibility engine', 'engine', 'extensions/third-party-compatibility'],
    ['Project parity evidence engine', 'engine', 'project/persistence'],
    ['Automation installed-host service smoke', 'runtime', 'automation/service-smoke'],
    ['Proxy HTTP listener capture engine', 'engine', 'proxy-core'],
    ['Scanner passive dedupe engine', 'engine', 'scanner/evidence'],
    ['Active scanner engine', 'engine', 'scanner/runtime'],
    ['Repeater workspace parity engine', 'engine', 'repeater/workspace'],
    ['Intruder engine', 'engine', 'intruder/runtime'],
    ['Callback listener backend engine', 'engine', 'collaborator/runtime'],
    ['Exploit backend execution engine', 'engine', 'exploit/runtime'],
    ['Report export engine', 'engine', 'reports/runtime'],
    ['Agentic control CLI smoke', 'runtime', 'ai/agentic-control'],
    ['Full browser workflow suite', 'e2e', 'frontend/workflows'],
  ];
  while (stepNames.length < 80) {
    stepNames.push([`Retained history coverage step ${stepNames.length + 1}`, 'engine', 'release/ci-full-nightly']);
  }
  const uploadPolicy = {
    summary: 'Upload test-results/ci-full-suite-summary.json, retained history summaries, Playwright artifacts, and generated report/headless artifacts from nightly runs.',
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
      ? ['test-results/ci-full-suite-summary.json', 'test-results/ci-full-suite-history/dashboard.json', 'test-results/playwright-artifacts/', 'playwright-report/']
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
  const summaries = [
    summary('run-001', 'full', coverageOwnership, plan.stepCount, 1290000, '2026-05-24T08:17:00.000Z'),
    summary('run-002', 'skip-browser', coverageOwnership.slice(0, -1), plan.stepCount - 1, 860000, '2026-05-25T08:17:00.000Z'),
    summary('run-003', 'full', coverageOwnership, plan.stepCount, 1320000, '2026-05-26T08:17:00.000Z'),
  ];
  const hostedRuns = summaries.map(({ runId, fullSummary }, index) => ({
    runId,
    source: 'github-actions',
    eventName: index === 1 ? 'workflow_dispatch' : 'schedule',
    workflowName: 'ProxyForge Nightly Full Suite',
    branch: 'main',
    headSha: [
      '1111111111111111111111111111111111111111',
      '2222222222222222222222222222222222222222',
      '3333333333333333333333333333333333333333',
    ][index],
    status: 'completed',
    conclusion: 'success',
    url: `https://github.com/the-vibe-dev/proxyforge/actions/runs/${runId}`,
    startedAt: fullSummary.startedAt,
    completedAt: fullSummary.completedAt,
    attempt: 1,
    artifactNames: [
      `proxyforge-full-suite-${runId}`,
      'test-results/ci-full-suite-summary.json',
      'test-results/ci-full-suite-history/dashboard.json',
    ],
    retainedHistoryRestored: true,
    retainedHistorySaved: true,
    suiteSummaryUploaded: true,
    historyDashboardUploaded: true,
    rawRunMetadata: [
      `proxyforge-full-suite-${runId}`,
      'actions/cache/restore@v4 restored test-results/ci-full-suite-history/',
      'actions/cache/save@v4 saved test-results/ci-full-suite-history/',
      'Upload full-suite artifacts included test-results/ci-full-suite-summary.json',
      'Upload full-suite artifacts included test-results/ci-full-suite-history/dashboard.json',
      rawRequest,
      rawResponse,
      'redact-only-during-report-export',
    ].join('\n'),
  }));
  return {
    plan,
    retainedSummaries: summaries.map(({ runId, fullSummary }) => ({
      runId,
      source: 'github-actions',
      artifactPath: `test-results/ci-full-suite-history/${runId}-summary.json`,
      recordedAt: fullSummary.completedAt,
      summaryDigest: simpleDigest(JSON.stringify(fullSummary)),
      summary: fullSummary,
      flakeViolations: 0,
    })),
    hostedRuns,
    currentSummary: summaries[2].fullSummary,
    historyArtifactPath: 'test-results/ci-full-suite-history/dashboard.json',
    retentionDays: 30,
    generatedAt,
    operationalSecretSamples: [
      'Authorization: Bearer retained-history-secret-token',
      'session=retained-history-session',
      'X-API-Key: retained-history-api-key',
      'callbackToken=retained-history-callback-token',
      'redact-only-during-report-export',
    ],
  };

  function summary(runId, mode, ownership, totalSteps, durationMs, startedAt) {
    const completedAt = new Date(Date.parse(startedAt) + durationMs).toISOString();
    const results = ownership.map((owner, index) => ({
      name: owner.name,
      kind: owner.kind,
      owner: owner.owner,
      command: `node tests/${owner.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.mjs`,
      status: 'passed',
      exitCode: 0,
      retryBudget: owner.retryBudget,
      artifactPaths: owner.artifactPaths,
      startedAt,
      completedAt,
      durationMs: 100 + index,
      stdoutTail: `${owner.name} passed\n${rawRequest}\n${rawResponse}`,
      stderrTail: '',
    }));
    return {
      runId,
      fullSummary: {
        kind: 'proxyforge-ci-full-suite-summary',
        mode,
        startedAt,
        completedAt,
        durationMs,
        passed: true,
        totalSteps,
        completedSteps: totalSteps,
        uploadPolicy,
        flakeBudget,
        coverageOwnership: ownership,
        results,
      },
    };
  }
}

function simpleDigest(value) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
