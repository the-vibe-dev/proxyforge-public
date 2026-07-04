// run-all: skip  (CI orchestrator — runs full pipeline; use --plan-only flag to validate plan only)
import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import fs from 'node:fs/promises';
import path from 'node:path';

const startedAt = new Date();
const npmBin = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const npxBin = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const planOnly = process.argv.includes('--plan-only');
const skipBrowser = process.argv.includes('--skip-browser');
const resultsDir = path.resolve('test-results');

const uploadPolicy = {
  summary: 'Upload test-results/ci-full-suite-summary.json, retained runtime history, Playwright artifacts, and any generated report/headless artifacts from nightly runs.',
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

const steps = [
  step('Build renderer and Electron runtime', npmBin, ['run', 'build'], 'build', 'release/platform', ['dist/', 'dist-electron/']),
  step('Live vulnerable fixture app', process.execPath, ['tests/vulnerable-fixture-app.mjs'], 'runtime', 'fixtures/live-target', ['tests/fixtures/vulnerable-app/server.mjs']),
  step('Release readiness verifier', process.execPath, ['tests/release-readiness.mjs'], 'release', 'release/platform', ['test-results/ci-full-suite-summary.json']),
  step('Release smoke runner plan', process.execPath, ['tests/release-smoke-runner.mjs'], 'release', 'release/platform', ['test-results/release-smoke-plan-test.json']),
  step('CI nightly policy gate', process.execPath, ['tests/ci-nightly-policy.mjs'], 'release', 'release/ci-policy', ['.github/workflows/nightly-full-suite.yml']),
  step('Release runtime workflow smoke', process.execPath, ['tests/release-runtime-workflow.mjs'], 'release', 'release/runtime', ['dist-electron/releaseWorkflowSmoke.js']),
  step('Platform Release parity evidence engine', process.execPath, ['tests/platform-release-engine.mjs'], 'release', 'release/platform', ['.gitignored/test-artifacts/platform-release-engine/platform-release-parity-evidence-package.json']),
  step('UI Scale production evidence engine', process.execPath, ['tests/ui-scale-production-engine.mjs'], 'release', 'release/ui-scale', ['.gitignored/test-artifacts/ui-scale-production-engine/ui-scale-production-evidence-package.json']),
  step('Platform Shell production evidence engine', process.execPath, ['tests/platform-shell-production-engine.mjs'], 'release', 'release/platform-shell', ['.gitignored/test-artifacts/platform-shell-production-engine/platform-shell-production-evidence-package.json']),
  step('Agent Control production evidence engine', process.execPath, ['tests/agent-control-production-engine.mjs'], 'runtime', 'ai/agentic-control', ['.gitignored/test-artifacts/agent-control-production-engine/agent-control-production-evidence-package.json']),
  step('AI Provider production evidence engine', process.execPath, ['tests/ai-provider-production-engine.mjs'], 'engine', 'ai/provider-production', ['.gitignored/test-artifacts/ai-provider-production-engine/ai-provider-production-evidence-package.json']),
  step('Release Security production evidence engine', process.execPath, ['tests/release-security-production-engine.mjs'], 'release', 'release/security-production', ['.gitignored/test-artifacts/release-security-production-engine/release-security-production-evidence-package.json']),
  step('Release Trust production evidence engine', process.execPath, ['tests/release-trust-production-engine.mjs'], 'release', 'release/trust-production', ['.gitignored/test-artifacts/release-trust-production-engine/release-trust-production-evidence-package.json']),
  step('Fast regression production evidence engine', process.execPath, ['tests/fast-regression-production-engine.mjs'], 'release', 'release/ci-fast', ['.gitignored/test-artifacts/fast-regression-production-engine/fast-regression-production-evidence-package.json']),
  step('Full/Nightly production evidence engine', process.execPath, ['tests/full-nightly-production-engine.mjs'], 'release', 'release/ci-full-nightly', ['.gitignored/test-artifacts/full-nightly-production-engine/full-nightly-production-evidence-package.json']),
  step('Full/Nightly retained history engine', process.execPath, ['tests/full-nightly-history-engine.mjs'], 'release', 'release/ci-full-nightly', ['.gitignored/test-artifacts/full-nightly-history-engine/full-nightly-retained-history-evidence-package.json']),
  step('Install docs production evidence engine', process.execPath, ['tests/install-docs-production-engine.mjs'], 'release', 'release/docs', ['.gitignored/test-artifacts/install-docs-production-engine/install-docs-production-evidence-package.json']),
  step('Windows package production evidence engine', process.execPath, ['tests/windows-package-production-engine.mjs'], 'release', 'release/windows-package', ['.gitignored/test-artifacts/windows-package-production-engine/windows-package-production-evidence-package.json']),
  step('Linux package production evidence engine', process.execPath, ['tests/linux-package-production-engine.mjs'], 'release', 'release/linux-package', ['.gitignored/test-artifacts/linux-package-production-engine/linux-package-production-evidence-package.json']),
  step('Enterprise policy transport engine', process.execPath, ['tests/enterprise-policy-transport.mjs'], 'engine', 'enterprise/governance', ['dist-electron/enterprisePolicyTransport.js']),
  step('Safety and enterprise parity evidence engine', process.execPath, ['tests/safety-enterprise-engine.mjs'], 'engine', 'enterprise/safety', ['.gitignored/test-artifacts/safety-enterprise-engine/safety-enterprise-parity-evidence-package.json']),
  step('Project parity evidence engine', process.execPath, ['tests/project-parity-engine.mjs'], 'engine', 'project/persistence', ['.gitignored/test-artifacts/project-parity-engine/project-parity-evidence-package.json']),
  step('Project import compatibility engine', process.execPath, ['tests/project-import-compatibility-engine.mjs'], 'engine', 'project/import-compatibility', ['.gitignored/test-artifacts/project-import-compatibility/project-import-compatibility-evidence-package.json']),
  step('Customer-scale interop profiling engine', process.execPath, ['tests/customer-scale-interop-engine.mjs'], 'engine', 'project/customer-scale-interop', ['.gitignored/test-artifacts/customer-scale-interop/customer-scale-interop-evidence-package.json']),
  step('Project Store v2 persistence engine', process.execPath, ['tests/project-store-v2.mjs'], 'engine', 'project/store-v2', ['.gitignored/test-artifacts/project-store-v2/']),
  step('Typed IPC capability and audit contract engine', process.execPath, ['tests/ipc-contract-security.mjs'], 'runtime', 'security/ipc-contracts', ['.gitignored/test-artifacts/ipc-contract-security/']),
  step('Project Store settings workflow engine', process.execPath, ['tests/project-store-settings-workflow.mjs'], 'engine', 'project/settings', ['.gitignored/test-artifacts/project-store-settings-workflow/']),
  step('Project Store cookie jar workflow engine', process.execPath, ['tests/project-store-cookie-jar-workflow.mjs'], 'engine', 'project/cookie-jar', ['.gitignored/test-artifacts/project-store-cookie-jar-workflow/']),
  step('Project Store target inventory workflow engine', process.execPath, ['tests/project-store-target-inventory-workflow.mjs'], 'engine', 'project/target-inventory', ['.gitignored/test-artifacts/project-store-target-inventory-workflow/']),
  step('Project Store automation AI extension run-state workflow engine', process.execPath, ['tests/project-store-run-state-workflow.mjs'], 'engine', 'project/run-state', ['.gitignored/test-artifacts/project-store-run-state-workflow/']),
  step('Project Store live automation AI extension run-state wiring engine', process.execPath, ['tests/project-store-live-run-state-wiring.mjs'], 'engine', 'project/live-run-state', ['.gitignored/test-artifacts/project-store-live-run-state-wiring/']),
  step('Proxy Project Store workflow engine', process.execPath, ['tests/proxy-project-store-workflow.mjs'], 'engine', 'project/proxy-store-workflow', ['.gitignored/test-artifacts/proxy-project-store-workflow/']),
  step('Project Store OAST workflow engine', process.execPath, ['tests/project-store-oast-workflow.mjs'], 'engine', 'project/oast-store-workflow', ['.gitignored/test-artifacts/project-store-oast-workflow/']),
  step('Project Store signed OAST evidence engine', process.execPath, ['tests/project-store-oast-signed-evidence.mjs'], 'engine', 'project/oast-signed-evidence', ['.gitignored/test-artifacts/project-store-oast-signed-evidence/']),
  step('Scanner OAST SSRF workflow engine', process.execPath, ['tests/scanner-oast-ssrf.mjs'], 'engine', 'scanner/oast-correlation', ['.gitignored/test-artifacts/scanner-oast-ssrf/']),
  step('Agent option audit gate', process.execPath, ['tests/agent-option-audit.mjs'], 'runtime', 'ai/agentic-control', ['docs/agents/MVP_OPTION_AUDIT.md']),
  step('Certificate manager engine', process.execPath, ['tests/cert-manager.mjs'], 'engine', 'proxy-platform', ['dist-electron/certManager.js']),
  step('Browser launcher and cookie extraction engine', process.execPath, ['tests/browser-launcher.mjs'], 'engine', 'platform/session', ['dist-electron/browserLauncher.js', 'dist-electron/browserCookies.js']),
  step('Session profile live refresh engine', process.execPath, ['tests/session-profile-refresh.mjs'], 'engine', 'target/session', ['dist-electron/sessionProfileRefresh.js']),
  step('Shared session cookie jar engine', process.execPath, ['tests/session-cookie-jar.mjs'], 'engine', 'session/cookie-jar', ['.gitignored/test-artifacts/session-cookie-jar/']),
  step('Session macro token refresh engine', process.execPath, ['tests/session-macro-engine.mjs'], 'engine', 'session/macro-refresh', ['.gitignored/test-artifacts/session-macro-engine/']),
  step('Session replay runtime engine', process.execPath, ['tests/session-replay-engine.mjs'], 'engine', 'session/runtime', ['dist-electron/sessionEngine.js']),
  step('Proxy HTTP listener capture engine', process.execPath, ['tests/proxy-listener-engine.mjs'], 'engine', 'proxy-core', ['dist-electron/proxyEngine.js']),
  step('CONNECT tunnel metadata engine', process.execPath, ['tests/connect-tunnel.mjs'], 'engine', 'proxy-core', ['dist-electron/proxyEngine.js']),
  step('HTTPS MITM engine', process.execPath, ['tests/https-mitm.mjs'], 'engine', 'proxy-core', ['dist-electron/proxyEngine.js', 'dist-electron/certManager.js']),
  step('Proxy intercept engine', process.execPath, ['tests/intercept-engine.mjs'], 'engine', 'proxy-core', ['dist-electron/proxyEngine.js']),
  step('Proxy history analysis engine', process.execPath, ['tests/proxy-history-engine.mjs'], 'engine', 'proxy-history', ['test-results/ci-full-suite-summary.json']),
  step('Crawler engine', process.execPath, ['tests/crawl-engine.mjs'], 'engine', 'target/crawler', ['dist-electron/crawlEngine.js']),
  step('Crawl insertion audit engine', process.execPath, ['tests/crawl-audit.mjs'], 'engine', 'target/scanner', ['dist-electron/proxyEngine.js']),
  step('Target map engine', process.execPath, ['tests/target-map-engine.mjs'], 'engine', 'target/map', ['test-results/ci-full-suite-summary.json']),
  step('Scanner passive dedupe engine', process.execPath, ['tests/scanner-passive-engine.mjs'], 'engine', 'scanner/evidence', ['.gitignored/test-artifacts/scanner-passive-engine/scanner-passive-dedupe-parity-package.json']),
  step('Active scanner engine', process.execPath, ['tests/active-scanner.mjs'], 'engine', 'scanner/runtime', ['dist-electron/proxyEngine.js']),
  step('Scanner live calibration engine', process.execPath, ['tests/scanner-live-calibration.mjs'], 'engine', 'scanner/runtime', ['dist-electron/proxyEngine.js']),
  step('Scanner active evidence engine', process.execPath, ['tests/scanner-active-scan-engine.mjs'], 'engine', 'scanner/evidence', ['test-results/ci-full-suite-summary.json']),
  step('Scanner retest evidence delta engine', process.execPath, ['tests/scanner-retest-engine.mjs'], 'engine', 'scanner/evidence', ['test-results/ci-full-suite-summary.json']),
  step('Anvil custom scan-check engine', process.execPath, ['tests/anvil-engine.mjs'], 'engine', 'scanner/evidence', ['test-results/ci-full-suite-summary.json']),
  step('Repeater transport engine', process.execPath, ['tests/repeater-transport.mjs'], 'engine', 'repeater/runtime', ['dist-electron/proxyEngine.js']),
  step('Repeater workspace parity engine', process.execPath, ['tests/repeater-workspace-engine.mjs'], 'engine', 'repeater/workspace', ['test-results/ci-full-suite-summary.json']),
  step('Repeater OAST workflow engine', process.execPath, ['tests/repeater-oast-workflow.mjs'], 'engine', 'repeater/oast-workflow', ['.gitignored/test-artifacts/repeater-oast-workflow/']),
  step('Repeater desync race socket engine', process.execPath, ['tests/repeater-desync-race-engine.mjs'], 'engine', 'repeater/desync-race', ['dist-electron/repeaterDesyncRaceEngine.js']),
  step('Intruder engine', process.execPath, ['tests/intruder-engine.mjs'], 'engine', 'intruder/runtime', ['dist-electron/proxyEngine.js']),
  step('Intruder OAST row correlation engine', process.execPath, ['tests/intruder-oast-correlation.mjs'], 'engine', 'intruder/oast-correlation', ['.gitignored/test-artifacts/intruder-oast-correlation/']),
  step('Sequencer large-sample reliability engine', process.execPath, ['tests/sequencer-engine.mjs'], 'engine', 'sequencer/runtime', ['dist-electron/sequencerEngine.js']),
  step('Decoder token workflow engine', process.execPath, ['tests/decoder-engine.mjs'], 'engine', 'decoder/runtime', ['test-results/ci-full-suite-summary.json']),
  step('Comparer engine', process.execPath, ['tests/compare-engine.mjs'], 'engine', 'comparer/runtime', ['test-results/ci-full-suite-summary.json']),
  step('Analysis tool refresh evidence engine', process.execPath, ['tests/analysis-tool-refresh-engine.mjs'], 'engine', 'analysis/package-refresh', ['.gitignored/test-artifacts/analysis-tool-refresh-engine/analysis-tool-refresh-evidence-package.json']),
  step('Report export engine', process.execPath, ['tests/report-engine.mjs'], 'engine', 'reports/runtime', ['dist-electron/reportEngine.js']),
  step('Report PDF visual QA smoke', process.execPath, ['tests/report-pdf-visual-qa.mjs'], 'engine', 'reports/runtime', ['dist-electron/reportEngine.js']),
  step('Release security review engine', process.execPath, ['tests/security-review-engine.mjs'], 'release', 'release/security', ['test-results/ci-full-suite-summary.json']),
  step('Headless CLI runtime smoke', process.execPath, ['tests/headless-runner.mjs'], 'runtime', 'automation/ci', ['test-results/.last-run.json']),
  step('Agentic control CLI smoke', process.execPath, ['tests/agent-cli.mjs'], 'runtime', 'ai/agentic-control', ['scripts/proxyforge-agent.mjs']),
  step('Browser workflow source audit', process.execPath, ['tests/browser-suite-audit.mjs'], 'e2e', 'frontend/workflows', ['tests/proxyforge.spec.ts']),
  step('Logger custom column engine', process.execPath, ['tests/logger-column-engine.mjs'], 'engine', 'logger/runtime', ['test-results/ci-full-suite-summary.json']),
  step('Logger parity evidence engine', process.execPath, ['tests/logger-evidence-engine.mjs'], 'engine', 'logger/evidence', ['.gitignored/test-artifacts/logger-evidence-engine/logger-parity-evidence-package.json']),
  step('Organizer parity evidence engine', process.execPath, ['tests/organizer-evidence-engine.mjs'], 'engine', 'organizer/evidence', ['.gitignored/test-artifacts/organizer-evidence-engine/organizer-parity-evidence-package.json']),
  step('Search semantic ranking engine', process.execPath, ['tests/search-engine.mjs'], 'engine', 'search/runtime', ['test-results/ci-full-suite-summary.json']),
  step('Viewer parity engine', process.execPath, ['tests/viewer-engine.mjs'], 'engine', 'viewer/runtime', ['.gitignored/test-artifacts/viewer-engine/viewer-parity-evidence-package.json']),
  step('Automation scheduler engine', process.execPath, ['tests/automation-engine.mjs'], 'engine', 'automation/runtime', ['test-results/ci-full-suite-summary.json']),
  step('Automation installed-host service smoke', process.execPath, ['tests/automation-service-smoke.mjs'], 'runtime', 'automation/service-smoke', ['.gitignored/test-artifacts/automation-service-smoke/agent-service-smoke-package.json']),
  step('Sandboxed extension runtime engine', process.execPath, ['tests/extension-engine.mjs'], 'engine', 'extensions/runtime', ['test-results/ci-full-suite-summary.json']),
  step('Extension third-party compatibility engine', process.execPath, ['tests/extension-third-party-compatibility-engine.mjs'], 'engine', 'extensions/third-party-compatibility', ['.gitignored/test-artifacts/extension-third-party-compatibility/extension-third-party-sdk-compatibility-package.json']),
  step('Callback listener backend engine', process.execPath, ['tests/callback-listener-service.mjs'], 'engine', 'collaborator/runtime', ['dist-electron/callbackListenerService.js']),
  step('Callback live backend engine', process.execPath, ['tests/callback-live-backend-engine.mjs'], 'engine', 'collaborator/evidence', ['test-results/ci-full-suite-summary.json']),
  step('Exploit backend execution engine', process.execPath, ['tests/exploit-engine.mjs'], 'engine', 'exploit/runtime', ['.gitignored/test-artifacts/exploit-engine/exploit-parity-evidence-package.json']),
  step('Transparent proxy mode side-car stub engine', process.execPath, ['tests/traffic-transparent-linux.mjs'], 'engine', 'proxy/transparent-mode', ['dist-electron/electron/traffic/transparentMode.js']),
  step('Raw TCP/UDP transport stub engine', process.execPath, ['tests/traffic-raw-tcp-udp.mjs'], 'engine', 'proxy/raw-transport', ['dist-electron/electron/traffic/rawTcpUdp.js']),
  step('HTTP/3 QUIC transport side-car stub engine', process.execPath, ['tests/traffic-http3-end-to-end.mjs'], 'engine', 'proxy/http3-transport', ['dist-electron/electron/traffic/http3Transport.js']),
  step('WireGuard capture side-car stub engine', process.execPath, ['tests/traffic-wireguard.mjs'], 'engine', 'proxy/wireguard-mode', ['dist-electron/electron/traffic/wireguardMode.js']),
  step('WebSocket engine', process.execPath, ['tests/websocket-engine.mjs'], 'engine', 'proxy/websocket', ['dist-electron/proxyEngine.js']),
  step('AI provider engine', process.execPath, ['tests/ai-engine.mjs'], 'engine', 'ai/runtime', ['dist-electron/aiEngine.js']),
  step('AI controlled action execution engine', process.execPath, ['tests/ai-action-engine.mjs'], 'engine', 'ai/actions', ['.gitignored/test-artifacts/ai-action-engine/ai-parity-evidence-package.json']),
  step('Full browser workflow suite', npxBin, ['playwright', 'test', 'tests/proxyforge.spec.ts'], 'e2e', 'frontend/workflows', ['playwright-report/', 'test-results/playwright-artifacts/'], 1),
].filter((item) => !(skipBrowser && item.kind === 'e2e'));

const plan = {
  kind: 'proxyforge-ci-full-suite-plan',
  suite: 'full-nightly',
  generatedAt: startedAt.toISOString(),
  stepCount: steps.length,
  uploadPolicy,
  flakeBudget,
  coverageOwnership: steps.map(({ name, kind, owner, artifactPaths, retryBudget }) => ({
    name,
    kind,
    owner,
    artifactPaths,
    retryBudget,
  })),
};

validatePlan(plan);
await fs.mkdir(resultsDir, { recursive: true });
await fs.writeFile(path.join(resultsDir, 'ci-full-suite-plan.json'), JSON.stringify(plan, null, 2));

if (planOnly) {
  const summary = {
    kind: 'proxyforge-ci-full-suite-summary',
    mode: 'plan-only',
    passed: true,
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    durationMs: Date.now() - startedAt.getTime(),
    totalSteps: steps.length,
    completedSteps: 0,
    uploadPolicy,
    flakeBudget,
    results: [],
  };
  await persistSuiteSummary(summary);
  console.log(`ci-full-suite: plan validated for ${steps.length} step${steps.length === 1 ? '' : 's'}`);
  process.exit(0);
}

const results = [];
for (const suiteStep of steps) {
  const result = await runStep(suiteStep);
  results.push(result);
  if (result.status !== 'passed') break;
}

const completedAt = new Date();
const summary = {
  kind: 'proxyforge-ci-full-suite-summary',
  mode: skipBrowser ? 'skip-browser' : 'full',
  startedAt: startedAt.toISOString(),
  completedAt: completedAt.toISOString(),
  durationMs: completedAt.getTime() - startedAt.getTime(),
  passed: results.every((result) => result.status === 'passed') && results.length === steps.length,
  totalSteps: steps.length,
  completedSteps: results.length,
  uploadPolicy,
  flakeBudget,
  coverageOwnership: plan.coverageOwnership,
  results,
};

await persistSuiteSummary(summary);

assert.equal(summary.passed, true, `ci-full-suite failed at ${results.find((result) => result.status !== 'passed')?.name ?? 'unknown step'}`);
console.log(`ci-full-suite: ${summary.completedSteps}/${summary.totalSteps} steps passed in ${summary.durationMs}ms`);

function step(name, command, args, kind, owner, artifactPaths, retryBudget = 0) {
  return {
    name,
    command,
    args,
    kind,
    owner,
    artifactPaths,
    retryBudget,
  };
}

function validatePlan(planToValidate) {
  assert.ok(planToValidate.stepCount > 10, 'full suite should cover broad engine and browser workflow surfaces');
  assert.ok(planToValidate.coverageOwnership.every((item) => item.owner && item.kind), 'each full-suite step needs owner and kind metadata');
  assert.equal(new Set(planToValidate.coverageOwnership.map((item) => item.name)).size, planToValidate.coverageOwnership.length, 'full-suite step names must be unique');
  assert.ok(planToValidate.uploadPolicy.requiredArtifacts.includes('test-results/ci-full-suite-summary.json'), 'full suite summary must be uploadable');
  assert.equal(planToValidate.flakeBudget.maxFlakySteps, 0, 'nightly flake budget must default to zero tolerated flaky steps');
}

function runStep(suiteStep) {
  const start = new Date();
  console.log(`ci-full-suite: starting ${suiteStep.name}`);
  return new Promise((resolve) => {
    const child = spawn(suiteStep.command, suiteStep.args, {
      cwd: process.cwd(),
      env: {
        ...process.env,
        CI: process.env.CI ?? '1',
        FORCE_COLOR: process.env.FORCE_COLOR ?? '0',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      const text = chunk.toString();
      stdout += text;
      process.stdout.write(text);
    });
    child.stderr.on('data', (chunk) => {
      const text = chunk.toString();
      stderr += text;
      process.stderr.write(text);
    });
    child.on('close', (code) => {
      const end = new Date();
      const status = code === 0 ? 'passed' : 'failed';
      console.log(`ci-full-suite: ${status} ${suiteStep.name}`);
      resolve({
        name: suiteStep.name,
        kind: suiteStep.kind,
        owner: suiteStep.owner,
        command: [suiteStep.command, ...suiteStep.args].join(' '),
        status,
        exitCode: code,
        retryBudget: suiteStep.retryBudget,
        artifactPaths: suiteStep.artifactPaths,
        startedAt: start.toISOString(),
        completedAt: end.toISOString(),
        durationMs: end.getTime() - start.getTime(),
        stdoutTail: tail(stdout),
        stderrTail: tail(stderr),
      });
    });
  });
}

function tail(value) {
  return value.split(/\r?\n/).filter(Boolean).slice(-12).join('\n');
}

async function persistSuiteSummary(summary) {
  const summaryPath = path.join(resultsDir, 'ci-full-suite-summary.json');
  await fs.writeFile(summaryPath, JSON.stringify(summary, null, 2));
  await fs.writeFile(path.join(resultsDir, '.last-run.json'), JSON.stringify({
    kind: 'proxyforge-ci-last-run',
    suite: 'full-nightly',
    mode: summary.mode,
    passed: summary.passed,
    startedAt: summary.startedAt,
    completedAt: summary.completedAt,
    totalSteps: summary.totalSteps,
    completedSteps: summary.completedSteps,
    summaryPath: 'test-results/ci-full-suite-summary.json',
  }, null, 2));

  if (summary.mode === 'plan-only') return;
  await retainRuntimeSummary(summary);
}

async function retainRuntimeSummary(summary) {
  const historyDir = path.join(resultsDir, 'ci-full-suite-history');
  await fs.mkdir(historyDir, { recursive: true });
  const runId = buildRunId(summary);
  const artifactPath = `test-results/ci-full-suite-history/${runId}-summary.json`;
  const retainedSummaryPath = path.join(historyDir, `${runId}-summary.json`);
  await fs.writeFile(retainedSummaryPath, JSON.stringify(summary, null, 2));

  const retainedRuns = [];
  const entries = await fs.readdir(historyDir, { withFileTypes: true });
  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('-summary.json')) continue;
    const entryPath = path.join(historyDir, entry.name);
    try {
      const parsed = JSON.parse(await fs.readFile(entryPath, 'utf8'));
      if (parsed?.kind !== 'proxyforge-ci-full-suite-summary') continue;
      retainedRuns.push({
        runId: entry.name.replace(/-summary\.json$/, ''),
        mode: parsed.mode,
        startedAt: parsed.startedAt,
        completedAt: parsed.completedAt,
        passed: parsed.passed,
        totalSteps: parsed.totalSteps,
        completedSteps: parsed.completedSteps,
        durationMs: parsed.durationMs,
        artifactPath: `test-results/ci-full-suite-history/${entry.name}`,
        summaryDigest: simpleDigest(JSON.stringify(parsed)),
        failedStepNames: (parsed.results ?? [])
          .filter((result) => result.status !== 'passed' || result.exitCode !== 0)
          .map((result) => result.name),
      });
    } catch {
      retainedRuns.push({
        runId: entry.name.replace(/-summary\.json$/, ''),
        mode: 'unreadable',
        startedAt: new Date(0).toISOString(),
        completedAt: new Date(0).toISOString(),
        passed: false,
        totalSteps: 0,
        completedSteps: 0,
        durationMs: 0,
        artifactPath: `test-results/ci-full-suite-history/${entry.name}`,
        summaryDigest: 'unreadable',
        failedStepNames: ['unreadable retained summary'],
      });
    }
  }

  retainedRuns.sort((left, right) => Date.parse(left.startedAt) - Date.parse(right.startedAt));
  const runtimeRuns = retainedRuns.filter((run) => run.mode === 'full' || run.mode === 'skip-browser');
  const durations = runtimeRuns.map((run) => run.durationMs).sort((left, right) => left - right);
  const failedStepFrequency = retainedRuns.reduce((counts, run) => {
    for (const failedStepName of run.failedStepNames ?? []) {
      counts[failedStepName] = (counts[failedStepName] ?? 0) + 1;
    }
    return counts;
  }, {});
  const dashboard = {
    kind: 'proxyforge-full-nightly-retained-history-dashboard',
    generatedAt: new Date().toISOString(),
    historyArtifactPath: 'test-results/ci-full-suite-history/dashboard.json',
    latestWrittenSummaryPath: artifactPath,
    retainedRunCount: retainedRuns.length,
    runtimeRunCount: runtimeRuns.length,
    fullRunCount: runtimeRuns.filter((run) => run.mode === 'full').length,
    skipBrowserRunCount: runtimeRuns.filter((run) => run.mode === 'skip-browser').length,
    planOnlyRunCount: retainedRuns.filter((run) => run.mode === 'plan-only').length,
    passedRunCount: retainedRuns.filter((run) => run.passed).length,
    failedRunCount: retainedRuns.filter((run) => !run.passed).length,
    consecutiveRuntimePasses: countTrailingPasses(runtimeRuns),
    medianRuntimeDurationMs: median(durations),
    latestRuntimeRun: runtimeRuns.at(-1),
    retainedRuns,
    artifactPaths: retainedRuns.map((run) => run.artifactPath),
    failedStepFrequency,
  };
  await fs.writeFile(path.join(historyDir, 'dashboard.json'), JSON.stringify(dashboard, null, 2));
}

function buildRunId(summary) {
  const stamp = summary.startedAt.replace(/[:.]/g, '-');
  if (process.env.GITHUB_RUN_ID) {
    const attempt = process.env.GITHUB_RUN_ATTEMPT ? `-${process.env.GITHUB_RUN_ATTEMPT}` : '';
    return `github-${process.env.GITHUB_RUN_ID}${attempt}-${stamp}`;
  }
  return `local-${stamp}`;
}

function countTrailingPasses(runs) {
  let count = 0;
  for (let index = runs.length - 1; index >= 0; index -= 1) {
    if (!runs[index].passed) break;
    count += 1;
  }
  return count;
}

function median(values) {
  if (!values.length) return 0;
  const midpoint = Math.floor(values.length / 2);
  if (values.length % 2) return values[midpoint];
  return Math.round((values[midpoint - 1] + values[midpoint]) / 2);
}

function simpleDigest(value) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
