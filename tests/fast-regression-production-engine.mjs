import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildFastRegressionProductionEvidencePackage',
];
const enginePath = path.resolve('src/fastRegressionProductionEngine.ts');
const fastRegressionEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof fastRegressionEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `fast-regression-production-engine: missing export(s): ${missingExports.join(', ')}`);

const context = buildFastRegressionContext();
const productionPackage = fastRegressionEngine.buildFastRegressionProductionEvidencePackage(context);
const packageContent = JSON.parse(productionPackage.content);

assert.equal(productionPackage.kind, 'proxyforge-fast-regression-production-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, true);
assert(Object.values(productionPackage.requirements).every(Boolean), 'all Fast Regression production requirements should be true');
assert.equal(productionPackage.stepCount, context.summary.totalSteps);
assert.equal(packageContent.kind, 'proxyforge-fast-regression-production-evidence-package');
assert.match(productionPackage.content, /test-results\/ci-fast-suite-summary\.json/);
assert.match(productionPackage.content, /Platform Release parity evidence engine/);
assert.match(productionPackage.content, /UI Scale production evidence engine/);
assert.match(productionPackage.content, /Platform Shell production evidence engine/);
assert.match(productionPackage.content, /Agent Control production evidence engine/);
assert.match(productionPackage.content, /AI Provider production evidence engine/);
assert.match(productionPackage.content, /Release Security production evidence engine/);
assert.match(productionPackage.content, /Release Trust production evidence engine/);
assert.match(productionPackage.content, /Full\/Nightly production evidence engine/);
assert.match(productionPackage.content, /Full\/Nightly retained history engine/);
assert.match(productionPackage.content, /Project import compatibility engine/);
assert.match(productionPackage.content, /Customer-scale interop profiling engine/);
assert.match(productionPackage.content, /Extension third-party compatibility engine/);
assert.match(productionPackage.content, /Automation installed-host service smoke/);
assert.match(productionPackage.content, /Agentic control CLI smoke/);
assert.match(productionPackage.content, /Analysis tool refresh evidence engine/);
assert.match(productionPackage.content, /Focused browser workflow smoke/);
assert.match(productionPackage.content, /Authorization: Bearer fast-regression-secret-token/);
assert.match(productionPackage.content, /session=fast-regression-session/);
assert.match(productionPackage.content, /X-API-Key: fast-regression-api-key/);
assert.match(productionPackage.content, /callbackToken=fast-regression-callback-token/);
assert.match(productionPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/fast-regression-production-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'fast-regression-production-evidence-package.json'), productionPackage.content);

console.log('fast-regression-production-engine: verified production-grade fast-suite coverage, artifact policy, and full-fidelity secret boundary');

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

function buildFastRegressionContext() {
  const startedAt = '2026-05-25T23:59:30.000Z';
  const completedAt = '2026-05-26T00:02:30.000Z';
  const rawRequest = [
    'GET /api/fast-regression HTTP/1.1',
    'Host: app.shop.local',
    'Authorization: Bearer fast-regression-secret-token',
    'Cookie: session=fast-regression-session',
    'X-API-Key: fast-regression-api-key',
    '',
    '',
  ].join('\r\n');
  const rawResponse = [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json',
    'Set-Cookie: callbackToken=fast-regression-callback-token; HttpOnly',
    '',
    '{"ok":true,"rawResponse":"fast-regression"}',
  ].join('\r\n');
  const names = [
    ['Build renderer and Electron runtime', 'build', 'npm run build'],
    ['Release readiness verifier', 'release', 'node tests/release-readiness.mjs'],
    ['Release smoke runner plan', 'release', 'node tests/release-smoke-runner.mjs'],
    ['CI nightly policy gate', 'release', 'node tests/ci-nightly-policy.mjs'],
    ['Release runtime workflow smoke', 'release', 'node tests/release-runtime-workflow.mjs'],
    ['Platform Release parity evidence engine', 'release', 'node tests/platform-release-engine.mjs'],
    ['UI Scale production evidence engine', 'release', 'node tests/ui-scale-production-engine.mjs'],
    ['Platform Shell production evidence engine', 'release', 'node tests/platform-shell-production-engine.mjs'],
    ['Agent Control production evidence engine', 'runtime', 'node tests/agent-control-production-engine.mjs'],
    ['AI Provider production evidence engine', 'engine', 'node tests/ai-provider-production-engine.mjs'],
    ['Release Security production evidence engine', 'release', 'node tests/release-security-production-engine.mjs'],
    ['Release Trust production evidence engine', 'release', 'node tests/release-trust-production-engine.mjs'],
    ['Fast regression production evidence engine', 'release', 'node tests/fast-regression-production-engine.mjs'],
    ['Full/Nightly production evidence engine', 'release', 'node tests/full-nightly-production-engine.mjs'],
    ['Full/Nightly retained history engine', 'release', 'node tests/full-nightly-history-engine.mjs'],
    ['Install docs production evidence engine', 'release', 'node tests/install-docs-production-engine.mjs'],
    ['Windows package production evidence engine', 'release', 'node tests/windows-package-production-engine.mjs'],
    ['Linux package production evidence engine', 'release', 'node tests/linux-package-production-engine.mjs'],
    ['Enterprise policy transport engine', 'engine', 'node tests/enterprise-policy-transport.mjs'],
    ['Safety and enterprise parity evidence engine', 'engine', 'node tests/safety-enterprise-engine.mjs'],
    ['Project parity evidence engine', 'engine', 'node tests/project-parity-engine.mjs'],
    ['Project import compatibility engine', 'engine', 'node tests/project-import-compatibility-engine.mjs'],
    ['Customer-scale interop profiling engine', 'engine', 'node tests/customer-scale-interop-engine.mjs'],
    ['Extension third-party compatibility engine', 'engine', 'node tests/extension-third-party-compatibility-engine.mjs'],
    ['Agent option audit gate', 'runtime', 'node tests/agent-option-audit.mjs'],
    ['Search semantic ranking engine', 'engine', 'node tests/search-engine.mjs'],
    ['Viewer parity engine', 'engine', 'node tests/viewer-engine.mjs'],
    ['Logger custom column compatibility engine', 'engine', 'node tests/logger-column-engine.mjs'],
    ['Logger parity evidence engine', 'engine', 'node tests/logger-evidence-engine.mjs'],
    ['Organizer parity evidence engine', 'engine', 'node tests/organizer-evidence-engine.mjs'],
    ['Sequencer large-sample reliability engine', 'engine', 'node tests/sequencer-engine.mjs'],
    ['Decoder token workflow engine', 'engine', 'node tests/decoder-engine.mjs'],
    ['Decoder transform chain golden corpus', 'engine', 'node tests/decoder-golden.mjs'],
    ['Comparer parity engine', 'engine', 'node tests/compare-engine.mjs'],
    ['Analysis tool refresh evidence engine', 'engine', 'node tests/analysis-tool-refresh-engine.mjs'],
    ['Automation scheduler engine', 'engine', 'node tests/automation-engine.mjs'],
    ['Automation installed-host service smoke', 'runtime', 'node tests/automation-service-smoke.mjs'],
    ['Sandboxed extension runtime engine', 'engine', 'node tests/extension-engine.mjs'],
    ['Callback live backend engine', 'engine', 'node tests/callback-live-backend-engine.mjs'],
    ['OAST relay integration engine', 'engine', 'node tests/oast-relay-integration.mjs'],
    ['OAST provider diversity engine', 'engine', 'node tests/oast-provider-diversity.mjs'],
    ['Exploit backend execution engine', 'engine', 'node tests/exploit-engine.mjs'],
    ['AI controlled action execution engine', 'engine', 'node tests/ai-action-engine.mjs'],
    ['Repeater transport engine', 'engine', 'node tests/repeater-transport.mjs'],
    ['Repeater workspace parity engine', 'engine', 'node tests/repeater-workspace-engine.mjs'],
    ['Session profile live refresh engine', 'engine', 'node tests/session-profile-refresh.mjs'],
    ['Crawler runtime engine', 'engine', 'node tests/crawl-engine.mjs'],
    ['Target access-control and comparison map engine', 'engine', 'node tests/target-map-engine.mjs'],
    ['Browser launch and cookie matrix engine', 'platform', 'node tests/browser-launcher.mjs'],
    ['Proxy HTTP listener capture engine', 'engine', 'node tests/proxy-listener-engine.mjs'],
    ['CONNECT tunnel byte-accounting engine', 'engine', 'node tests/connect-tunnel.mjs'],
    ['HTTPS MITM project CA engine', 'engine', 'node tests/https-mitm.mjs'],
    ['Proxy intercept request-response engine', 'engine', 'node tests/intercept-engine.mjs'],
    ['Repeater desync race socket engine', 'engine', 'node tests/repeater-desync-race-engine.mjs'],
    ['Intruder attack mode matrix engine', 'engine', 'node tests/intruder-engine.mjs'],
    ['Proxy HTTP/2 fidelity engine', 'engine', 'node tests/proxy-history-engine.mjs'],
    ['Proxy WebSocket capture engine', 'engine', 'node tests/websocket-engine.mjs'],
    ['Scanner passive dedupe engine', 'engine', 'node tests/scanner-passive-engine.mjs'],
    ['Active scanner check-pack engine', 'engine', 'node tests/active-scanner.mjs'],
    ['Scanner insertion point inventory engine', 'engine', 'node tests/insertion-point-engine.mjs'],
    ['Crawl insertion audit engine', 'engine', 'node tests/crawl-audit.mjs'],
    ['Scanner active evidence engine', 'engine', 'node tests/scanner-active-scan-engine.mjs'],
    ['Scanner retest evidence delta engine', 'engine', 'node tests/scanner-retest-engine.mjs'],
    ['Anvil custom scan-check engine', 'engine', 'node tests/anvil-engine.mjs'],
    ['Scanner live calibration engine', 'engine', 'node tests/scanner-live-calibration.mjs'],
    ['Release security review engine', 'release', 'node tests/security-review-engine.mjs'],
    ['Report export parity engine', 'engine', 'node tests/report-engine.mjs'],
    ['Report PDF visual QA smoke', 'engine', 'node tests/report-pdf-visual-qa.mjs'],
    ['Headless CLI runtime smoke', 'runtime', 'node tests/headless-runner.mjs'],
    ['Agentic control CLI smoke', 'runtime', 'node tests/agent-cli.mjs'],
    ['Focused browser workflow smoke', 'e2e', 'npx playwright test tests/proxyforge.spec.ts -g search|automation|extension'],
  ];
  const results = names.map(([name, kind, command], index) => ({
    name,
    kind,
    command,
    status: 'passed',
    exitCode: 0,
    startedAt,
    completedAt,
    durationMs: 100 + index,
    stdoutTail: `${name} passed\n${rawRequest}\n${rawResponse}`,
    stderrTail: '',
  }));
  return {
    summary: {
      kind: 'proxyforge-ci-fast-suite-summary',
      startedAt,
      completedAt,
      durationMs: 180000,
      passed: true,
      totalSteps: results.length,
      completedSteps: results.length,
      results,
    },
    artifactPath: 'test-results/ci-fast-suite-summary.json',
    retentionDays: 30,
    generatedAt: completedAt,
    operationalSecretSamples: [
      'Authorization: Bearer fast-regression-secret-token',
      'session=fast-regression-session',
      'X-API-Key: fast-regression-api-key',
      'callbackToken=fast-regression-callback-token',
    ],
  };
}
