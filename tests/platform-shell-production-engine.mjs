import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildPlatformShellProductionEvidencePackage',
];
const enginePath = path.resolve('src/platformShellProductionEngine.ts');
const platformShellEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof platformShellEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `platform-shell-production-engine: missing export(s): ${missingExports.join(', ')}`);

const context = buildPlatformShellContext();
const productionPackage = platformShellEngine.buildPlatformShellProductionEvidencePackage(context);
const packageContent = JSON.parse(productionPackage.content);

assert.equal(productionPackage.kind, 'proxyforge-platform-shell-production-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, false, 'fixture-backed platform shell schema evidence must not be release productionReady');
assert.equal(productionPackage.requirements.artifactBackedShellSmokes, false);
assert(Object.entries(productionPackage.requirements).every(([name, value]) => name === 'artifactBackedShellSmokes' ? value === false : value === true), 'only artifact-backed shell evidence requirement should be false for fixture schema coverage');
assert.equal(productionPackage.smokeCount, 15);
assert.equal(packageContent.kind, 'proxyforge-platform-shell-production-evidence-package');
assert.match(productionPackage.content, /PROXYFORGE_RELEASE_SMOKE=1/);
assert.match(productionPackage.content, /proxyforge-release-smoke/);
assert.match(productionPackage.content, /resources\/app\.asar/);
assert.match(productionPackage.content, /external-cwd/);
assert.match(productionPackage.content, /~\/vantix/);
assert.match(productionPackage.content, /proxyforge-linux-package-production-evidence-package/);
assert.match(productionPackage.content, /proxyforge-windows-package-production-evidence-package/);
assert.match(productionPackage.content, /Authorization: Bearer platform-shell-secret-token/);
assert.match(productionPackage.content, /session=platform-shell-session/);
assert.match(productionPackage.content, /X-API-Key: platform-shell-api-key/);
assert.match(productionPackage.content, /callbackToken=platform-shell-callback-token/);
assert.match(productionPackage.content, /windows-trust-runner/);
assert.match(productionPackage.content, /ERROR_NOT_SUPPORTED/);
assert.match(productionPackage.content, /redact-only-during-report-export/);
assert.match(productionPackage.content, /Fixture\/schema shell evidence is blocked from productionReady/);

const artifactDir = path.resolve('.gitignored/test-artifacts/platform-shell-production-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'platform-shell-production-evidence-package.json'), productionPackage.content);

console.log('platform-shell-production-engine: verified Linux/Windows shell schema evidence, artifact-backed release gate, platform pins, and full-fidelity secret boundary');

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

function buildPlatformShellContext() {
  const now = '2026-05-26T00:10:00.000Z';
  const rawRequest = [
    'GET /api/platform-shell HTTP/1.1',
    'Host: app.shop.local',
    'Authorization: Bearer platform-shell-secret-token',
    'Cookie: session=platform-shell-session',
    'X-API-Key: platform-shell-api-key',
    '',
    '',
  ].join('\r\n');
  const rawResponse = [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json',
    'Set-Cookie: callbackToken=platform-shell-callback-token; HttpOnly',
    '',
    '{"ok":true,"rawResponse":"platform-shell"}',
  ].join('\r\n');
  return {
    generatedAt: now,
    smokes: [
      smoke('linux-shell', 'linux', 'electron-shell', 'passed', 'local-linux', 1, 0, 'PROXYFORGE_RELEASE_SMOKE=1 release/linux-unpacked/proxyforge emitted proxyforge-release-smoke and loaded resources/app.asar/dist/index.html', rawRequest, rawResponse),
      smoke('windows-shell', 'windows', 'electron-shell', 'passed', 'windows-trust-runner', 1, 0, 'PROXYFORGE_RELEASE_SMOKE=1 release\\win-unpacked\\ProxyForge.exe emitted proxyforge-release-smoke and loaded resources/app.asar/dist/index.html', rawRequest, rawResponse),
      smoke('linux-headless', 'linux', 'headless-cli', 'passed', 'local-linux', 2, 0, 'ELECTRON_RUN_AS_NODE=1 packaged headless CLI and scan/report started from resources/app.asar/dist-electron/headlessRunner.js', rawRequest, rawResponse),
      smoke('windows-headless', 'windows', 'headless-cli', 'passed', 'windows-trust-runner', 2, 0, 'Installed Windows packaged headless CLI and scan/report started from resources\\app.asar\\dist-electron\\headlessRunner.js', rawRequest, rawResponse),
      smoke('linux-agent', 'linux', 'agent-cli', 'passed', 'local-linux', 2, 0, 'packaged proxyforge-agent status returned command inventory with execution-full-fidelity-secrets-preserved', rawRequest, rawResponse),
      smoke('windows-agent', 'windows', 'agent-cli', 'passed', 'windows-trust-runner', 2, 0, 'installed packaged proxyforge-agent status returned command inventory with execution-full-fidelity-secrets-preserved', rawRequest, rawResponse),
      smoke('linux-external-cwd', 'linux', 'external-cwd-agent', 'passed', 'local-linux', 2, 0, 'external-cwd packaged agent invocation from ~/vantix resolved appRoot to resources/app.asar and kept full executor material', rawRequest, rawResponse),
      smoke('linux-runtime', 'linux', 'runtime-proxy-cert-oast-report', 'passed', 'local-linux', 5, 0, 'packaged runtime proxy/cert/OAST/report smoke captured HTTP, HTTPS MITM, callbacks, and report export', rawRequest, rawResponse),
      smoke('windows-runtime', 'windows', 'runtime-proxy-cert-oast-report', 'passed', 'windows-trust-runner', 5, 0, 'installed packaged runtime proxy/cert/OAST/report smoke captured HTTP, HTTPS MITM, callbacks, and report export', rawRequest, rawResponse),
      smoke('linux-browser-routing', 'linux', 'browser-routing', 'passed', 'local-linux', 2, 0, 'packaged Chromium browser routing through ProxyForge captured traffic in Proxy history', rawRequest, rawResponse),
      smoke('windows-browser-routing', 'windows', 'browser-routing', 'passed', 'windows-trust-runner', 2, 0, 'packaged Google Chrome browser routing through ProxyForge captured traffic in Proxy history', rawRequest, rawResponse),
      smoke('linux-package-gate', 'linux', 'package-production-gate', 'passed', 'local-linux', 1, 0, 'proxyforge-linux-package-production-evidence-package productionReady=true', rawRequest, rawResponse),
      smoke('windows-package-gate', 'windows', 'package-production-gate', 'passed', 'windows-trust-runner', 1, 0, 'proxyforge-windows-package-production-evidence-package productionReady=true', rawRequest, rawResponse),
      smoke('windows-trust-pin', 'windows', 'trust-store-pin', 'pinned-nonblocking', 'windows-trust-runner', 7, 0, 'windows-trust-runner CurrentUser\\Root trust-store mutation blocked with ERROR_NOT_SUPPORTED; accepted by Windows Package production gate', rawRequest, rawResponse),
      smoke('host-diversity-pin', 'windows', 'host-limit', 'pinned-nonblocking', 'windows-trust-runner', 1, 0, 'Broader host diversity remains a release-wide hardening lane, but shell production is nonblocking because current package runner lane and trust-store pin are explicit', rawRequest, rawResponse),
    ],
    releaseDocs: [
      'INSTALL_LINUX_WINDOWS documents Platform Shell production commands, release:smoke:linux, release:smoke:windows, PROXYFORGE_RELEASE_SMOKE, and Production Ready shell proof.',
      'OPERATOR_GUIDE documents Platform Shell production evidence retention, app.asar, external-cwd ~/vantix invocation, package gates, full-fidelity operational material, and redact-only-during-report-export.',
      'OPERATOR_GUIDE requires Platform Shell production evidence before the Electron shell row is Production Ready.',
    ],
    operationalSecretSamples: [
      'Authorization: Bearer platform-shell-secret-token',
      'session=platform-shell-session',
      'X-API-Key: platform-shell-api-key',
      'callbackToken=platform-shell-callback-token',
    ],
  };
}

function smoke(id, platform, lane, status, runner, passedChecks, failedChecks, notes, rawRequest, rawResponse) {
  return {
    id,
    platform,
    lane,
    status,
    runner,
    passedChecks,
    failedChecks,
    reason: status === 'pinned-nonblocking' ? notes : undefined,
    content: JSON.stringify({
      kind: 'proxyforge-platform-shell-smoke',
      platform,
      lane,
      status,
      runner,
      notes,
      rawRequest,
      rawResponse,
      reportRedactionBoundary: 'redact-only-during-report-export',
    }),
  };
}
