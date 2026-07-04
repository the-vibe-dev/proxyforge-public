import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildWindowsPackageProductionEvidencePackage',
];
const enginePath = path.resolve('src/windowsPackageProductionEngine.ts');
const windowsPackageEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof windowsPackageEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `windows-package-production-engine: missing export(s): ${missingExports.join(', ')}`);

const context = buildWindowsPackageContext();
const productionPackage = windowsPackageEngine.buildWindowsPackageProductionEvidencePackage(context);
const packageContent = JSON.parse(productionPackage.content);

assert.equal(productionPackage.kind, 'proxyforge-windows-package-production-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, false, 'fixture-backed Windows package schema evidence must not be release productionReady');
assert.equal(productionPackage.requirements.artifactBackedNativeArtifacts, false);
assert(Object.entries(productionPackage.requirements).every(([name, value]) => name === 'artifactBackedNativeArtifacts' ? value === false : value === true), 'only artifact-backed evidence requirement should be false for fixture schema coverage');
assert.equal(productionPackage.artifactCount, context.artifacts.length);
assert.equal(productionPackage.smokeCount, context.smokes.length);
assert.equal(packageContent.kind, 'proxyforge-windows-package-production-evidence-package');
assert.match(productionPackage.content, /ProxyForge Setup 0\.1\.0-alpha\.1\.exe/);
assert.match(productionPackage.content, /release\/win-unpacked\/ProxyForge\.exe/);
assert.match(productionPackage.content, /release\/ProxyForge 0\.1\.0-alpha\.1\.exe/);
assert.match(productionPackage.content, /release\/ProxyForge-0\.1\.0-alpha\.1-win\.zip/);
assert.match(productionPackage.content, /windows-installed-runtime-proxy-cert-oast-report/);
assert.match(productionPackage.content, /windows-packaged-dpapi-cookie/);
assert.match(productionPackage.content, /windows-trust-runner/);
assert.match(productionPackage.content, /ERROR_NOT_SUPPORTED/);
assert.match(productionPackage.content, /Authorization: Bearer windows-package-secret-token/);
assert.match(productionPackage.content, /session=windows-package-session/);
assert.match(productionPackage.content, /X-API-Key: windows-package-api-key/);
assert.match(productionPackage.content, /callbackToken=windows-package-callback-token/);
assert.match(productionPackage.content, /redact-only-during-report-export/);
assert.match(productionPackage.content, /Fixture\/schema evidence is blocked from productionReady/);

const artifactDir = path.resolve('.gitignored/test-artifacts/windows-package-production-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'windows-package-production-evidence-package.json'), productionPackage.content);

console.log('windows-package-production-engine: verified Windows package schema evidence, artifact-backed release gate, trust-store pin acceptance, and full-fidelity secret boundary');

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

function buildWindowsPackageContext() {
  const generatedAt = '2026-05-25T23:59:50.000Z';
  const rawRequest = [
    'GET /api/windows-package HTTP/1.1',
    'Host: app.shop.local',
    'Authorization: Bearer windows-package-secret-token',
    'Cookie: session=windows-package-session',
    'X-API-Key: windows-package-api-key',
    '',
    '',
  ].join('\r\n');
  const rawResponse = [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json',
    'Set-Cookie: callbackToken=windows-package-callback-token; HttpOnly',
    '',
    '{"ok":true,"rawResponse":"windows-package"}',
  ].join('\r\n');
  const artifact = (id, artifactType, artifactPath, builtOnWindows = true) => ({
    id,
    artifactType,
    path: artifactPath,
    sizeBytes: 104_100_228,
    sha256: `${id.replace(/[^a-z0-9]/gi, '')}sha256digest000000`,
    builtOnWindows,
    content: JSON.stringify({
      kind: 'proxyforge-windows-artifact-proof',
      artifactPath,
      builtOnWindows,
      notes: artifactType === 'win-zip' ? 'zip fallback hygiene: no resources/app.asar.unpacked, no rolldown, no lightningcss, no linux-x64, no vite' : 'native Windows artifact',
      rawRequest,
      rawResponse,
    }),
  });
  const smoke = (id, lane, status, passedChecks, blockedChecks, failedChecks, reason = '') => ({
    id,
    lane,
    status,
    runner: 'windows-trust-runner',
    passedChecks,
    blockedChecks,
    failedChecks,
    reason,
    content: JSON.stringify({
      kind: 'proxyforge-windows-package-smoke',
      id,
      lane,
      status,
      runner: 'windows-trust-runner',
      reason,
      checks: [
        'PROXYFORGE_RELEASE_SMOKE=1',
        'Windows Lane',
        'NSIS',
        'portable',
        'DPAPI',
        'release:smoke:windows',
        'Production Ready',
      ],
      rawRequest,
      rawResponse,
      redactionBoundary: 'redact-only-during-report-export',
    }),
  });

  return {
    generatedAt,
    artifacts: [
      artifact('windows-nsis', 'nsis', 'release/ProxyForge Setup 0.1.0-alpha.1.exe'),
      artifact('windows-portable', 'portable', 'release/ProxyForge 0.1.0-alpha.1.exe'),
      artifact('windows-unpacked', 'win-unpacked', 'release/win-unpacked/ProxyForge.exe'),
      artifact('windows-zip-fallback', 'win-zip', 'release/ProxyForge-0.1.0-alpha.1-win.zip', false),
    ],
    smokes: [
      smoke('windows-native-build', 'native-build', 'passed', 3, 0, 0),
      smoke('windows-unpacked-gui-launch', 'unpacked-gui', 'passed', 1, 0, 0),
      smoke('windows-nsis-install', 'nsis-install', 'passed', 1, 0, 0),
      smoke('windows-installed-gui-launch', 'installed-gui', 'passed', 1, 0, 0),
      smoke('windows-installed-headless-cli', 'installed-headless-cli', 'passed', 1, 0, 0),
      smoke('windows-installed-headless-scan-report', 'installed-headless-scan-report', 'passed', 4, 0, 0),
      smoke('windows-installed-runtime-proxy-cert-oast-report', 'installed-runtime-proxy-cert-oast-report', 'passed', 5, 0, 0),
      smoke('windows-packaged-browser-routing', 'browser-routing', 'passed', 1, 0, 0),
      smoke('windows-packaged-dpapi-cookie', 'dpapi-cookie', 'passed', 1, 0, 0),
      smoke('windows-installer-silent-uninstall', 'uninstall', 'passed', 1, 0, 0),
      smoke('windows-portable-wrapper-stdout', 'portable-wrapper', 'pinned-nonblocking', 0, 1, 0, 'Portable wrapper stdout is pinned; unpacked executable remains the counted GUI proof.'),
      smoke('windows-trust-store-pin', 'trust-store-browser', 'pinned-nonblocking', 7, 1, 0, 'windows-trust-runner rejects temporary Cert:\\CurrentUser\\Root mutation with ERROR_NOT_SUPPORTED; trust-store lane pinned nonblocking.'),
    ],
    releaseDocs: [
      'Windows Lane: NSIS portable DPAPI windows-trust-runner trust-store release:smoke:windows Production Ready.',
      'Windows package lane has browser-routing, DPAPI cookie, installed headless scan/report, installed runtime proxy/cert/OAST/report, quiet uninstall, and blocked trusted-CA lane pinned as nonblocking.',
    ],
    operationalSecretSamples: [
      'Authorization: Bearer windows-package-secret-token',
      'session=windows-package-session',
      'X-API-Key: windows-package-api-key',
      'callbackToken=windows-package-callback-token',
    ],
  };
}
