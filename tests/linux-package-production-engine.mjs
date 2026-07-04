import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildLinuxPackageProductionEvidencePackage',
];
const enginePath = path.resolve('src/linuxPackageProductionEngine.ts');
const linuxPackageEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof linuxPackageEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `linux-package-production-engine: missing export(s): ${missingExports.join(', ')}`);

const context = buildLinuxPackageContext();
const productionPackage = linuxPackageEngine.buildLinuxPackageProductionEvidencePackage(context);
const packageContent = JSON.parse(productionPackage.content);

assert.equal(productionPackage.kind, 'proxyforge-linux-package-production-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, false, 'fixture-backed Linux package schema evidence must not be release productionReady');
assert.equal(productionPackage.requirements.artifactBackedNativeArtifacts, false);
assert(Object.entries(productionPackage.requirements).every(([name, value]) => name === 'artifactBackedNativeArtifacts' ? value === false : value === true), 'only artifact-backed evidence requirement should be false for fixture schema coverage');
assert.equal(productionPackage.artifactCount, context.artifacts.length);
assert.equal(productionPackage.smokeCount, context.smokes.length);
assert.equal(packageContent.kind, 'proxyforge-linux-package-production-evidence-package');
assert.match(productionPackage.content, /ProxyForge-0\.1\.0-alpha\.1\.AppImage/);
assert.match(productionPackage.content, /proxyforge_0\.1\.0-alpha\.1_amd64\.deb/);
assert.match(productionPackage.content, /release\/linux-unpacked\/proxyforge/);
assert.match(productionPackage.content, /release-deb-container-smoke/);
assert.match(productionPackage.content, /clean-container-trusted-ca-browser/);
assert.match(productionPackage.content, /without --ignore-certificate-errors/);
assert.match(productionPackage.content, /packaged-agent-external-cwd/);
assert.match(productionPackage.content, /Authorization: Bearer linux-package-secret-token/);
assert.match(productionPackage.content, /session=linux-package-session/);
assert.match(productionPackage.content, /X-API-Key: linux-package-api-key/);
assert.match(productionPackage.content, /callbackToken=linux-package-callback-token/);
assert.match(productionPackage.content, /redact-only-during-report-export/);
assert.match(productionPackage.content, /Fixture\/schema evidence is blocked from productionReady/);

const artifactDir = path.resolve('.gitignored/test-artifacts/linux-package-production-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'linux-package-production-evidence-package.json'), productionPackage.content);

console.log('linux-package-production-engine: verified Linux package schema evidence, artifact-backed release gate, clean-container trusted-CA smokes, and full-fidelity secret boundary');

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

function buildLinuxPackageContext() {
  const generatedAt = '2026-05-25T23:59:55.000Z';
  const rawRequest = [
    'GET /api/linux-package HTTP/1.1',
    'Host: app.shop.local',
    'Authorization: Bearer linux-package-secret-token',
    'Cookie: session=linux-package-session',
    'X-API-Key: linux-package-api-key',
    '',
    '',
  ].join('\r\n');
  const rawResponse = [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json',
    'Set-Cookie: callbackToken=linux-package-callback-token; HttpOnly',
    '',
    '{"ok":true,"rawResponse":"linux-package"}',
  ].join('\r\n');
  const artifact = (id, artifactType, artifactPath, sizeBytes) => ({
    id,
    artifactType,
    path: artifactPath,
    sizeBytes,
    sha256: `${id.replace(/[^a-z0-9]/gi, '')}sha256digest000000`,
    content: JSON.stringify({
      kind: 'proxyforge-linux-artifact-proof',
      artifactPath,
      artifactType,
      rawRequest,
      rawResponse,
    }),
  });
  const smoke = (id, lane, status, passedChecks, failedChecks, reason = '') => ({
    id,
    lane,
    status,
    runner: 'linux-clean-container',
    passedChecks,
    failedChecks,
    reason,
    content: JSON.stringify({
      kind: 'proxyforge-linux-package-smoke',
      id,
      lane,
      status,
      runner: 'linux-clean-container',
      reason,
      checks: [
        'Linux Lane',
        'AppImage',
        'deb',
        'release:smoke:linux',
        'release-deb-container-smoke',
        'browser-trust-store',
        'PROXYFORGE_RELEASE_SMOKE=1',
        'Package: proxyforge',
        'Version: 0.1.0-alpha.1',
        'Architecture: amd64',
        'libgbm1',
        'libasound2',
        'NSS trust store',
        'trusted-CA',
        'certificateMode: trusted-ca',
        'without --ignore-certificate-errors',
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
      artifact('linux-appimage', 'appimage', 'release/ProxyForge-0.1.0-alpha.1.AppImage', 126_286_149),
      artifact('linux-deb', 'deb', 'release/proxyforge_0.1.0-alpha.1_amd64.deb', 98_174_848),
      artifact('linux-unpacked', 'linux-unpacked', 'release/linux-unpacked/proxyforge', 210_091_224),
    ],
    smokes: [
      smoke('linux-native-build', 'native-build', 'passed', 3, 0),
      smoke('linux-appimage-node-runtime', 'appimage-node-runtime', 'passed', 1, 0),
      smoke('linux-appimage-gui', 'appimage-gui', 'passed', 1, 0),
      smoke('linux-unpacked-node-runtime', 'unpacked-node-runtime', 'passed', 1, 0),
      smoke('linux-unpacked-gui', 'unpacked-gui', 'passed', 1, 0),
      smoke('linux-deb-metadata', 'deb-metadata', 'passed', 1, 0),
      smoke('linux-packaged-headless-cli', 'packaged-headless-cli', 'passed', 1, 0),
      smoke('linux-packaged-headless-scan-report', 'packaged-headless-scan-report', 'passed', 4, 0),
      smoke('linux-packaged-agent-cli', 'packaged-agent-cli', 'passed', 1, 0),
      smoke('linux-packaged-agent-external-cwd', 'packaged-agent-external-cwd', 'passed', 1, 0),
      smoke('linux-packaged-runtime-proxy-cert-oast-report', 'packaged-runtime-proxy-cert-oast-report', 'passed', 5, 0),
      smoke('linux-packaged-browser-routing', 'packaged-browser-routing', 'passed', 1, 0),
      smoke('linux-clean-container-deb-install', 'clean-container-deb-install', 'passed', 1, 0),
      smoke('linux-clean-container-runtime', 'clean-container-runtime', 'passed', 1, 0),
      smoke('linux-clean-container-gui', 'clean-container-gui', 'passed', 1, 0),
      smoke('linux-clean-container-trusted-ca-browser', 'clean-container-trusted-ca-browser', 'passed', 2, 0),
      smoke('linux-clean-container-uninstall', 'clean-container-uninstall', 'passed', 2, 0),
      smoke('linux-known-warning-pin', 'known-warning', 'pinned-nonblocking', 0, 0, 'Chromium GPU command-buffer warning under Xvfb and Docker unshare failed postinstall sandbox warning are pinned nonblocking after structured smokes passed.'),
    ],
    releaseDocs: [
      'Linux Lane: AppImage deb release:smoke:linux release-deb-container-smoke browser-trust-store Production Ready.',
      'Linux package lane has build, install, runtime, browser-routing, trusted-CA, packaged headless scan/report, packaged agent, packaged runtime proxy/cert/OAST/report, and report export proof.',
    ],
    operationalSecretSamples: [
      'Authorization: Bearer linux-package-secret-token',
      'session=linux-package-session',
      'X-API-Key: linux-package-api-key',
      'callbackToken=linux-package-callback-token',
    ],
  };
}
