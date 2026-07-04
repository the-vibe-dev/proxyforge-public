import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';
import { buildReleaseTrustManifest, writeReleaseTrustManifest } from '../scripts/release-trust.mjs';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildReleaseTrustProductionEvidencePackage',
];
const enginePath = path.resolve('src/releaseTrustProductionEngine.ts');
const releaseTrustEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof releaseTrustEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `release-trust-production-engine: missing export(s): ${missingExports.join(', ')}`);

const generatedAt = '2026-05-26T06:55:00.000Z';
const trustManifest = await buildReleaseTrustManifest({ generatedAt });
const docs = [
  'OPERATOR_GUIDE requires proxyforge-release-trust-production-evidence-package with SBOM, checksums, provenance, signing pins, and report-export-only redaction.',
  'OPERATOR_GUIDE requires release trust evidence before Production Ready signoff and keeps operational raw material full fidelity.',
  'SCHEMAS.md documents proxyforge-release-trust-production-evidence-package requirements for agents.',
  'Operational submission/report artifacts redact only at redact-only-during-report-export.',
];
const rawRequest = [
  'POST /api/release-trust HTTP/2',
  'Host: app.shop.local',
  'Authorization: Bearer release-trust-secret-token',
  'Cookie: session=release-trust-session',
  'X-API-Key: release-trust-api-key',
  '',
  '{"rawRequest":true,"callbackToken":"release-trust-callback-token"}',
].join('\n');
const rawResponse = [
  'HTTP/2 200 OK',
  'Content-Type: application/json',
  '',
  '{"ok":true,"rawResponse":"release-trust"}',
].join('\n');
const context = {
  sbom: trustManifest.sbom,
  artifactDigests: trustManifest.artifactDigests,
  provenance: trustManifest.provenance,
  policy: trustManifest.policy,
  docs,
  generatedAt,
  operationalSecretSamples: [
    rawRequest,
    rawResponse,
    'Authorization: Bearer release-trust-secret-token',
    'session=release-trust-session',
    'X-API-Key: release-trust-api-key',
    'callbackToken=release-trust-callback-token',
  ],
};
const productionPackage = releaseTrustEngine.buildReleaseTrustProductionEvidencePackage(context);
const packageContent = JSON.parse(productionPackage.content);

assert.equal(trustManifest.kind, 'proxyforge-release-trust-manifest');
assert.equal(productionPackage.kind, 'proxyforge-release-trust-production-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, true);
assert(Object.values(productionPackage.requirements).every(Boolean), 'all Release Trust production requirements should be true');
assert.equal(packageContent.kind, 'proxyforge-release-trust-production-evidence-package');
assert.equal(packageContent.requirements.sbomGeneratedFromLockfile, true);
assert.equal(packageContent.requirements.provenanceStatementCovered, true);
assert.equal(packageContent.requirements.signingStatePinned, true);
assert.match(productionPackage.content, /proxyforge-release-trust-sbom/);
assert.match(productionPackage.content, /package-lock\.json/);
assert.match(productionPackage.content, /dist-electron\/headlessRunner\.js/);
assert.match(productionPackage.content, /docs\/agents\/SCHEMAS\.md/);
assert.match(productionPackage.content, /\.github\/workflows\/nightly-full-suite\.yml/);
assert.match(productionPackage.content, /slsa-provenance-lite/);
assert.match(productionPackage.content, /unsigned-local-build-pinned/);
assert.match(productionPackage.content, /npm run release:trust/);
assert.match(productionPackage.content, /Authorization: Bearer release-trust-secret-token/);
assert.match(productionPackage.content, /session=release-trust-session/);
assert.match(productionPackage.content, /X-API-Key: release-trust-api-key/);
assert.match(productionPackage.content, /callbackToken=release-trust-callback-token/);
assert.match(productionPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/release-trust-production-engine');
await fs.mkdir(artifactDir, { recursive: true });
await writeReleaseTrustManifest(trustManifest, artifactDir);
await fs.writeFile(path.join(artifactDir, 'release-trust-production-evidence-package.json'), productionPackage.content);

console.log('release-trust-production-engine: verified SBOM, checksums, provenance, signing pins, retention, and full-fidelity secret boundary');

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
