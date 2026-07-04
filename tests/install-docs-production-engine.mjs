import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildInstallDocsProductionEvidencePackage',
];
const enginePath = path.resolve('src/installDocsProductionEngine.ts');
const installDocsEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof installDocsEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `install-docs-production-engine: missing export(s): ${missingExports.join(', ')}`);

const context = await buildInstallDocsContext();
const productionPackage = installDocsEngine.buildInstallDocsProductionEvidencePackage(context);
const packageContent = JSON.parse(productionPackage.content);

assert.equal(productionPackage.kind, 'proxyforge-install-docs-production-evidence-package');
assert.equal(productionPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(productionPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(productionPackage.productionReady, true);
assert(Object.values(productionPackage.requirements).every(Boolean), 'all Install Docs production requirements should be true');
assert.equal(productionPackage.documentCount, context.documents.length);
assert.equal(productionPackage.packagedDocumentCount, context.documents.length);
assert.equal(packageContent.kind, 'proxyforge-install-docs-production-evidence-package');
assert.match(productionPackage.content, /docs\/INSTALL_LINUX_WINDOWS\.md/);
assert.match(productionPackage.content, /docs\/OPERATOR_GUIDE\.md/);
assert.match(productionPackage.content, /docs\/RELEASE_CHECKLIST\.md/);
assert.match(productionPackage.content, /docs\/RELEASE_EVIDENCE\.md/);
assert.match(productionPackage.content, /docs\/agents\/SCHEMAS\.md/);
assert.match(productionPackage.content, /release:smoke:linux/);
assert.match(productionPackage.content, /release:smoke:windows/);
assert.match(productionPackage.content, /windows-trust-runner|windows-trust-runner/);
assert.match(productionPackage.content, /repeater-race-run/);
assert.match(productionPackage.content, /Authorization: Bearer install-docs-secret-token/);
assert.match(productionPackage.content, /session=install-docs-session/);
assert.match(productionPackage.content, /X-API-Key: install-docs-api-key/);
assert.match(productionPackage.content, /callbackToken=install-docs-callback-token/);
assert.match(productionPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/install-docs-production-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'install-docs-production-evidence-package.json'), productionPackage.content);

console.log('install-docs-production-engine: verified packaged install/operator docs, release evidence sync, and full-fidelity secret boundary');

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

async function buildInstallDocsContext() {
  const packageJson = JSON.parse(await fs.readFile(path.resolve('package.json'), 'utf8'));
  const documentPaths = [
    ['install-guide', 'docs/INSTALL_LINUX_WINDOWS.md', 'Linux and Windows install guide'],
    ['operator-guide', 'docs/OPERATOR_GUIDE.md', 'Operator guide'],
    ['release-checklist', 'docs/RELEASE_CHECKLIST.md', 'Release checklist'],
    ['release-evidence', 'docs/RELEASE_EVIDENCE.md', 'Release evidence'],
    ['agent-schema', 'docs/agents/SCHEMAS.md', 'Agent schemas'],
    ['agent-codex', 'docs/agents/CODEX.md', 'Codex agent guide'],
    ['agent-claude', 'docs/agents/CLAUDE.md', 'Claude agent guide'],
    ['agent-vantix', 'docs/agents/VANTIX.md', 'Vantix agent guide'],
  ];
  const packageFiles = packageJson.build?.files ?? [];
  return {
    documents: await Promise.all(documentPaths.map(async ([id, documentPath, title]) => ({
      id,
      path: documentPath,
      title,
      content: await fs.readFile(path.resolve(documentPath), 'utf8'),
      packaged: packageFiles.includes(documentPath) || packageFiles.some((pattern) => pattern === 'docs/agents/**/*' && documentPath.startsWith('docs/agents/')),
    }))),
    packageFiles,
    packageScripts: packageJson.scripts ?? {},
    generatedAt: '2026-05-25T23:59:40.000Z',
    operationalSecretSamples: [
      'Authorization: Bearer install-docs-secret-token',
      'Cookie: session=install-docs-session',
      'X-API-Key: install-docs-api-key',
      'callbackToken=install-docs-callback-token',
    ],
  };
}
