import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = ['buildAnalysisToolRefreshEvidencePackage'];
const enginePath = path.resolve('src/analysisToolRefreshEngine.ts');
const analysisToolRefreshEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof analysisToolRefreshEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `analysis-tool-refresh-engine: missing export(s): ${missingExports.join(', ')}`);

const secretSamples = [
  'analysis-search-token',
  'analysis-viewer-session',
  'analysis-sequencer-token',
  'analysis-decoder-key',
  'analysis-comparer-key',
  'analysis-logger-api-key',
  'analysis-organizer-passphrase',
];
const evidencePackage = analysisToolRefreshEngine.buildAnalysisToolRefreshEvidencePackage({
  generatedAt: '2026-05-26T18:15:00.000Z',
  searchPackage: packageFixture('analysis-search', 'proxyforge-search-parity-evidence-package', {
    fullTextSearchCovered: true,
    structuredPredicatesCovered: true,
    semanticRankingCovered: true,
    persistentIndexCovered: true,
    largeProjectSoakCovered: true,
    reportPhaseOnlyRedaction: true,
  }, 'GET /search?q=refund HTTP/1.1\nAuthorization: Bearer analysis-search-token\nfullTextSearchCovered semanticRankingCovered persistentIndexCovered largeProjectSoakCovered redact-only-during-report-export'),
  loggerPackage: packageFixture('analysis-logger', 'proxyforge-logger-parity-evidence-package', {
    toolGeneratedTrafficCovered: true,
    archiveImportExportCovered: true,
    archiveConflictDedupeCovered: true,
    customColumnPackageRefreshCovered: true,
    fullFidelityRawMaterialPreserved: true,
  }, 'POST /logger/import HTTP/1.1\nX-API-Key: analysis-logger-api-key\ncustom column packageRefresh toolGeneratedTrafficCovered archiveImportExportCovered archiveConflictDedupeCovered report-export-only redaction'),
  organizerPackage: packageFixture('analysis-organizer', 'proxyforge-organizer-parity-evidence-package', {
    collectionsCovered: true,
    passphraseSealedPackageCovered: true,
    conflictAuditCovered: true,
  }, 'GET /organizer/packages HTTP/1.1\nCookie: session=analysis-viewer-session\ncollectionsCovered passphraseSealedPackageCovered conflictAuditCovered reviewer sealed analysis-organizer-passphrase redact-only-during-report-export'),
  viewerPackage: packageFixture('analysis-viewer', 'proxyforge-viewer-parity-evidence-package', {
    rawViewCovered: true,
    prettyJsonViewCovered: true,
    graphqlViewCovered: true,
    replayComparisonExportsCovered: true,
    reportAttachmentCovered: true,
  }, 'GET /viewer/raw HTTP/1.1\nCookie: session=analysis-viewer-session\nrawViewCovered prettyJsonViewCovered graphqlViewCovered replayComparisonExportsCovered reportAttachmentCovered report-export-only'),
  sequencerPackage: packageFixture('analysis-sequencer', 'proxyforge-sequencer-parity-evidence-package', {
    tokenLocationExtractionCovered: true,
    largeSampleReliabilityCovered: true,
    fipsCapCovered: true,
    fullFidelityTokenSamplesPreserved: true,
  }, 'GET /sequencer/sample HTTP/1.1\nAuthorization: Bearer analysis-sequencer-token\ntokenLocationExtractionCovered largeSampleReliabilityCovered fipsCapCovered fullFidelityTokenSamplesPreserved redact-only-during-report-export'),
  decoderPackage: packageFixture('analysis-decoder', 'proxyforge-decoder-parity-evidence-package', {
    encodeDecodeHashFormatCovered: true,
    jweDecryptEditReencryptCovered: true,
    reportPhaseOnlyRedaction: true,
  }, 'POST /decoder/chain HTTP/1.1\nAuthorization: Bearer analysis-decoder-key\nencodeDecodeHashFormatCovered jweDecryptEditReencryptCovered transform golden reportPhaseOnlyRedaction'),
  comparerPackage: packageFixture('analysis-comparer', 'proxyforge-comparer-parity-evidence-package', {
    textDiffCovered: true,
    wordDiffCovered: true,
    byteDiffCovered: true,
    structuredHttpDiffCovered: true,
    normalizationPresetsCovered: true,
  }, 'POST /compare HTTP/1.1\nAuthorization: Bearer analysis-comparer-key\ntextDiff wordDiff byteDiff structuredHttpDiffCovered normalizationPresetsCovered report-export-only'),
  operationalSecretSamples: secretSamples,
});
const parsedContent = JSON.parse(evidencePackage.content);

assert.equal(evidencePackage.kind, 'proxyforge-analysis-tool-refresh-evidence-package');
assert.equal(evidencePackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(evidencePackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(evidencePackage.reportReady, true);
assert(Object.values(evidencePackage.requirements).every(Boolean), 'all Analysis tool refresh requirements should be true');
assert.equal(evidencePackage.packageRefreshProof.stalePackageIds.length, 0);
assert.equal(evidencePackage.packageRefreshProof.linkedPackageDigests.length, 7);
for (const kind of [
  'proxyforge-search-parity-evidence-package',
  'proxyforge-logger-parity-evidence-package',
  'proxyforge-organizer-parity-evidence-package',
  'proxyforge-viewer-parity-evidence-package',
  'proxyforge-sequencer-parity-evidence-package',
  'proxyforge-decoder-parity-evidence-package',
  'proxyforge-comparer-parity-evidence-package',
]) {
  assert(evidencePackage.linkedPackageKinds.includes(kind), `analysis refresh package should link ${kind}`);
}
for (const sample of secretSamples) {
  assert(evidencePackage.content.includes(sample), `analysis refresh package should preserve ${sample}`);
}
assert.equal(parsedContent.kind, 'proxyforge-analysis-tool-refresh-evidence-package');
assert.equal(parsedContent.linkedPackages.length, 7);
assert.match(evidencePackage.content, /redact-only-during-report-export|report-export-only/);
assert.match(evidencePackage.content, /Authorization: Bearer analysis-search-token/);
assert.match(evidencePackage.content, /Cookie: session=analysis-viewer-session/);

const artifactDir = path.resolve('.gitignored/test-artifacts/analysis-tool-refresh-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'analysis-tool-refresh-evidence-package.json'), evidencePackage.content);

console.log('analysis-tool-refresh-engine: exercised Search/Logger/Organizer/Viewer/Sequencer/Decoder/Comparer package-refresh digests, stale checks, and full-fidelity executor material');

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

function packageFixture(id, kind, requirements, markerText) {
  const content = JSON.stringify({
    id,
    kind,
    generatedAt: '2026-05-26T18:15:00.000Z',
    requirements,
    markerText,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  }, null, 2);
  return {
    id,
    kind,
    requirements,
    reportReady: true,
    content,
  };
}
