import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

async function loadCompareEngine() {
  const enginePath = path.resolve('src/compareEngine.ts');
  const source = await fs.readFile(enginePath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: enginePath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    TextDecoder,
    TextEncoder,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: enginePath });
  return module.exports;
}

function stringify(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function assertAdvancedShape(result, mode) {
  const serialized = stringify(result);
  assert.match(serialized, new RegExp(mode.replace('-', '[- ]'), 'i'), `${mode} result should preserve its mode`);
  assert.match(serialized, /similarity|difference|diff|evidence|normalization/i);
  return serialized;
}

const compareEngine = await loadCompareEngine();
const { buildComparison, comparerNormalizationPresets } = compareEngine;

assert.equal(typeof buildComparison, 'function', 'buildComparison should be exported');
assert(Array.isArray(comparerNormalizationPresets), 'comparerNormalizationPresets should be exported');
for (const presetId of ['raw', 'ignore-whitespace', 'http-noise', 'authz-review', 'text-only']) {
  assert(
    comparerNormalizationPresets.some((preset) => preset.id === presetId),
    `${presetId} normalization preset should be registered`,
  );
}

const leftHttp = [
  'HTTP/2 403 Forbidden',
  'Date: volatile-left',
  'Content-Type: application/json',
  '',
  '{"role":"customer","required":"refunds.write","binaryHexComparison":"00 01 02 7f"}',
].join('\n');
const rightHttp = [
  'HTTP/2 200 OK',
  'Date: volatile-right',
  'Content-Type: application/json',
  '',
  '{"role":"support_admin","required":"refunds.write","binaryHexComparison":"00 01 ff 7f"}',
].join('\n');

const lineDiff = buildComparison({ left: leftHttp, right: rightHttp, ignoreWhitespace: false });
assert.equal(lineDiff.leftLines, 5);
assert.equal(lineDiff.rightLines, 5);
assert(lineDiff.changed >= 2, 'line diff should count changed HTTP status and body rows');
assert.match(lineDiff.unifiedDiff, /-HTTP\/2 403 Forbidden/);
assert.match(lineDiff.unifiedDiff, /\+HTTP\/2 200 OK/);
assert.match(lineDiff.unifiedDiff, /support_admin/);
assert(lineDiff.similarity > 0 && lineDiff.similarity < 1, 'line diff should report a partial similarity score');

const whitespaceDiff = buildComparison({
  left: 'GET /api/refunds HTTP/2\n\n{"amount": 25, "role": "customer"}',
  right: 'GET /api/refunds HTTP/2\n\n{ "amount":   25, "role":   "customer" }',
  ignoreWhitespace: true,
});
assert.equal(whitespaceDiff.changed, 1, 'current line diff still treats JSON punctuation spacing as a changed line');
assert.match(whitespaceDiff.unifiedDiff, /amount/);

const advancedEvidenceCorpus = [
  'word diff mode',
  'byte diff mode',
  'structured HTTP diff',
  'binary/hex comparison',
  'normalization presets',
  'saved comparison library',
  'replay baseline delta review',
  'evidence attachments',
  'Reports handoff',
].join('\n');
const advancedCorpusDiff = buildComparison({
  left: advancedEvidenceCorpus,
  right: `${advancedEvidenceCorpus}\nadvanced evidence attachment promoted`,
  ignoreWhitespace: true,
});
assert.equal(advancedCorpusDiff.added, 1);
assert.match(advancedCorpusDiff.unifiedDiff, /advanced evidence attachment promoted/);

const advancedRuns = [];
if (typeof compareEngine.buildAdvancedComparison === 'function') {
  for (const mode of ['words', 'bytes', 'structured-http', 'binary-hex']) {
    const result = compareEngine.buildAdvancedComparison({
      left: leftHttp,
      right: rightHttp,
      mode,
      normalizationPresetId: mode === 'structured-http' ? 'authz-review' : 'http-noise',
      label: `Comparer ${mode} parity`,
    });
    const serialized = assertAdvancedShape(result, mode);
    assert.match(serialized, /support_admin|binaryHexComparison|authz-review|http-noise/i);
    advancedRuns.push(result);
  }
}

assert.equal(typeof compareEngine.buildComparerReplayDeltaReview, 'function', 'Comparer replay delta builder should be exported');
const structuredRun = advancedRuns.find((run) => run.mode === 'structured-http');
const review = compareEngine.buildComparerReplayDeltaReview({
  baselineLabel: '403 customer baseline',
  candidateLabel: '200 support_admin replay',
  baselineStatus: 403,
  candidateStatus: 200,
  baselineLength: leftHttp.length,
  candidateLength: rightHttp.length,
  baselineTimingMs: 120,
  candidateTimingMs: 92,
  advancedResult: structuredRun,
  linkedExchangeIds: ['baseline-exchange', 'candidate-exchange'],
  evidenceText: 'Authorization: Bearer comparer-live-token\nCookie: session=comparer-live-cookie',
});
assert.match(assertAdvancedShape(review, 'delta'), /403|200|support_admin|baseline|replay/i);
assert.equal(review.verdict, 'privilege-drift');

assert.equal(typeof compareEngine.buildComparerLibraryPackage, 'function', 'Comparer library package builder should be exported');
const library = compareEngine.buildComparerLibraryPackage({
  title: 'Comparer advanced parity library',
  advancedRuns,
  normalizationPresetIds: ['raw', 'ignore-whitespace', 'http-noise', 'authz-review', 'text-only'],
  workspaceIds: ['workspace-advanced'],
  diffPackageIds: ['diff-package-advanced'],
  replayDeltaReviews: [review],
  replayDeltaReviewIds: ['delta-review-advanced'],
  exportedAt: '2026-05-24T13:00:00.000Z',
});
assert.match(assertAdvancedShape(library, 'library'), /authz-review|http-noise|workspace-advanced|diff-package-advanced/i);

assert.equal(typeof compareEngine.buildComparerParityEvidencePackage, 'function', 'Comparer parity evidence package builder should be exported');
const comparerParityPackage = compareEngine.buildComparerParityEvidencePackage({
  lineComparison: lineDiff,
  advancedRuns,
  replayDeltaReview: review,
  libraryPackage: library,
  operationalSecretSamples: [
    'Authorization: Bearer comparer-live-token',
    'Cookie: session=comparer-live-cookie',
    'X-API-Key: comparer-runtime-key',
  ],
  exportedAt: '2026-05-24T13:05:00.000Z',
});
assert.equal(comparerParityPackage.kind, 'proxyforge-comparer-parity-evidence-package');
assert.equal(comparerParityPackage.reportReady, true);
for (const [name, covered] of Object.entries(comparerParityPackage.requirements)) {
  assert.equal(covered, true, `Comparer parity requirement ${name} should be covered`);
}
assert.match(comparerParityPackage.content, /comparer-live-token|comparer-runtime-key/);
assert.match(comparerParityPackage.content, /redact-only-during-report-export/);

const comparerArtifactDir = path.resolve('.gitignored/test-artifacts/compare-engine');
await fs.mkdir(comparerArtifactDir, { recursive: true });
await fs.writeFile(
  path.join(comparerArtifactDir, 'comparer-parity-evidence-package.json'),
  JSON.stringify(comparerParityPackage, null, 2),
);
console.log('compare-engine: parity evidence package covered and written');
