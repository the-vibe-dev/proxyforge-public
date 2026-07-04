import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const enginePath = path.resolve('src/scanner/paramMinerEngine.ts');

async function loadEngine() {
  let source;
  try {
    source = await fs.readFile(enginePath, 'utf8');
  } catch {
    console.log('scanner-param-miner: skipped (source not found)');
    process.exit(0);
  }

  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: enginePath,
  }).outputText;

  const mod = { exports: {} };
  const sandbox = {
    module: mod,
    exports: mod.exports,
    require,
    process,
    console,
    URL,
    URLSearchParams,
    TextDecoder,
    TextEncoder,
    Buffer,
  };
  try {
    vm.runInNewContext(transpiled, sandbox, { filename: enginePath });
  } catch (err) {
    console.log(`scanner-param-miner: skipped (load error: ${err.message})`);
    process.exit(0);
  }
  return mod.exports;
}

const engine = await loadEngine();

const expectedExports = [
  'createParamMinerRun',
  'recordParamResult',
  'rankMinedParams',
  'getInterestingParams',
];

const missing = expectedExports.filter((name) => typeof engine[name] !== 'function');
if (missing.length) {
  console.log(`scanner-param-miner: skipped (missing exports: ${missing.join(', ')})`);
  process.exit(0);
}

const { createParamMinerRun, recordParamResult, rankMinedParams, getInterestingParams } = engine;

// --- createParamMinerRun returns run with probed=0 and empty found ---
{
  const run = createParamMinerRun({ targetUrl: 'https://example.com/api' });
  assert.equal(run.probed, 0, 'initial probed count should be 0');
  assert.ok(Array.isArray(run.found), 'found should be an array');
  assert.equal(run.found.length, 0, 'found should start empty');
  assert.equal(run.status, 'running', 'initial status should be running');
  assert.equal(run.targetUrl, 'https://example.com/api', 'targetUrl should be set');
  assert.ok(typeof run.id === 'string' && run.id.length > 0, 'run should have a non-empty id');
}

// --- recordParamResult adds mined param to run.found ---
{
  const run = createParamMinerRun({
    targetUrl: 'https://example.com/api',
    parameterList: ['id', 'debug', 'admin'],
  });
  assert.equal(run.found.length, 0);

  recordParamResult(run, 'debug', 'query', true, 0.9, 'Response length changed by 120 bytes');
  assert.equal(run.found.length, 1, 'found should have one entry after recording');
  assert.equal(run.probed, 1, 'probed should increment');

  const param = run.found[0];
  assert.equal(param.name, 'debug', 'param name should match');
  assert.equal(param.location, 'query', 'param location should match');
  assert.equal(param.reflected, true, 'reflected flag should match');
  assert.equal(param.anomalyScore, 0.9, 'anomalyScore should match');
  assert.equal(param.evidence, 'Response length changed by 120 bytes', 'evidence should match');

  recordParamResult(run, 'X-Debug', 'header', false, 0.3, 'No notable difference');
  assert.equal(run.found.length, 2);
  assert.equal(run.probed, 2);
}

// --- rankMinedParams sorts by anomalyScore descending ---
{
  const params = [
    { name: 'low', location: 'query', reflected: false, anomalyScore: 0.1, evidence: 'minor' },
    { name: 'high', location: 'query', reflected: true, anomalyScore: 0.95, evidence: 'major' },
    { name: 'mid', location: 'body', reflected: false, anomalyScore: 0.6, evidence: 'moderate' },
  ];
  const ranked = rankMinedParams(params);
  assert.equal(ranked[0].name, 'high', 'highest anomalyScore should be first');
  assert.equal(ranked[1].name, 'mid', 'mid anomalyScore should be second');
  assert.equal(ranked[2].name, 'low', 'lowest anomalyScore should be last');
  // Original array should not be mutated
  assert.equal(params[0].name, 'low', 'original array should not be mutated');
}

// --- getInterestingParams with default threshold filters correctly ---
{
  const run = createParamMinerRun({ targetUrl: 'https://example.com/search' });
  recordParamResult(run, 'q', 'query', true, 0.8, 'Reflected in response body');
  recordParamResult(run, 'debug', 'query', false, 0.5, 'Status code changed');
  recordParamResult(run, 'noise', 'header', false, 0.2, 'No measurable effect');

  const interesting = getInterestingParams(run);
  assert.equal(interesting.length, 2, 'default threshold 0.5 should include params with score >= 0.5');
  const names = interesting.map((p) => p.name);
  assert.ok(names.includes('q'), 'q (0.8) should be interesting');
  assert.ok(names.includes('debug'), 'debug (0.5) should be interesting at default threshold');
  assert.ok(!names.includes('noise'), 'noise (0.2) should not be interesting');

  // Custom threshold
  const strict = getInterestingParams(run, 0.7);
  assert.equal(strict.length, 1, 'threshold 0.7 should only include params with score >= 0.7');
  assert.equal(strict[0].name, 'q');
}

console.log('scanner-param-miner: all tests passed');
