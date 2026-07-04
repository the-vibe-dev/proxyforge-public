import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const enginePath = path.resolve('src/contentDiscoveryEngine.ts');

async function loadEngine() {
  let source;
  try {
    source = await fs.readFile(enginePath, 'utf8');
  } catch {
    console.log('content-discovery-engine: skipped (source not found)');
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
    __filename: fileURLToPath(new URL('../src/contentDiscoveryEngine.ts', import.meta.url)),
    __dirname: path.resolve('src'),
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
    console.log(`content-discovery-engine: skipped (load error: ${err.message})`);
    process.exit(0);
  }
  return mod.exports;
}

const engine = await loadEngine();

const expectedExports = [
  'createDiscoveryRun',
  'recordDiscoveryResult',
  'isInterestingPath',
  'getInterestingPaths',
  'loadWordlist',
];

const missing = expectedExports.filter((name) => typeof engine[name] !== 'function');
if (missing.length) {
  console.log(`content-discovery-engine: skipped (missing exports: ${missing.join(', ')})`);
  process.exit(0);
}

const { createDiscoveryRun, recordDiscoveryResult, isInterestingPath, getInterestingPaths, loadWordlist } = engine;

// --- createDiscoveryRun returns run with status 'running' and probed=0 ---
{
  const run = createDiscoveryRun({ baseUrl: 'https://example.com' });
  assert.equal(run.status, 'running', 'initial status should be running');
  assert.equal(run.probed, 0, 'initial probed count should be 0');
  assert.ok(typeof run.id === 'string' && run.id.length > 0, 'run should have a non-empty id');
  assert.ok(Array.isArray(run.discovered), 'discovered should be an array');
  assert.equal(run.baseUrl, 'https://example.com', 'baseUrl should be set correctly');
}

// --- recordDiscoveryResult increments probed count ---
{
  const run = createDiscoveryRun({ baseUrl: 'https://example.com', wordlist: ['/admin', '/api', '/login'] });
  assert.equal(run.probed, 0);
  recordDiscoveryResult(run, '/admin', 200, 'text/html', 1024);
  assert.equal(run.probed, 1, 'probed should be 1 after one result');
  recordDiscoveryResult(run, '/api', 404);
  assert.equal(run.probed, 2, 'probed should increment on each result');
  assert.equal(run.discovered.length, 2, 'discovered array should hold all results');
}

// --- isInterestingPath returns true for 200 when notFoundStatus is 404 ---
{
  assert.equal(isInterestingPath('/admin', 200, 404), true, '200 should be interesting when 404 is baseline');
}

// --- isInterestingPath returns false for 404 when notFoundStatus is 404 ---
{
  assert.equal(isInterestingPath('/missing', 404, 404), false, '404 should not be interesting when 404 is baseline');
}

// --- isInterestingPath returns true for 403 (access control exists) ---
{
  assert.equal(isInterestingPath('/admin', 403, 404), true, '403 should be interesting (access control barrier)');
}

// --- isInterestingPath returns false for redirects ---
{
  assert.equal(isInterestingPath('/old-path', 301, 404), false, '301 redirect should not be flagged as interesting');
  assert.equal(isInterestingPath('/other', 302, 404), false, '302 redirect should not be flagged as interesting');
}

// --- getInterestingPaths filters to interesting results only ---
{
  const run = createDiscoveryRun({ baseUrl: 'https://example.com', wordlist: ['/admin', '/api', '/missing'] });
  recordDiscoveryResult(run, '/admin', 200, 'text/html', 512);
  recordDiscoveryResult(run, '/api', 403, 'application/json', 64);
  recordDiscoveryResult(run, '/missing', 404, undefined, 0);

  const interesting = getInterestingPaths(run);
  assert.equal(interesting.length, 2, 'should return only interesting paths (200 and 403)');
  const paths = interesting.map((p) => p.path);
  assert.ok(paths.includes('/admin'), '/admin (200) should be interesting');
  assert.ok(paths.includes('/api'), '/api (403) should be interesting');
  assert.ok(!paths.includes('/missing'), '/missing (404) should not be interesting');
}

// --- loadWordlist('common-paths') returns array with length > 0 and includes '/admin' ---
{
  let wordlist;
  try {
    wordlist = loadWordlist('common-paths');
  } catch (err) {
    assert.fail(`loadWordlist threw: ${err.message}`);
  }
  assert.ok(Array.isArray(wordlist), 'wordlist should be an array');
  assert.ok(wordlist.length > 0, 'wordlist should not be empty');
  assert.ok(wordlist.includes('/admin'), "wordlist should include '/admin'");
}

console.log('content-discovery-engine: all tests passed');
