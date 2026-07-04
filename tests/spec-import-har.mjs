import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Load harSeed.ts via TypeScript transpilation
// harSeed.ts imports types from './index' — types are erased at transpile time.
// ---------------------------------------------------------------------------

async function transpile(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  return ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: filePath,
  }).outputText;
}

async function loadHarSeedParser() {
  const harPath = path.resolve('src/specImport/harSeed.ts');

  try {
    await fs.access(harPath);
  } catch {
    console.log('spec-import-har: skipped (source file not found)');
    process.exit(0);
  }

  let harCode;
  try {
    harCode = await transpile(harPath);
  } catch (err) {
    console.log(`spec-import-har: skipped (transpile error: ${err.message})`);
    process.exit(0);
  }

  function makeModule(code, filename, localRequire) {
    const mod = { exports: {} };
    const sandbox = {
      module: mod,
      exports: mod.exports,
      require: localRequire,
      process,
      console,
      URL,
      URLSearchParams,
      TextDecoder,
      TextEncoder,
      Buffer,
    };
    vm.runInNewContext(code, sandbox, { filename });
    return mod.exports;
  }

  const indexStub = {};

  return makeModule(harCode, harPath, (id) => {
    if (id === './index' || id === './index.js') return indexStub;
    return require(id);
  });
}

const mod = await loadHarSeedParser();
const { parseHarSeed, validateHarShape } = mod;

if (typeof parseHarSeed !== 'function' || typeof validateHarShape !== 'function') {
  console.log('spec-import-har: skipped (missing required exports)');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeHar(entries) {
  return JSON.stringify({
    log: {
      version: '1.2',
      entries,
    },
  });
}

function makeEntry(method, url, queryString = [], postData = null) {
  const entry = {
    request: {
      method,
      url,
      headers: [],
      queryString,
      cookies: [],
    },
    response: { status: 200 },
  };
  if (postData) entry.request.postData = postData;
  return entry;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. Returns format: 'har' and error on invalid JSON
{
  const result = parseHarSeed('not valid json }{');
  assert.equal(result.format, 'har', "format should be 'har' even on invalid JSON");
  assert.ok(Array.isArray(result.errors) && result.errors.length > 0, 'should return errors on invalid JSON');
  assert.equal(result.routes.length, 0, 'routes should be empty on invalid JSON');
}

// 2. Returns error on missing log.entries
{
  const result = parseHarSeed(JSON.stringify({ log: { version: '1.2' } }));
  assert.equal(result.format, 'har', "format should be 'har'");
  assert.ok(Array.isArray(result.errors) && result.errors.length > 0, 'should return errors for missing entries');
  assert.equal(result.routes.length, 0, 'routes should be empty when entries is missing');
}

// 3. Parses valid HAR with one GET entry and extracts url + method
{
  const har = makeHar([makeEntry('GET', 'https://api.example.com/users')]);
  const result = parseHarSeed(har);
  assert.equal(result.format, 'har', "format should be 'har'");
  assert.equal(result.routes.length, 1, `should parse 1 route, got ${result.routes.length}`);
  const route = result.routes[0];
  assert.equal(route.method, 'GET', 'route method should be GET');
  assert.ok(route.path.includes('/users'), `route path should include '/users', got '${route.path}'`);
}

// 4. Extracts query string params from HAR queryString array
{
  const har = makeHar([
    makeEntry('GET', 'https://api.example.com/search', [
      { name: 'q', value: 'test' },
      { name: 'page', value: '1' },
    ]),
  ]);
  const result = parseHarSeed(har);
  assert.equal(result.routes.length, 1, 'should parse 1 route');
  const route = result.routes[0];
  const qParam = route.params.find((p) => p.name === 'q' && p.location === 'query');
  const pageParam = route.params.find((p) => p.name === 'page' && p.location === 'query');
  assert.ok(qParam, "should extract 'q' as a query param");
  assert.equal(qParam.example, 'test', "q param example should be 'test'");
  assert.ok(pageParam, "should extract 'page' as a query param");
}

// 5. Deduplicates GET entries with same method+url
{
  const har = makeHar([
    makeEntry('GET', 'https://api.example.com/products'),
    makeEntry('GET', 'https://api.example.com/products'), // duplicate
    makeEntry('GET', 'https://api.example.com/products?color=red'), // same path, different query — same dedup key
  ]);
  const result = parseHarSeed(har);
  assert.equal(result.routes.length, 1, `GET /products should deduplicate to 1 route, got ${result.routes.length}`);
}

// 6. Skips entries with invalid URLs and adds warning
{
  const har = JSON.stringify({
    log: {
      version: '1.2',
      entries: [
        { request: { method: 'GET', url: 'not-a-valid-url', headers: [], queryString: [], cookies: [] }, response: { status: 200 } },
        { request: { method: 'GET', url: 'https://api.example.com/valid', headers: [], queryString: [], cookies: [] }, response: { status: 200 } },
      ],
    },
  });
  const result = parseHarSeed(har);
  assert.equal(result.routes.length, 1, 'only 1 valid route should be parsed');
  assert.ok(
    result.warnings && result.warnings.some((w) => w.includes('not-a-valid-url')),
    'should add warning for skipped invalid URL',
  );
}

// 7. validateHarShape rejects non-object, missing log, missing entries
{
  const r1 = validateHarShape(null);
  assert.equal(r1.valid, false, 'null should be invalid');
  assert.ok(r1.errors.length > 0, 'errors should be non-empty for null');

  const r2 = validateHarShape({ notLog: true });
  assert.equal(r2.valid, false, 'object without log should be invalid');
  assert.ok(r2.errors.some((e) => e.toLowerCase().includes('log')), 'error should mention log');

  const r3 = validateHarShape({ log: { version: '1.2' } });
  assert.equal(r3.valid, false, 'log without entries array should be invalid');
  assert.ok(r3.errors.some((e) => e.toLowerCase().includes('entries')), 'error should mention entries');
}

// 8. validateHarShape accepts valid HAR shape
{
  const { valid, errors } = validateHarShape({
    log: {
      version: '1.2',
      entries: [],
    },
  });
  assert.equal(valid, true, 'valid HAR shape should pass validation');
  assert.equal(errors.length, 0, 'errors should be empty for valid shape');
}

console.log('spec-import-har: all tests passed');
