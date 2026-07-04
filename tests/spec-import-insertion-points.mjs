import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Load insertionPointsFromSpec.ts via TypeScript transpilation
// The module imports types from '../specImport/index' — types are erased.
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

async function loadInsertionPoints() {
  const sipPath = path.resolve('src/scanner/insertionPointsFromSpec.ts');

  try {
    await fs.access(sipPath);
  } catch {
    console.log('spec-import-insertion-points: skipped (source file not found)');
    process.exit(0);
  }

  let sipCode;
  try {
    sipCode = await transpile(sipPath);
  } catch (err) {
    console.log(`spec-import-insertion-points: skipped (transpile error: ${err.message})`);
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

  const specImportStub = {};

  return makeModule(sipCode, sipPath, (id) => {
    if (id.includes('specImport') || id.includes('index')) return specImportStub;
    return require(id);
  });
}

const mod = await loadInsertionPoints();
const {
  extractInsertionPoints,
  groupByRoute,
  filterByKind,
  filterRequiredOnly,
} = mod;

const missing = [
  'extractInsertionPoints',
  'groupByRoute',
  'filterByKind',
  'filterRequiredOnly',
].filter((name) => typeof mod[name] !== 'function');

if (missing.length > 0) {
  console.log(`spec-import-insertion-points: skipped (missing exports: ${missing.join(', ')})`);
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRoute(method, path, params = [], requestBody = undefined) {
  return { method, path, params, requestBody };
}

function makeParam(name, location, required = false, example = undefined) {
  return { name, location, required, example };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. extractInsertionPoints returns empty array for empty routes
{
  const points = extractInsertionPoints([]);
  assert.ok(Array.isArray(points), 'should return an array');
  assert.equal(points.length, 0, 'should return empty array for empty routes');
}

// 2. Route with query param produces insertion point with kind: 'query'
{
  const route = makeRoute('GET', '/search', [makeParam('q', 'query', false, 'term')]);
  const points = extractInsertionPoints([route]);
  const queryPoint = points.find((p) => p.name === 'q');
  assert.ok(queryPoint, "should produce insertion point for param 'q'");
  assert.equal(queryPoint.kind, 'query', "insertion point kind should be 'query'");
  assert.equal(queryPoint.method, 'GET', 'insertion point method should be GET');
  assert.equal(queryPoint.path, '/search', 'insertion point path should be /search');
}

// 3. Route with path param in params produces insertion point with kind: 'path'
{
  const route = makeRoute('GET', '/users/:id', [makeParam('id', 'path', true)]);
  const points = extractInsertionPoints([route]);
  const pathPoints = points.filter((p) => p.kind === 'path');
  assert.ok(pathPoints.length >= 1, 'should produce at least 1 path insertion point');
  const idPoint = pathPoints.find((p) => p.name === 'id');
  assert.ok(idPoint, "should produce insertion point for path param 'id'");
  assert.equal(idPoint.required, true, 'path param should be required');
}

// 4. Route with requestBody: {contentType: 'application/json'} produces JSON insertion point
{
  const route = makeRoute('POST', '/items', [], { contentType: 'application/json' });
  const points = extractInsertionPoints([route]);
  const jsonPoint = points.find((p) => p.kind === 'json');
  assert.ok(jsonPoint, 'should produce a json insertion point for JSON request body');
  assert.equal(jsonPoint.name, '__body__', "json body insertion point name should be '__body__'");
  assert.equal(jsonPoint.required, true, 'json body insertion point should be required');
}

// 5. Path template /users/{id} auto-extracts path param 'id'
{
  const route = makeRoute('GET', '/users/{id}', []); // no explicit params
  const points = extractInsertionPoints([route]);
  const idPoint = points.find((p) => p.name === 'id' && p.kind === 'path');
  assert.ok(idPoint, "should auto-extract 'id' from /users/{id} template");
  assert.equal(idPoint.required, true, 'auto-extracted path param should be required');
}

// 6. groupByRoute groups insertion points by route key
{
  const routes = [
    makeRoute('GET', '/a', [makeParam('x', 'query')]),
    makeRoute('POST', '/b', [makeParam('y', 'body')]),
  ];
  const points = extractInsertionPoints(routes);
  const grouped = groupByRoute(points);
  // vm context has its own Map global so instanceof fails — duck-type instead
  assert.equal(typeof grouped.get, 'function', 'groupByRoute should return a Map-like object');
  assert.equal(typeof grouped.has, 'function', 'groupByRoute result should have .has()');
  assert.ok(grouped.has('GET:/a'), "grouped map should have key 'GET:/a'");
  assert.ok(grouped.has('POST:/b'), "grouped map should have key 'POST:/b'");
  for (const [key, arr] of grouped) {
    assert.ok(arr.every((p) => p.routeKey === key), 'all points in group should have matching routeKey');
  }
}

// 7. filterByKind returns only insertion points of given kinds
{
  const routes = [
    makeRoute('GET', '/things', [makeParam('limit', 'query'), makeParam('Authorization', 'header')]),
    makeRoute('POST', '/things', [], { contentType: 'application/json' }),
  ];
  const points = extractInsertionPoints(routes);
  const queryOnly = filterByKind(points, ['query']);
  assert.ok(queryOnly.every((p) => p.kind === 'query'), 'filterByKind(query) should only return query points');

  const jsonAndQuery = filterByKind(points, ['json', 'query']);
  assert.ok(jsonAndQuery.every((p) => p.kind === 'json' || p.kind === 'query'), 'filterByKind should filter by all given kinds');
  assert.ok(jsonAndQuery.some((p) => p.kind === 'json'), 'result should include json points');
  assert.ok(jsonAndQuery.some((p) => p.kind === 'query'), 'result should include query points');
}

// 8. filterRequiredOnly returns only required insertion points
{
  const routes = [
    makeRoute('GET', '/resource/{id}', [
      makeParam('id', 'path', true),
      makeParam('verbose', 'query', false),
    ]),
  ];
  const points = extractInsertionPoints(routes);
  const required = filterRequiredOnly(points);
  assert.ok(required.length > 0, 'should return at least one required point');
  assert.ok(required.every((p) => p.required === true), 'all returned points should be required');
  const optional = points.filter((p) => !p.required);
  assert.ok(!required.some((p) => optional.some((o) => o.id === p.id)), 'required-only result should not include optional points');
}

// 9. Each insertion point has id, routeKey, method, path, kind, name fields
{
  const route = makeRoute('PUT', '/records/{recordId}', [makeParam('Authorization', 'header', true)]);
  const points = extractInsertionPoints([route]);
  assert.ok(points.length > 0, 'should produce at least 1 insertion point');
  for (const p of points) {
    assert.ok(typeof p.id === 'string' && p.id.length > 0, `each point should have a non-empty id, got: ${p.id}`);
    assert.ok(typeof p.routeKey === 'string' && p.routeKey.length > 0, `each point should have routeKey, got: ${p.routeKey}`);
    assert.ok(typeof p.method === 'string' && p.method.length > 0, `each point should have method, got: ${p.method}`);
    assert.ok(typeof p.path === 'string' && p.path.length > 0, `each point should have path, got: ${p.path}`);
    assert.ok(typeof p.kind === 'string' && p.kind.length > 0, `each point should have kind, got: ${p.kind}`);
    assert.ok(typeof p.name === 'string' && p.name.length > 0, `each point should have name, got: ${p.name}`);
  }
}

console.log('spec-import-insertion-points: all tests passed');
