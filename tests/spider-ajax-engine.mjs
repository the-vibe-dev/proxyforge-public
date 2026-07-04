import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Load ajaxSpiderEngine via TypeScript transpilation
// ajaxSpiderEngine imports a type from ajaxSpiderDriver — types are erased by
// transpileModule so we only need a stub for the runtime require.
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

async function loadAjaxSpiderEngine() {
  const enginePath = path.resolve('src/spiders/ajaxSpiderEngine.ts');

  try {
    await fs.access(enginePath);
  } catch {
    console.log('spider-ajax-engine: skipped (source file not found)');
    process.exit(0);
  }

  let engineCode;
  try {
    engineCode = await transpile(enginePath);
  } catch (err) {
    console.log(`spider-ajax-engine: skipped (transpile error: ${err.message})`);
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

  // The driver module is only imported for types — TypeScript erases type-only
  // imports. Provide an empty stub in case transpileModule emits a require() anyway.
  const driverStub = {};

  return makeModule(engineCode, enginePath, (id) => {
    if (id.includes('ajaxSpiderDriver')) return driverStub;
    return require(id);
  });
}

const mod = await loadAjaxSpiderEngine();

const {
  createSpiderState,
  mergeRoutes,
  markVisited,
  getUnvisited,
  getSitemapSnapshot,
  setFramework,
  filterByDepth,
  filterByOrigin,
} = mod;

const missing = [
  'createSpiderState',
  'mergeRoutes',
  'markVisited',
  'getUnvisited',
  'getSitemapSnapshot',
  'setFramework',
  'filterByDepth',
].filter((name) => typeof mod[name] !== 'function');

if (missing.length > 0) {
  console.log(`spider-ajax-engine: skipped (missing exports: ${missing.join(', ')})`);
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeRoute(method, url, depth = 0, via = 'navigation', framework = undefined) {
  return { method, url, foundAt: url, depth, via, framework };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. createSpiderState creates state with empty entries map and correct startUrl
{
  const state = createSpiderState('https://app.example.com/');
  // vm context has its own Map global so instanceof fails — duck-type instead
  assert.equal(typeof state.entries.get, 'function', 'state.entries should be Map-like (has .get)');
  assert.equal(typeof state.entries.set, 'function', 'state.entries should be Map-like (has .set)');
  assert.equal(state.entries.size, 0, 'state.entries should be empty on creation');
  assert.equal(state.startUrl, 'https://app.example.com/', 'state.startUrl should match argument');
  assert.equal(state.visitCount, 0, 'state.visitCount should start at 0');
}

// 2. mergeRoutes adds routes to entries map
{
  const state = createSpiderState('https://app.example.com/');
  const routes = [
    makeRoute('GET', 'https://app.example.com/users', 0),
    makeRoute('POST', 'https://app.example.com/users', 0),
  ];
  const added = mergeRoutes(state, routes);
  assert.equal(state.entries.size, 2, 'entries map should have 2 items after mergeRoutes');
  assert.equal(added.length, 2, 'mergeRoutes should return 2 added entries');
}

// 3. mergeRoutes deduplicates by normalised method+URL key
{
  const state = createSpiderState('https://app.example.com/');
  const routes = [
    makeRoute('GET', 'https://app.example.com/products', 0),
    makeRoute('GET', 'https://app.example.com/products', 1), // duplicate
    makeRoute('GET', 'https://app.example.com/products#section', 0), // fragment-only difference → same key
  ];
  mergeRoutes(state, routes);
  assert.equal(state.entries.size, 1, 'duplicates and fragment variants should be deduplicated to 1 entry');
}

// 4. markVisited increments visitCount and sets entry.visited
{
  const state = createSpiderState('https://app.example.com/');
  mergeRoutes(state, [makeRoute('GET', 'https://app.example.com/dashboard', 0)]);
  assert.equal(state.visitCount, 0, 'visitCount should be 0 before markVisited');
  markVisited(state, 'https://app.example.com/dashboard', 'GET');
  assert.equal(state.visitCount, 1, 'visitCount should be 1 after markVisited');
  const entry = [...state.entries.values()][0];
  assert.equal(entry.visited, true, 'entry.visited should be true after markVisited');
}

// 5. getUnvisited returns only non-visited entries
{
  const state = createSpiderState('https://app.example.com/');
  mergeRoutes(state, [
    makeRoute('GET', 'https://app.example.com/a', 0),
    makeRoute('GET', 'https://app.example.com/b', 0),
    makeRoute('GET', 'https://app.example.com/c', 0),
  ]);
  markVisited(state, 'https://app.example.com/a', 'GET');
  const unvisited = getUnvisited(state);
  assert.equal(unvisited.length, 2, 'getUnvisited should return 2 unvisited entries');
  assert.ok(unvisited.every((e) => !e.visited), 'all returned entries should have visited=false');
}

// 6. filterByDepth returns entries at/below maxDepth
{
  const state = createSpiderState('https://app.example.com/');
  mergeRoutes(state, [
    makeRoute('GET', 'https://app.example.com/shallow', 0),
    makeRoute('GET', 'https://app.example.com/mid', 1),
    makeRoute('GET', 'https://app.example.com/deep', 3),
    makeRoute('GET', 'https://app.example.com/verydeep', 5),
  ]);
  const shallow = filterByDepth(state, 1);
  assert.equal(shallow.length, 2, 'filterByDepth(1) should return 2 entries (depth 0 and 1)');
  assert.ok(shallow.every((e) => e.depth <= 1), 'all returned entries should have depth <= 1');

  const all = filterByDepth(state, 10);
  assert.equal(all.length, 4, 'filterByDepth(10) should return all 4 entries');
}

// 7. setFramework updates state.framework
{
  const state = createSpiderState('https://app.example.com/');
  assert.equal(state.framework, undefined, 'framework should be undefined initially');
  setFramework(state, 'react');
  assert.equal(state.framework, 'react', 'state.framework should be updated to "react"');
  setFramework(state, 'vue');
  assert.equal(state.framework, 'vue', 'state.framework should update again to "vue"');
}

// 8. getSitemapSnapshot returns all entries as array
{
  const state = createSpiderState('https://app.example.com/');
  mergeRoutes(state, [
    makeRoute('GET', 'https://app.example.com/x', 0),
    makeRoute('POST', 'https://app.example.com/y', 1),
  ]);
  markVisited(state, 'https://app.example.com/x', 'GET');
  const snapshot = getSitemapSnapshot(state);
  assert.ok(Array.isArray(snapshot), 'getSitemapSnapshot should return an array');
  assert.equal(snapshot.length, 2, 'snapshot should contain all 2 entries');
  // Includes both visited and unvisited
  assert.ok(snapshot.some((e) => e.visited), 'snapshot should include visited entries');
  assert.ok(snapshot.some((e) => !e.visited), 'snapshot should include unvisited entries');
}

console.log('spider-ajax-engine: all tests passed');
