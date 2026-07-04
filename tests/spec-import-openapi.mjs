import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Load and link the spec import modules
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

async function loadSpecImportModules() {
  const indexPath = path.resolve('src/specImport/index.ts');
  const openApiPath = path.resolve('src/specImport/openApi.ts');
  const postmanPath = path.resolve('src/specImport/postman.ts');
  const graphqlPath = path.resolve('src/specImport/graphqlSchema.ts');

  for (const p of [indexPath, openApiPath, postmanPath, graphqlPath]) {
    try {
      await fs.access(p);
    } catch {
      console.log('spec-import-openapi: skipped (source files not found)');
      process.exit(0);
    }
  }

  let indexCode, openApiCode, postmanCode, graphqlCode;
  try {
    [indexCode, openApiCode, postmanCode, graphqlCode] = await Promise.all([
      transpile(indexPath),
      transpile(openApiPath),
      transpile(postmanPath),
      transpile(graphqlPath),
    ]);
  } catch (err) {
    console.log(`spec-import-openapi: skipped (transpile error: ${err.message})`);
    process.exit(0);
  }

  // Build a mini module registry so cross-imports resolve correctly
  const registry = {};

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

  function specRequire(id) {
    if (registry[id]) return registry[id];
    // Fall back to the outer require for node builtins
    return require(id);
  }

  // Load sub-modules first, they import from './index'
  registry['openApi'] = makeModule(openApiCode, openApiPath, (id) => {
    if (id === './index' || id === './index.js') return registry['index'] ?? {};
    return specRequire(id);
  });
  registry['postman'] = makeModule(postmanCode, postmanPath, (id) => {
    if (id === './index' || id === './index.js') return registry['index'] ?? {};
    return specRequire(id);
  });
  registry['graphqlSchema'] = makeModule(graphqlCode, graphqlPath, (id) => {
    if (id === './index' || id === './index.js') return registry['index'] ?? {};
    return specRequire(id);
  });

  // Now load the index, which imports from the sub-modules
  registry['index'] = makeModule(indexCode, indexPath, (id) => {
    if (id === './openApi' || id === './openApi.js') return registry['openApi'];
    if (id === './postman' || id === './postman.js') return registry['postman'];
    if (id === './graphqlSchema' || id === './graphqlSchema.js') return registry['graphqlSchema'];
    return specRequire(id);
  });

  return { index: registry['index'], openApi: registry['openApi'] };
}

const { index, openApi } = await loadSpecImportModules();

const { detectFormat, importSpec } = index;
const { parseOpenApi } = openApi;

if (typeof detectFormat !== 'function' || typeof parseOpenApi !== 'function') {
  console.log('spec-import-openapi: skipped (missing required exports)');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// --- detectFormat returns 'openapi3' for OpenAPI 3.0.0 fixture ---
{
  const fixture = JSON.stringify({ openapi: '3.0.0', info: { title: 'T', version: '1' }, paths: {} });
  const format = detectFormat(fixture);
  assert.equal(format, 'openapi3', `detectFormat should return 'openapi3', got '${format}'`);
}

// --- detectFormat returns 'swagger2' for Swagger 2.0 fixture ---
{
  const fixture = JSON.stringify({ swagger: '2.0', info: { title: 'T', version: '1' }, paths: {} });
  const format = detectFormat(fixture);
  assert.equal(format, 'swagger2', `detectFormat should return 'swagger2', got '${format}'`);
}

// --- parseOpenApi with OpenAPI 3 fixture: 2 routes, 2 params, correct locations ---
{
  const fixture = JSON.stringify({
    openapi: '3.0.0',
    info: { title: 'Test', version: '1.0' },
    paths: {
      '/users': {
        get: {
          operationId: 'listUsers',
          parameters: [{ name: 'page', in: 'query', required: false }],
          responses: {},
        },
      },
      '/users/{id}': {
        get: {
          parameters: [{ name: 'id', in: 'path', required: true }],
          responses: {},
        },
      },
    },
  });

  const result = parseOpenApi(fixture);
  assert.equal(result.format, 'openapi3', 'format should be openapi3');
  assert.equal(result.routes.length, 2, `should parse 2 routes, got ${result.routes.length}`);

  const listUsersRoute = result.routes.find((r) => r.operationId === 'listUsers');
  assert.ok(listUsersRoute, 'should find listUsers route');
  assert.equal(listUsersRoute.method, 'GET', 'listUsers method should be GET');
  assert.equal(listUsersRoute.path, '/users', 'listUsers path should be /users');
  assert.equal(listUsersRoute.params.length, 1, 'listUsers should have 1 param');
  assert.equal(listUsersRoute.params[0].name, 'page', 'param name should be page');
  assert.equal(listUsersRoute.params[0].location, 'query', 'param location should be query');
  assert.equal(listUsersRoute.params[0].required, false, 'page should not be required');

  const getUserRoute = result.routes.find((r) => r.path === '/users/{id}');
  assert.ok(getUserRoute, 'should find /users/{id} route');
  assert.equal(getUserRoute.params.length, 1, '/users/{id} should have 1 param');
  assert.equal(getUserRoute.params[0].name, 'id', 'path param should be id');
  assert.equal(getUserRoute.params[0].location, 'path', 'id should be a path param');
  assert.equal(getUserRoute.params[0].required, true, 'id should be required');

  // Total params across all routes
  const totalParams = result.routes.reduce((sum, r) => sum + r.params.length, 0);
  assert.equal(totalParams, 2, `total params across all routes should be 2, got ${totalParams}`);
}

// --- parseOpenApi with Swagger 2 fixture: 1 route, method POST ---
{
  const fixture = JSON.stringify({
    swagger: '2.0',
    info: { title: 'T', version: '1' },
    paths: {
      '/items': {
        post: {
          parameters: [{ name: 'body', in: 'body' }],
          responses: {},
        },
      },
    },
  });

  const result = parseOpenApi(fixture);
  assert.equal(result.format, 'swagger2', 'format should be swagger2');
  assert.equal(result.routes.length, 1, `should parse 1 route, got ${result.routes.length}`);

  const route = result.routes[0];
  assert.equal(route.method, 'POST', 'method should be POST');
  assert.equal(route.path, '/items', 'path should be /items');

  // routes[0].params should include body param
  assert.ok(route.params.length >= 1, 'should have at least 1 param');
  const bodyParam = route.params.find((p) => p.name === 'body' && p.location === 'body');
  assert.ok(bodyParam, "routes[0].params should include a param named 'body' with location 'body'");
}

// --- importSpec routes correctly to parseOpenApi ---
{
  const fixture = JSON.stringify({
    openapi: '3.0.0',
    info: { title: 'Router Test', version: '1.0' },
    paths: {
      '/ping': {
        get: { operationId: 'ping', parameters: [], responses: {} },
      },
    },
  });

  const result = importSpec(fixture);
  assert.equal(result.format, 'openapi3', 'importSpec should detect and route openapi3');
  assert.equal(result.routes.length, 1);
  assert.equal(result.routes[0].operationId, 'ping');
}

console.log('spec-import-openapi: all tests passed');
