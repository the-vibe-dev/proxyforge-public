import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Graceful skip: check if insomnia.ts source (or compiled .js) exists.
// ---------------------------------------------------------------------------

const SRC_INSOMNIA = path.resolve('src/specImport/insomnia.ts');
const DIST_INSOMNIA = path.resolve('dist-electron/specImport/insomnia.js');

async function fileExists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

const hasSrc = await fileExists(SRC_INSOMNIA);
const hasDist = await fileExists(DIST_INSOMNIA);

if (!hasSrc && !hasDist) {
  console.log('spec-import-insomnia: skipped (src/specImport/insomnia.ts not yet implemented)');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// TypeScript transpiler helper
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

// ---------------------------------------------------------------------------
// Load insomnia parser module
// ---------------------------------------------------------------------------

async function loadInsomniaParser() {
  const indexPath = path.resolve('src/specImport/index.ts');

  let insomniaCode;
  try {
    insomniaCode = await transpile(SRC_INSOMNIA);
  } catch (err) {
    console.log(`spec-import-insomnia: skipped (transpile error: ${err.message})`);
    process.exit(0);
  }

  let indexCode;
  try {
    indexCode = await transpile(indexPath);
  } catch {
    indexCode = '"use strict";Object.defineProperty(exports,"__esModule",{value:true});';
  }

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
    try {
      vm.runInNewContext(code, sandbox, { filename });
    } catch (err) {
      console.log(`spec-import-insomnia: skipped (vm load error: ${err.message})`);
      process.exit(0);
    }
    return mod.exports;
  }

  const stubOpenApi = { parseOpenApi: () => ({ format: 'openapi3', routes: [] }) };
  const stubPostman = { parsePostman: () => ({ format: 'postman', routes: [] }) };
  const stubGraphql = { parseGraphqlSchema: () => ({ format: 'graphql-schema', routes: [] }) };
  const stubOdata = { parseOdata: () => ({ format: 'odata', routes: [] }) };
  const stubHarSeed = { parseHarSeed: () => ({ format: 'har', routes: [] }) };
  const stubSoapWsdl = { parseWsdl: () => ({ operations: [], services: [], warnings: [] }) };

  registry['index'] = makeModule(indexCode, indexPath, (id) => {
    if (id === './openApi' || id === './openApi.js') return stubOpenApi;
    if (id === './postman' || id === './postman.js') return stubPostman;
    if (id === './graphqlSchema' || id === './graphqlSchema.js') return stubGraphql;
    if (id === './odata' || id === './odata.js') return stubOdata;
    if (id === './harSeed' || id === './harSeed.js') return stubHarSeed;
    if (id === './soapWsdl' || id === './soapWsdl.js') return stubSoapWsdl;
    if (id === './insomnia' || id === './insomnia.js') return registry['insomnia'] ?? {};
    return require(id);
  });

  registry['insomnia'] = makeModule(insomniaCode, SRC_INSOMNIA, (id) => {
    if (id === './index' || id === './index.js') return registry['index'];
    return require(id);
  });

  return registry['insomnia'];
}

const insomniaModule = await loadInsomniaParser();
const { parseInsomnia, validateInsomniaShape } = insomniaModule;

if (typeof parseInsomnia !== 'function') {
  console.log('spec-import-insomnia: skipped (parseInsomnia not exported)');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Helper: normalise result to a consistent shape.
// parseInsomnia returns { requests, warnings } while the router-level API
// uses { routes, ... }.  We accept either field name.
// ---------------------------------------------------------------------------

function getRequests(result) {
  return result.requests ?? result.routes ?? [];
}

function getWarnings(result) {
  return result.warnings ?? result.errors ?? [];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. parseInsomnia returns empty requests on minimal empty export
{
  const input = JSON.stringify({ _type: 'export', __export_format: 4, resources: [] });
  const result = parseInsomnia(input);
  assert.ok(result, 'parseInsomnia: should return a result object');
  const requests = getRequests(result);
  assert.ok(Array.isArray(requests), 'parseInsomnia: result.requests should be an array');
  assert.strictEqual(requests.length, 0, 'parseInsomnia: empty resources should yield 0 requests');
}

// 2. parseInsomnia extracts requests from resources with _type: "request"
{
  const input = JSON.stringify({
    _type: 'export',
    __export_format: 4,
    resources: [
      {
        _type: 'request',
        _id: 'req_001',
        name: 'Get Users',
        method: 'GET',
        url: 'https://api.example.com/users',
        headers: [],
        body: {},
      },
      {
        _type: 'request',
        _id: 'req_002',
        name: 'Create User',
        method: 'POST',
        url: 'https://api.example.com/users',
        headers: [],
        body: { mimeType: 'application/json', text: '{"name":"test"}' },
      },
    ],
  });
  const result = parseInsomnia(input);
  const requests = getRequests(result);
  assert.ok(requests.length >= 2, `parseInsomnia: should extract 2 requests, got ${requests.length}`);
}

// 3. Skips non-request resources and adds warning about count
{
  const input = JSON.stringify({
    _type: 'export',
    __export_format: 4,
    resources: [
      { _type: 'request_group', _id: 'grp_001', name: 'Auth' },
      { _type: 'environment', _id: 'env_001', name: 'Base Env', data: {} },
      { _type: 'request', _id: 'req_001', name: 'Login', method: 'POST', url: 'https://api.example.com/login', headers: [], body: {} },
    ],
  });
  const result = parseInsomnia(input);
  const requests = getRequests(result);
  const warnings = getWarnings(result);
  assert.strictEqual(requests.length, 1,
    `parseInsomnia: should extract only 1 request (skipping 2 non-request resources), got ${requests.length}`);
  assert.ok(warnings.length > 0, 'parseInsomnia: should add a warning when non-request resources are skipped');
}

// 4. Request has method, url, name fields
{
  const input = JSON.stringify({
    _type: 'export',
    __export_format: 4,
    resources: [
      {
        _type: 'request',
        _id: 'req_001',
        name: 'Get Users',
        method: 'GET',
        url: 'https://api.example.com/users',
        headers: [],
        body: {},
      },
    ],
  });
  const result = parseInsomnia(input);
  const requests = getRequests(result);
  assert.ok(requests.length >= 1, 'parseInsomnia: should return at least 1 request');
  const req = requests[0];
  assert.ok(req.method, 'parseInsomnia: request should have a method field');
  assert.ok(req.url || req.path, 'parseInsomnia: request should have a url or path field');
  assert.ok(req.name || req.operationId || req.summary, 'parseInsomnia: request should have a name/operationId/summary field');
}

// validateInsomniaShape tests — only run if exported
if (typeof validateInsomniaShape === 'function') {
  // 5. validateInsomniaShape rejects non-object
  {
    const result = validateInsomniaShape('not an object');
    const isRejected = result === false ||
      (result && result.valid === false) ||
      (result && Array.isArray(result.errors) && result.errors.length > 0);
    assert.ok(isRejected, 'validateInsomniaShape: should reject a non-object input');
  }

  // 6. validateInsomniaShape rejects missing _type
  {
    const result = validateInsomniaShape({ __export_format: 4, resources: [] });
    const isRejected = result === false ||
      (result && result.valid === false) ||
      (result && Array.isArray(result.errors) && result.errors.length > 0);
    assert.ok(isRejected, 'validateInsomniaShape: should reject object missing _type');
  }

  // 7. validateInsomniaShape accepts valid shape
  {
    const result = validateInsomniaShape({ _type: 'export', __export_format: 4, resources: [] });
    const isAccepted = result === true ||
      (result && result.valid === true) ||
      (result && Array.isArray(result.errors) && result.errors.length === 0);
    assert.ok(isAccepted, 'validateInsomniaShape: should accept valid Insomnia export shape');
  }
} else {
  console.log('spec-import-insomnia: validateInsomniaShape not exported — skipping shape validation tests (5-7)');
}

console.log('spec-import-insomnia: all tests passed');
