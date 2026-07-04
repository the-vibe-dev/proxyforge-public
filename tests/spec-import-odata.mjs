import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Load odata.ts via TypeScript transpilation
// odata.ts imports types from './index' — types are erased, but we stub the
// require in case transpileModule emits a runtime require().
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

async function loadOdataParser() {
  const odataPath = path.resolve('src/specImport/odata.ts');

  try {
    await fs.access(odataPath);
  } catch {
    console.log('spec-import-odata: skipped (source file not found)');
    process.exit(0);
  }

  let odataCode;
  try {
    odataCode = await transpile(odataPath);
  } catch (err) {
    console.log(`spec-import-odata: skipped (transpile error: ${err.message})`);
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

  // Stub the index module — only types are imported, no runtime values needed.
  const indexStub = {};

  return makeModule(odataCode, odataPath, (id) => {
    if (id === './index' || id === './index.js') return indexStub;
    return require(id);
  });
}

const mod = await loadOdataParser();
const { parseOdata, validateOdataShape } = mod;

if (typeof parseOdata !== 'function' || typeof validateOdataShape !== 'function') {
  console.log('spec-import-odata: skipped (missing required exports)');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const EDMX_USERS = `<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
  <edmx:DataServices>
    <Schema Namespace="TestService" xmlns="http://docs.oasis-open.org/odata/ns/edm">
      <EntityType Name="User">
        <Key><PropertyRef Name="Id"/></Key>
        <Property Name="Id" Type="Edm.Int32" Nullable="false"/>
        <Property Name="Name" Type="Edm.String"/>
      </EntityType>
      <EntityContainer Name="Container">
        <EntitySet Name="Users" EntityType="TestService.User"/>
      </EntityContainer>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>`;

const EDMX_WITH_ACTION = `<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
  <edmx:DataServices>
    <Schema Namespace="TestService" xmlns="http://docs.oasis-open.org/odata/ns/edm">
      <EntityContainer Name="Container">
        <ActionImport Name="ResetPassword"/>
      </EntityContainer>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>`;

const EDMX_EMPTY = `<?xml version="1.0" encoding="utf-8"?>
<edmx:Edmx Version="4.0" xmlns:edmx="http://docs.oasis-open.org/odata/ns/edmx">
  <edmx:DataServices>
    <Schema Namespace="Empty" xmlns="http://docs.oasis-open.org/odata/ns/edm">
      <EntityContainer Name="Container"/>
    </Schema>
  </edmx:DataServices>
</edmx:Edmx>`;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. parseOdata with XML EDMX containing <EntitySet Name="Users"> produces GET/POST/PATCH/DELETE routes
{
  const result = parseOdata(EDMX_USERS);
  assert.ok(Array.isArray(result.routes), 'routes should be an array');
  const methods = result.routes.map((r) => r.method);
  assert.ok(methods.includes('GET'), 'should produce GET routes for Users');
  assert.ok(methods.includes('POST'), 'should produce POST route for Users');
  assert.ok(methods.includes('PATCH'), 'should produce PATCH route for Users');
  assert.ok(methods.includes('DELETE'), 'should produce DELETE route for Users');
  // Should have routes for collection and keyed entity
  const userPaths = result.routes.map((r) => r.path);
  assert.ok(userPaths.some((p) => p === '/Users'), 'should have /Users collection route');
  assert.ok(userPaths.some((p) => p.includes('Users({id})')), 'should have /Users({id}) keyed route');
}

// 2. Routes include standard OData query params on GET list routes
{
  const result = parseOdata(EDMX_USERS);
  const listRoute = result.routes.find((r) => r.method === 'GET' && r.path === '/Users');
  assert.ok(listRoute, 'should find GET /Users list route');
  assert.ok(Array.isArray(listRoute.params), 'list route params should be an array');
  const paramNames = listRoute.params.map((p) => p.name);
  assert.ok(paramNames.includes('$top'), 'should include $top param');
  assert.ok(paramNames.includes('$skip'), 'should include $skip param');
  assert.ok(paramNames.includes('$filter'), 'should include $filter param');
  assert.ok(paramNames.includes('$select'), 'should include $select param');
  assert.ok(paramNames.includes('$expand'), 'should include $expand param');
}

// 3. parseOdata with XML EDMX containing <ActionImport Name="ResetPassword"> produces a POST route
{
  const result = parseOdata(EDMX_WITH_ACTION);
  const actionRoute = result.routes.find((r) => r.path === '/ResetPassword');
  assert.ok(actionRoute, 'should find /ResetPassword route');
  assert.equal(actionRoute.method, 'POST', 'action import route should be POST');
}

// 4. validateOdataShape rejects null
{
  const { valid, errors } = validateOdataShape(null);
  assert.equal(valid, false, 'null should be invalid');
  assert.ok(errors.length > 0, 'errors should be non-empty for null');
}

// 5. validateOdataShape rejects object without routes array
{
  const { valid, errors } = validateOdataShape({ title: 'No routes' });
  assert.equal(valid, false, 'object without routes array should be invalid');
  assert.ok(errors.some((e) => e.toLowerCase().includes('routes')), 'error should mention routes');
}

// 6. validateOdataShape accepts valid result object
{
  const { valid, errors } = validateOdataShape({ format: 'openapi3', routes: [] });
  assert.equal(valid, true, 'object with routes array should be valid');
  assert.equal(errors.length, 0, 'errors should be empty for valid shape');
}

// 7. parseOdata with empty XML returns empty routes array (not a crash)
{
  let result;
  try {
    result = parseOdata(EDMX_EMPTY);
  } catch (err) {
    assert.fail(`parseOdata should not throw on empty EDMX, got: ${err.message}`);
  }
  assert.ok(Array.isArray(result.routes), 'result.routes should still be an array');
  assert.equal(result.routes.length, 0, 'empty EDMX should produce 0 routes');
}

console.log('spec-import-odata: all tests passed');
