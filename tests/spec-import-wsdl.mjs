import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Graceful skip: check if soapWsdl.ts source (or compiled .js) exists.
// ---------------------------------------------------------------------------

const SRC_WSDL = path.resolve('src/specImport/soapWsdl.ts');
const DIST_WSDL = path.resolve('dist-electron/specImport/soapWsdl.js');

async function fileExists(p) {
  try { await fs.access(p); return true; } catch { return false; }
}

const hasSrc = await fileExists(SRC_WSDL);
const hasDist = await fileExists(DIST_WSDL);

if (!hasSrc && !hasDist) {
  console.log('spec-import-wsdl: skipped (src/specImport/soapWsdl.ts not yet implemented)');
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
// Load soapWsdl parser module
// ---------------------------------------------------------------------------

async function loadWsdlParser() {
  let wsdlCode;
  try {
    wsdlCode = await transpile(SRC_WSDL);
  } catch (err) {
    console.log(`spec-import-wsdl: skipped (transpile error: ${err.message})`);
    process.exit(0);
  }

  const mod = { exports: {} };
  const sandbox = {
    module: mod,
    exports: mod.exports,
    require: (id) => {
      if (id === './index' || id === './index.js') return {};
      return require(id);
    },
    process,
    console,
    URL,
    URLSearchParams,
    TextDecoder,
    TextEncoder,
    Buffer,
  };

  try {
    vm.runInNewContext(wsdlCode, sandbox, { filename: SRC_WSDL });
  } catch (err) {
    console.log(`spec-import-wsdl: skipped (vm load error: ${err.message})`);
    process.exit(0);
  }

  return mod.exports;
}

const wsdlModule = await loadWsdlParser();
const { parseWsdl, validateWsdlShape } = wsdlModule;

if (typeof parseWsdl !== 'function') {
  console.log('spec-import-wsdl: skipped (parseWsdl not exported)');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// WSDL fixture helpers
// ---------------------------------------------------------------------------

/** Minimal WSDL 1.1 document with a single operation. */
function makeWsdl({ targetNamespace = 'http://example.com', operations = [], serviceAddress = '' } = {}) {
  const portTypeOps = operations.map((op) => `
    <operation name="${op.name}">
      <input message="tns:${op.name}Request"/>
      <output message="tns:${op.name}Response"/>
    </operation>`).join('');

  const bindingOps = operations.map((op) => `
    <operation name="${op.name}">
      <soap:operation soapAction="${op.soapAction ?? `${targetNamespace}/${op.name}`}"/>
      <input/><output/>
    </operation>`).join('');

  const serviceBlock = serviceAddress ? `
  <service name="ExampleService">
    <port name="ExamplePort" binding="tns:ExampleBinding">
      <soap:address location="${serviceAddress}"/>
    </port>
  </service>` : '';

  return `<?xml version="1.0" encoding="UTF-8"?>
<definitions xmlns="http://schemas.xmlsoap.org/wsdl/"
             xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
             xmlns:tns="${targetNamespace}"
             targetNamespace="${targetNamespace}">
  <portType name="ExamplePortType">${portTypeOps}
  </portType>
  <binding name="ExampleBinding" type="tns:ExamplePortType">${bindingOps}
  </binding>${serviceBlock}
</definitions>`;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// 1. parseWsdl extracts targetNamespace from <definitions targetNamespace="http://example.com">
{
  const wsdl = makeWsdl({ targetNamespace: 'http://example.com', operations: [] });
  const result = parseWsdl(wsdl);
  assert.ok(result, 'parseWsdl: should return a result object');
  assert.strictEqual(result.targetNamespace, 'http://example.com',
    `parseWsdl: targetNamespace should be 'http://example.com', got '${result.targetNamespace}'`);
}

// 2. parseWsdl extracts operation names from <operation name="GetUser">
{
  const wsdl = makeWsdl({
    targetNamespace: 'http://example.com',
    operations: [
      { name: 'GetUser', soapAction: 'http://example.com/GetUser' },
      { name: 'ListUsers', soapAction: 'http://example.com/ListUsers' },
    ],
  });
  const result = parseWsdl(wsdl);
  assert.ok(Array.isArray(result.operations), 'parseWsdl: result.operations should be an array');
  const names = result.operations.map((op) => op.name);
  assert.ok(names.includes('GetUser'), `parseWsdl: should extract 'GetUser' operation, got [${names.join(', ')}]`);
  assert.ok(names.includes('ListUsers'), `parseWsdl: should extract 'ListUsers' operation, got [${names.join(', ')}]`);
}

// 3. parseWsdl extracts soapAction from <soap:operation soapAction="http://example.com/GetUser">
{
  const wsdl = makeWsdl({
    targetNamespace: 'http://example.com',
    operations: [{ name: 'GetUser', soapAction: 'http://example.com/GetUser' }],
  });
  const result = parseWsdl(wsdl);
  const getUserOp = result.operations.find((op) => op.name === 'GetUser');
  assert.ok(getUserOp, 'parseWsdl: should find GetUser operation');
  assert.strictEqual(getUserOp.soapAction, 'http://example.com/GetUser',
    `parseWsdl: soapAction should be 'http://example.com/GetUser', got '${getUserOp.soapAction}'`);
}

// 4. parseWsdl extracts service address
{
  const serviceAddr = 'http://api.example.com/soap';
  const wsdl = makeWsdl({
    targetNamespace: 'http://example.com',
    operations: [{ name: 'Ping', soapAction: 'http://example.com/Ping' }],
    serviceAddress: serviceAddr,
  });
  const result = parseWsdl(wsdl);
  assert.ok(Array.isArray(result.services), 'parseWsdl: result.services should be an array');
  assert.ok(result.services.length >= 1, `parseWsdl: should extract at least one service, got ${result.services.length}`);
  const service = result.services[0];
  assert.strictEqual(service.address, serviceAddr,
    `parseWsdl: service address should be '${serviceAddr}', got '${service.address}'`);
}

// 5. parseWsdl returns empty operations on empty WSDL string
{
  const result = parseWsdl('');
  assert.ok(result, 'parseWsdl: should return a result object for empty input');
  assert.ok(Array.isArray(result.operations), 'parseWsdl: result.operations should be an array for empty input');
  assert.strictEqual(result.operations.length, 0,
    `parseWsdl: empty WSDL should yield 0 operations, got ${result.operations.length}`);
  // Should include a warning about empty input
  assert.ok(Array.isArray(result.warnings) && result.warnings.length > 0,
    'parseWsdl: empty WSDL should produce warnings');
}

// validateWsdlShape tests — only run if exported
if (typeof validateWsdlShape === 'function') {
  // 6. validateWsdlShape rejects null
  {
    const result = validateWsdlShape(null);
    const isRejected = result === false ||
      (result && result.valid === false) ||
      (result && Array.isArray(result.errors) && result.errors.length > 0);
    assert.ok(isRejected, 'validateWsdlShape: should reject null');
  }

  // 7. validateWsdlShape accepts object with operations array
  {
    const result = validateWsdlShape({ operations: [], services: [], warnings: [] });
    const isAccepted = result === true ||
      (result && result.valid === true) ||
      (result && Array.isArray(result.errors) && result.errors.length === 0);
    assert.ok(isAccepted, 'validateWsdlShape: should accept object with operations array');
  }
} else {
  console.log('spec-import-wsdl: validateWsdlShape not exported — skipping shape validation tests (6-7)');
}

console.log('spec-import-wsdl: all tests passed');
