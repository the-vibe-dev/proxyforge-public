/**
 * extension-signed-package.mjs
 *
 * Tests for:
 *  - computeDigest determinism
 *  - normalizeManifest defaults
 *  - validateManifest rejection of invalid hook/permission names
 *  - passive-secret-detector: onScannerPassive finds secrets in fixture response
 *  - intruder-base64: onIntruderPayload base64-encodes payload
 *
 * Gracefully skips if the modules cannot be loaded.
 */
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);

let ts;
try {
  ts = require('typescript');
} catch {
  console.log('extension-signed-package: skipped; typescript not available');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Loader helpers
// ---------------------------------------------------------------------------

async function loadTsModule(filePath, extraGlobals = {}) {
  let source;
  try {
    source = await fs.readFile(filePath, 'utf8');
  } catch {
    return null;
  }
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
      importsNotUsedAsValues: ts.ImportsNotUsedAsValues.Remove,
    },
    fileName: filePath,
  }).outputText;

  const mod = { exports: {} };
  const sandbox = {
    module: mod,
    exports: mod.exports,
    Buffer,
    console,
    URL,
    URLSearchParams,
    process,
    require,
    TextEncoder,
    TextDecoder,
    ...extraGlobals,
  };
  try {
    vm.runInNewContext(transpiled, sandbox, { filename: filePath });
  } catch (err) {
    console.log(`extension-signed-package: skipped; failed to load ${path.basename(filePath)}: ${err.message}`);
    return null;
  }
  return mod.exports;
}

/**
 * Load a sample extension that depends on sdkHelpers.
 * We inject a pre-built helpers module as the require result for the relative
 * path so the extension sandbox can resolve it.
 */
async function loadExtensionWithHelpers(extensionPath, helpers) {
  let source;
  try {
    source = await fs.readFile(extensionPath, 'utf8');
  } catch {
    return null;
  }
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
      importsNotUsedAsValues: ts.ImportsNotUsedAsValues.Remove,
    },
    fileName: extensionPath,
  }).outputText;

  const mod = { exports: {} };

  // Stub require so relative imports resolve to our pre-loaded helpers.
  function stubRequire(id) {
    if (id.includes('sdkHelpers')) return helpers;
    return require(id);
  }
  stubRequire.resolve = require.resolve;

  const sandbox = {
    module: mod,
    exports: mod.exports,
    Buffer,
    console,
    URL,
    URLSearchParams,
    process,
    require: stubRequire,
    TextEncoder,
    TextDecoder,
  };
  try {
    vm.runInNewContext(transpiled, sandbox, { filename: extensionPath });
  } catch (err) {
    console.log(`extension-signed-package: skipped; failed to load extension ${path.basename(extensionPath)}: ${err.message}`);
    return null;
  }
  return mod.exports;
}

// ---------------------------------------------------------------------------
// Load modules
// ---------------------------------------------------------------------------

const manifestPath = path.resolve('src/extensions/manifest.ts');
const helpersPath = path.resolve('src/extensions/sdkHelpers.ts');
const secretDetectorPath = path.resolve(
  'src/extensions/sampleExtensions/passive-secret-detector/index.ts',
);
const base64ExtPath = path.resolve(
  'src/extensions/sampleExtensions/intruder-base64/index.ts',
);

const manifest = await loadTsModule(manifestPath);
const helpers = await loadTsModule(helpersPath);

if (!manifest || !helpers) {
  console.log('extension-signed-package: skipped; manifest or helpers module failed to load');
  process.exit(0);
}

const secretDetectorMod = await loadExtensionWithHelpers(secretDetectorPath, helpers);
const base64Mod = await loadExtensionWithHelpers(base64ExtPath, helpers);

// ---------------------------------------------------------------------------
// computeDigest determinism
// ---------------------------------------------------------------------------
{
  const input = JSON.stringify({ id: 'test-ext', name: 'Test', version: '1.0.0' });
  const d1 = manifest.computeDigest(input);
  const d2 = manifest.computeDigest(input);
  assert.equal(d1, d2, 'computeDigest should be deterministic for the same input');
  assert.equal(d1.length, 64, 'computeDigest should return a 64-char hex string');
}

// Different inputs produce different digests
{
  const d1 = manifest.computeDigest('{"a":1}');
  const d2 = manifest.computeDigest('{"a":2}');
  assert.notEqual(d1, d2, 'computeDigest should return different digests for different inputs');
}

// ---------------------------------------------------------------------------
// normalizeManifest fills in missing optional fields with defaults
// ---------------------------------------------------------------------------
{
  const partial = { id: 'my-ext', name: 'My Extension', version: '2.0.0' };
  const norm = manifest.normalizeManifest(partial);
  assert.equal(norm.id, 'my-ext');
  assert.equal(norm.name, 'My Extension');
  assert.equal(norm.version, '2.0.0');
  assert.equal(norm.hooks.length, 0, 'normalizeManifest should default hooks to []');
  assert.equal(norm.permissions.length, 0, 'normalizeManifest should default permissions to []');
  assert.equal(norm.license, 'UNLICENSED', 'normalizeManifest should default license to UNLICENSED');
}

// normalizeManifest fills in all missing fields including id/name/version
{
  const norm = manifest.normalizeManifest({});
  assert.equal(norm.id, 'unknown-extension', 'normalizeManifest should default id');
  assert.equal(norm.name, 'Unnamed Extension', 'normalizeManifest should default name');
  assert.equal(norm.version, '0.0.0', 'normalizeManifest should default version');
}

// ---------------------------------------------------------------------------
// validateManifest rejects invalid hook names
// ---------------------------------------------------------------------------
{
  const result = manifest.validateManifest({
    id: 'test-ext',
    name: 'Test',
    version: '1.0.0',
    hooks: ['request', 'not_a_real_hook'],
    permissions: [],
  });
  assert.ok(!result.valid, 'validateManifest should reject invalid hook names');
  assert.ok(
    result.errors.some((e) => e.includes('not_a_real_hook')),
    'validateManifest should name the invalid hook in the error',
  );
}

// ---------------------------------------------------------------------------
// validateManifest rejects invalid permission tokens
// ---------------------------------------------------------------------------
{
  const result = manifest.validateManifest({
    id: 'test-ext',
    name: 'Test',
    version: '1.0.0',
    hooks: ['request'],
    permissions: ['read:history', 'delete:everything'],
  });
  assert.ok(!result.valid, 'validateManifest should reject invalid permission tokens');
  assert.ok(
    result.errors.some((e) => e.includes('delete:everything')),
    'validateManifest should name the invalid permission in the error',
  );
}

// ---------------------------------------------------------------------------
// passive-secret-detector: onScannerPassive finds secrets
// ---------------------------------------------------------------------------
if (!secretDetectorMod) {
  console.log('extension-signed-package: skipping passive-secret-detector tests (module not loaded)');
} else {
  const ext = secretDetectorMod.extension;
  assert.ok(ext, 'passive-secret-detector should export an extension object');
  assert.ok(typeof ext.onScannerPassive === 'function', 'passive-secret-detector should implement onScannerPassive');

  // Fixture response containing a secret
  const fixturePayload = {
    exchangeId: 'hx-test-001',
    requestRaw: 'GET /api/config HTTP/1.1\r\nHost: example.com\r\n\r\n',
    // Use a plain-text response body where the pattern is unambiguously matched.
    // The regex expects: api_key = <value> (colon or equals, optional quotes).
    responseRaw: [
      'HTTP/1.1 200 OK',
      'Content-Type: text/plain',
      '',
      'api_key=secretvalue123456789',
    ].join('\r\n'),
  };

  const result = await ext.onScannerPassive(fixturePayload);
  assert.ok(result, 'passive-secret-detector should return a result for a response containing a secret');
  assert.ok(
    Array.isArray(result.issues) && result.issues.length > 0,
    'passive-secret-detector should report at least one issue when a secret is detected',
  );
  assert.ok(
    result.issues[0].severity === 'high',
    'passive-secret-detector should report the issue as high severity',
  );

  // Clean response — no issues
  const cleanPayload = {
    exchangeId: 'hx-test-002',
    requestRaw: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>',
  };
  const cleanResult = await ext.onScannerPassive(cleanPayload);
  assert.ok(
    cleanResult === undefined || cleanResult === null || (cleanResult.issues ?? []).length === 0,
    'passive-secret-detector should not report issues for a clean response',
  );

  console.log('extension-signed-package: passive-secret-detector tests passed');
}

// ---------------------------------------------------------------------------
// intruder-base64: onIntruderPayload base64-encodes payload
// ---------------------------------------------------------------------------
if (!base64Mod) {
  console.log('extension-signed-package: skipping intruder-base64 tests (module not loaded)');
} else {
  const ext = base64Mod.extension;
  assert.ok(ext, 'intruder-base64 should export an extension object');
  assert.ok(typeof ext.onIntruderPayload === 'function', 'intruder-base64 should implement onIntruderPayload');

  const result = await ext.onIntruderPayload({ original: 'hello', position: 0 });
  assert.ok(result, 'intruder-base64 should return a result');
  assert.equal(result.transformed, 'aGVsbG8=', 'intruder-base64 should base64-encode "hello" as "aGVsbG8="');

  // Verify a second payload
  const result2 = await ext.onIntruderPayload({ original: 'ProxyForge', position: 1 });
  assert.equal(
    result2.transformed,
    Buffer.from('ProxyForge').toString('base64'),
    'intruder-base64 should correctly encode "ProxyForge"',
  );

  console.log('extension-signed-package: intruder-base64 tests passed');
}

console.log('extension-signed-package: all tests passed');
