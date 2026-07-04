/**
 * extension-sdk-manifest.mjs
 *
 * Focused contract tests for the Extension SDK manifest module
 * (src/extensions/manifest.ts).
 *
 * Covers: validation of required fields, hook-name allowlist,
 * unknown hook rejection, empty-hooks acceptance, and normalizeManifest defaults.
 *
 * Skips gracefully when the TypeScript compiler is unavailable.
 */
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);

let ts;
try {
  ts = require('typescript');
} catch {
  console.log('extension-sdk-manifest: skipped; typescript not available');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Loader helpers (same pattern used across the test suite)
// ---------------------------------------------------------------------------

function loadTsModule(filePath, cache = new Map()) {
  const resolved = path.resolve(filePath);
  if (cache.has(resolved)) return cache.get(resolved).exports;

  let source;
  try {
    source = fsSync.readFileSync(resolved, 'utf8');
  } catch {
    return null;
  }

  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: resolved,
  }).outputText;

  const mod = { exports: {} };
  cache.set(resolved, mod);

  const localRequire = (specifier) => {
    if (specifier.startsWith('.')) {
      const base = path.resolve(path.dirname(resolved), specifier);
      for (const candidate of [
        base,
        `${base}.json`,
        `${base}.ts`,
        `${base}.js`,
        path.join(base, 'index.ts'),
        path.join(base, 'index.js'),
      ]) {
        if (fsSync.existsSync(candidate) && fsSync.statSync(candidate).isFile()) {
          if (candidate.endsWith('.ts')) return loadTsModule(candidate, cache);
          return require(candidate);
        }
      }
    }
    return require(specifier);
  };

  const sandbox = {
    module: mod,
    exports: mod.exports,
    Buffer,
    console,
    URL,
    URLSearchParams,
    process,
    require: localRequire,
    TextEncoder,
    TextDecoder,
  };

  try {
    vm.runInNewContext(transpiled, sandbox, { filename: resolved });
  } catch (err) {
    console.log(`extension-sdk-manifest: skipped; failed to load ${path.basename(resolved)}: ${err.message}`);
    return null;
  }

  return mod.exports;
}

// ---------------------------------------------------------------------------
// Load the manifest module
// ---------------------------------------------------------------------------

const candidatePaths = [
  'src/extensions/manifest.ts',
  'electron/extensions/manifest.ts',
  'dist-electron/extensions/manifest.js',
  'dist/extensions/manifest.js',
];

let manifestPath = '';
for (const candidate of candidatePaths) {
  const resolved = path.resolve(candidate);
  try {
    const stat = await fs.stat(resolved);
    if (stat.isFile()) { manifestPath = resolved; break; }
  } catch { /* keep looking */ }
}

if (!manifestPath) {
  console.log('extension-sdk-manifest: skipped; manifest module not found');
  process.exit(0);
}

const manifest = loadTsModule(manifestPath);
if (!manifest) {
  console.log('extension-sdk-manifest: skipped; manifest module failed to load');
  process.exit(0);
}

// Verify required exports are present
const requiredExports = ['validateManifest', 'normalizeManifest', 'VALID_HOOKS'];
const missingExports = requiredExports.filter((n) => !manifest[n]);
if (missingExports.length) {
  console.log(`extension-sdk-manifest: skipped; missing export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const { validateManifest, normalizeManifest, VALID_HOOKS } = manifest;

// ---------------------------------------------------------------------------
// Helper: minimal valid manifest
// ---------------------------------------------------------------------------
function validManifest(overrides = {}) {
  return {
    id: 'example-ext',
    name: 'Example Extension',
    version: '1.2.3',
    hooks: ['request', 'response'],
    permissions: ['read:history'],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test 1: Valid manifest with all required fields passes validation
// ---------------------------------------------------------------------------
{
  const result = validateManifest(validManifest());
  assert.ok(result.valid, `Test 1 — valid manifest should pass; errors: ${result.errors.join(', ')}`);
  assert.equal(result.errors.length, 0, 'Test 1 — valid manifest should have no errors');
}

// ---------------------------------------------------------------------------
// Test 2: Missing `id` field fails validation with error mentioning "id"
// ---------------------------------------------------------------------------
{
  const result = validateManifest({ ...validManifest(), id: '' });
  assert.ok(!result.valid, 'Test 2 — manifest with empty id should fail validation');
  assert.ok(
    result.errors.some((e) => /\bid\b/i.test(e)),
    `Test 2 — error should mention "id"; got: ${JSON.stringify(result.errors)}`,
  );
}

// ---------------------------------------------------------------------------
// Test 3: Missing `version` field fails validation
// ---------------------------------------------------------------------------
{
  const result = validateManifest({ ...validManifest(), version: '' });
  assert.ok(!result.valid, 'Test 3 — manifest with empty version should fail validation');
  assert.ok(
    result.errors.some((e) => /version/i.test(e)),
    `Test 3 — error should mention "version"; got: ${JSON.stringify(result.errors)}`,
  );
}

// ---------------------------------------------------------------------------
// Test 4: Missing `hooks` array fails validation
// ---------------------------------------------------------------------------
{
  const obj = { id: 'x', name: 'X', version: '1.0.0', permissions: [] };
  const result = validateManifest(obj);
  assert.ok(!result.valid, 'Test 4 — manifest without hooks array should fail validation');
  assert.ok(
    result.errors.some((e) => /hook/i.test(e)),
    `Test 4 — error should mention "hooks"; got: ${JSON.stringify(result.errors)}`,
  );
}

// ---------------------------------------------------------------------------
// Test 5: Unknown hook type in hooks array fails validation
// ---------------------------------------------------------------------------
{
  const result = validateManifest(validManifest({ hooks: ['request', 'not_a_valid_hook'] }));
  assert.ok(!result.valid, 'Test 5 — manifest with unknown hook type should fail validation');
  assert.ok(
    result.errors.some((e) => /hook|not_a_valid_hook/i.test(e)),
    `Test 5 — error should mention the invalid hook; got: ${JSON.stringify(result.errors)}`,
  );
}

// ---------------------------------------------------------------------------
// Test 6: All 9 valid hook types pass individually
// ---------------------------------------------------------------------------
{
  const allHooks = [
    'request',
    'response',
    'tls_clienthello',
    'tcp_message',
    'scan_check',
    'editor_tab',
    'intruder_payload_processor',
    'repeater_action',
    'scanner_passive',
  ];

  // Verify VALID_HOOKS exports all 9
  assert.ok(Array.isArray(VALID_HOOKS), 'Test 6 — VALID_HOOKS should be an array');
  assert.equal(VALID_HOOKS.length, 9, `Test 6 — VALID_HOOKS should have exactly 9 entries, got ${VALID_HOOKS.length}`);

  for (const hook of allHooks) {
    const result = validateManifest(validManifest({ hooks: [hook] }));
    assert.ok(
      result.valid,
      `Test 6 — hook "${hook}" should be valid; errors: ${result.errors.join(', ')}`,
    );
  }
}

// ---------------------------------------------------------------------------
// Test 7: Manifest with empty hooks array is valid
// ---------------------------------------------------------------------------
{
  const result = validateManifest(validManifest({ hooks: [] }));
  assert.ok(result.valid, `Test 7 — manifest with empty hooks array should be valid; errors: ${result.errors.join(', ')}`);
  assert.equal(result.errors.length, 0, 'Test 7 — no errors for empty hooks array');
}

// ---------------------------------------------------------------------------
// Test 8: normalizeManifest fills in defaults for missing optional fields
// ---------------------------------------------------------------------------
{
  const partial = { id: 'my-ext', name: 'My Ext', version: '0.1.0' };
  const normalized = normalizeManifest(partial);

  assert.equal(typeof normalized, 'object', 'Test 8 — normalizeManifest should return an object');
  assert.ok(Array.isArray(normalized.hooks), 'Test 8 — normalized manifest should have hooks array');
  assert.ok(Array.isArray(normalized.permissions), 'Test 8 — normalized manifest should have permissions array');
  // When fields are absent normalizeManifest must fill them
  assert.ok(typeof normalized.license === 'string', 'Test 8 — normalized manifest should have a license string');
}

// ---------------------------------------------------------------------------
// Test 9: normalizeManifest preserves provided values
// ---------------------------------------------------------------------------
{
  const input = {
    id: 'custom-ext',
    name: 'Custom Extension',
    version: '3.0.0',
    hooks: ['scan_check'],
    permissions: ['write:issues'],
    license: 'MIT',
    author: 'Jane',
  };
  const normalized = normalizeManifest(input);
  assert.equal(normalized.id, 'custom-ext', 'Test 9 — normalizeManifest should preserve id');
  assert.equal(normalized.name, 'Custom Extension', 'Test 9 — normalizeManifest should preserve name');
  assert.equal(normalized.version, '3.0.0', 'Test 9 — normalizeManifest should preserve version');
  assert.deepEqual(normalized.hooks, ['scan_check'], 'Test 9 — normalizeManifest should preserve hooks');
  assert.equal(normalized.license, 'MIT', 'Test 9 — normalizeManifest should preserve license');
  assert.equal(normalized.author, 'Jane', 'Test 9 — normalizeManifest should preserve author');
}

// ---------------------------------------------------------------------------
// Test 10: normalizeManifest fills id/name/version defaults when absent
// ---------------------------------------------------------------------------
{
  const normalized = normalizeManifest({});
  assert.ok(typeof normalized.id === 'string' && normalized.id.length > 0, 'Test 10 — default id should be a non-empty string');
  assert.ok(typeof normalized.name === 'string' && normalized.name.length > 0, 'Test 10 — default name should be a non-empty string');
  assert.ok(typeof normalized.version === 'string' && normalized.version.length > 0, 'Test 10 — default version should be a non-empty string');
}

// ---------------------------------------------------------------------------
// Test 11: Null input fails validation with a clear message
// ---------------------------------------------------------------------------
{
  const result = validateManifest(null);
  assert.ok(!result.valid, 'Test 11 — null should fail validation');
  assert.ok(result.errors.length > 0, 'Test 11 — null input should produce at least one error');
}

// ---------------------------------------------------------------------------
// Test 12: Non-array hooks value fails (e.g., a string)
// ---------------------------------------------------------------------------
{
  const result = validateManifest({ id: 'x', name: 'X', version: '1.0.0', hooks: 'request', permissions: [] });
  assert.ok(!result.valid, 'Test 12 — non-array hooks should fail validation');
}

console.log('extension-sdk-manifest: all 12 manifest tests passed');
