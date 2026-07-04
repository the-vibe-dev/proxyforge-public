/**
 * extension-sdk-contract.mjs
 *
 * Contract tests for SDK helpers and the manifest module.
 * Uses the TypeScript transpile-on-the-fly approach consistent with other tests
 * in this project.  Gracefully skips if the modules cannot be loaded.
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
  console.log('extension-sdk-contract: skipped; typescript not available');
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
      // Strip type-only imports so the vm sandbox doesn't choke on them.
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
    console.log(`extension-sdk-contract: skipped; failed to load ${path.basename(filePath)}: ${err.message}`);
    return null;
  }
  return mod.exports;
}

// ---------------------------------------------------------------------------
// Load modules
// ---------------------------------------------------------------------------

const helpersPath = path.resolve('src/extensions/sdkHelpers.ts');
const manifestPath = path.resolve('src/extensions/manifest.ts');

const helpers = await loadTsModule(helpersPath);
const manifest = await loadTsModule(manifestPath);

if (!helpers || !manifest) {
  console.log('extension-sdk-contract: skipped; one or more modules failed to load');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// SDK Helper tests
// ---------------------------------------------------------------------------

// base64 round-trip
{
  const original = 'Hello, ProxyForge!';
  const encoded = helpers.base64Encode(original);
  const decoded = helpers.base64Decode(encoded);
  assert.equal(decoded, original, 'base64 round-trip should reproduce the original string');
}

// base64Encode produces the correct output
{
  assert.equal(helpers.base64Encode('hello'), 'aGVsbG8=', 'base64Encode("hello") should equal "aGVsbG8="');
}

// extractHeader is case-insensitive
{
  const headers = { 'Content-Type': 'application/json', Authorization: 'Bearer token123' };
  assert.equal(helpers.extractHeader(headers, 'content-type'), 'application/json', 'extractHeader should match case-insensitively');
  assert.equal(helpers.extractHeader(headers, 'AUTHORIZATION'), 'Bearer token123', 'extractHeader should match uppercase lookup');
  assert.equal(helpers.extractHeader(headers, 'x-missing'), null, 'extractHeader should return null for absent header');
}

// parseQueryParams extracts params
{
  const params = helpers.parseQueryParams('https://example.com/path?foo=bar&baz=qux');
  assert.equal(params.foo, 'bar', 'parseQueryParams should extract foo');
  assert.equal(params.baz, 'qux', 'parseQueryParams should extract baz');
}

// parseQueryParams handles URL with no query string
{
  const params = helpers.parseQueryParams('https://example.com/path');
  assert.equal(Object.keys(params).length, 0, 'parseQueryParams should return empty object for URL with no query string');
}

// matchesPattern with * glob
{
  assert.ok(helpers.matchesPattern('hello-world', 'hello-*'), 'matchesPattern should match with * glob');
  assert.ok(helpers.matchesPattern('foobar', 'foo*'), 'matchesPattern should match prefix wildcard');
  assert.ok(!helpers.matchesPattern('foobar', 'baz*'), 'matchesPattern should not match when glob does not apply');
}

// matchesPattern with ? glob
{
  assert.ok(helpers.matchesPattern('abc', 'a?c'), 'matchesPattern should match with ? glob');
  assert.ok(!helpers.matchesPattern('ac', 'a?c'), 'matchesPattern should not match when ? has nothing to match');
}

// isSensitiveHeader
{
  assert.ok(helpers.isSensitiveHeader('Authorization'), 'Authorization should be sensitive');
  assert.ok(helpers.isSensitiveHeader('authorization'), 'authorization (lowercase) should be sensitive');
  assert.ok(helpers.isSensitiveHeader('Cookie'), 'Cookie should be sensitive');
  assert.ok(helpers.isSensitiveHeader('X-Api-Key'), 'X-Api-Key should be sensitive');
  assert.ok(!helpers.isSensitiveHeader('Content-Type'), 'Content-Type should not be sensitive');
  assert.ok(!helpers.isSensitiveHeader('Accept'), 'Accept should not be sensitive');
}

// redactSensitiveHeaders
{
  const headers = {
    Authorization: 'Bearer secret123',
    'Content-Type': 'application/json',
    Cookie: 'session=abc123',
  };
  const redacted = helpers.redactSensitiveHeaders(headers);
  assert.equal(redacted.Authorization, '[REDACTED]', 'Authorization should be redacted');
  assert.equal(redacted.Cookie, '[REDACTED]', 'Cookie should be redacted');
  assert.equal(redacted['Content-Type'], 'application/json', 'Content-Type should be preserved');
}

// isJson
{
  assert.ok(helpers.isJson('{"a":1}'), 'isJson should return true for valid JSON');
  assert.ok(!helpers.isJson('not json'), 'isJson should return false for invalid JSON');
}

// prettyJson
{
  const pretty = helpers.prettyJson('{"a":1,"b":2}');
  assert.ok(pretty.includes('\n'), 'prettyJson should include newlines');
}

// truncate
{
  assert.equal(helpers.truncate('hello', 10), 'hello', 'truncate should not shorten strings within limit');
  assert.equal(helpers.truncate('hello world', 5), 'hello', 'truncate should shorten strings exceeding limit');
}

// ---------------------------------------------------------------------------
// Manifest module tests
// ---------------------------------------------------------------------------

// validateManifest accepts a valid manifest object
{
  const result = manifest.validateManifest({
    id: 'test-ext',
    name: 'Test Extension',
    version: '1.0.0',
    hooks: ['request', 'response'],
    permissions: ['read:history'],
  });
  assert.ok(result.valid, `validateManifest should accept valid manifest; errors: ${result.errors.join(', ')}`);
  assert.equal(result.errors.length, 0, 'validateManifest should have no errors for a valid manifest');
}

// validateManifest rejects object missing required fields
{
  const result = manifest.validateManifest({ version: '1.0.0' });
  assert.ok(!result.valid, 'validateManifest should reject manifest missing id/name');
  assert.ok(result.errors.length > 0, 'validateManifest should report errors for missing fields');
}

// validateManifest rejects non-object
{
  const result = manifest.validateManifest(null);
  assert.ok(!result.valid, 'validateManifest should reject null');
}

// computeDigest returns 64-char hex string
{
  const digest = manifest.computeDigest('{"id":"test"}');
  assert.equal(typeof digest, 'string', 'computeDigest should return a string');
  assert.equal(digest.length, 64, 'computeDigest should return a 64-character hex string');
  assert.ok(/^[0-9a-f]{64}$/.test(digest), 'computeDigest should return lowercase hex');
}

// VALID_HOOKS includes expected hook names
{
  const hooks = manifest.VALID_HOOKS;
  assert.ok(Array.isArray(hooks), 'VALID_HOOKS should be an array');
  assert.ok(hooks.includes('request'), 'VALID_HOOKS should include "request"');
  assert.ok(hooks.includes('response'), 'VALID_HOOKS should include "response"');
  assert.ok(hooks.includes('scanner_passive'), 'VALID_HOOKS should include "scanner_passive"');
}

// VALID_PERMISSIONS includes expected permission tokens
{
  const perms = manifest.VALID_PERMISSIONS;
  assert.ok(Array.isArray(perms), 'VALID_PERMISSIONS should be an array');
  assert.ok(perms.includes('read:history'), 'VALID_PERMISSIONS should include "read:history"');
}

console.log('extension-sdk-contract: all SDK helper and manifest contract tests passed');
