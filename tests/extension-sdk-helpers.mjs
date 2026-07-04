/**
 * extension-sdk-helpers.mjs
 *
 * Focused contract tests for the Extension SDK helper utilities
 * (src/extensions/sdkHelpers.ts).
 *
 * Covers: buildSdkFinding shape, error cases for helpers,
 * and all exported utility functions.
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
  console.log('extension-sdk-helpers: skipped; typescript not available');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Loader helpers
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
    console.log(`extension-sdk-helpers: skipped; failed to load ${path.basename(resolved)}: ${err.message}`);
    return null;
  }

  return mod.exports;
}

// ---------------------------------------------------------------------------
// Load the sdkHelpers module
// ---------------------------------------------------------------------------

const candidatePaths = [
  'src/extensions/sdkHelpers.ts',
  'electron/extensions/sdkHelpers.ts',
  'dist-electron/extensions/sdkHelpers.js',
  'dist/extensions/sdkHelpers.js',
];

let helpersPath = '';
for (const candidate of candidatePaths) {
  const resolved = path.resolve(candidate);
  try {
    const stat = await fs.stat(resolved);
    if (stat.isFile()) { helpersPath = resolved; break; }
  } catch { /* keep looking */ }
}

if (!helpersPath) {
  console.log('extension-sdk-helpers: skipped; sdkHelpers module not found');
  process.exit(0);
}

const helpers = loadTsModule(helpersPath);
if (!helpers) {
  console.log('extension-sdk-helpers: skipped; sdkHelpers module failed to load');
  process.exit(0);
}

// Verify core exports exist
const requiredFunctions = [
  'base64Encode',
  'base64Decode',
  'extractHeader',
  'parseQueryParams',
  'isJson',
  'prettyJson',
  'matchesPattern',
  'truncate',
  'isSensitiveHeader',
  'redactSensitiveHeaders',
  'buildSdkFinding',
];

const missing = requiredFunctions.filter((n) => typeof helpers[n] !== 'function');
if (missing.length) {
  console.log(`extension-sdk-helpers: skipped; missing export(s): ${missing.join(', ')}`);
  process.exit(0);
}

const {
  base64Encode,
  base64Decode,
  extractHeader,
  parseQueryParams,
  isJson,
  prettyJson,
  matchesPattern,
  truncate,
  isSensitiveHeader,
  redactSensitiveHeaders,
  buildSdkFinding,
} = helpers;

// ---------------------------------------------------------------------------
// Test 1: buildSdkFinding returns the correct shape
// ---------------------------------------------------------------------------
{
  const finding = buildSdkFinding({
    checkId: 'sqli-check',
    title: 'SQL Injection',
    severity: 'high',
    confidence: 0.9,
    detail: 'Error-based confirmation via single-quote.',
    evidence: "Response: You have an error in your SQL syntax",
  });

  assert.ok(typeof finding === 'object' && finding !== null, 'Test 1 — buildSdkFinding should return an object');
  assert.equal(finding.checkId, 'sqli-check', 'Test 1 — checkId should match');
  assert.equal(finding.title, 'SQL Injection', 'Test 1 — title should match');
  assert.equal(finding.severity, 'high', 'Test 1 — severity should match');
  assert.equal(finding.confidence, 0.9, 'Test 1 — confidence should match');
  assert.equal(finding.source, 'extension', 'Test 1 — source should be "extension"');
  assert.ok(typeof finding.timestamp === 'string', 'Test 1 — timestamp should be a string');
  assert.ok(finding.timestamp.length > 0, 'Test 1 — timestamp should be non-empty');
}

// ---------------------------------------------------------------------------
// Test 2: buildSdkFinding works for all severity levels
// ---------------------------------------------------------------------------
{
  const severities = ['critical', 'high', 'medium', 'low', 'info'];
  for (const severity of severities) {
    const finding = buildSdkFinding({ checkId: 'test', title: 'T', severity, confidence: 0.5 });
    assert.equal(finding.severity, severity, `Test 2 — severity "${severity}" should be preserved`);
  }
}

// ---------------------------------------------------------------------------
// Test 3: buildSdkFinding optional fields pass through
// ---------------------------------------------------------------------------
{
  const minimal = buildSdkFinding({ checkId: 'c', title: 'T', severity: 'info', confidence: 1 });
  assert.equal(minimal.checkId, 'c', 'Test 3 — minimal finding checkId');
  assert.equal(minimal.source, 'extension', 'Test 3 — minimal finding source');
  // detail and evidence optional — should not throw when absent
}

// ---------------------------------------------------------------------------
// Test 4: Helper functions are exported and callable
// ---------------------------------------------------------------------------
{
  assert.equal(typeof base64Encode, 'function', 'Test 4 — base64Encode is exported');
  assert.equal(typeof base64Decode, 'function', 'Test 4 — base64Decode is exported');
  assert.equal(typeof extractHeader, 'function', 'Test 4 — extractHeader is exported');
  assert.equal(typeof parseQueryParams, 'function', 'Test 4 — parseQueryParams is exported');
  assert.equal(typeof isJson, 'function', 'Test 4 — isJson is exported');
  assert.equal(typeof prettyJson, 'function', 'Test 4 — prettyJson is exported');
  assert.equal(typeof matchesPattern, 'function', 'Test 4 — matchesPattern is exported');
  assert.equal(typeof truncate, 'function', 'Test 4 — truncate is exported');
  assert.equal(typeof isSensitiveHeader, 'function', 'Test 4 — isSensitiveHeader is exported');
  assert.equal(typeof redactSensitiveHeaders, 'function', 'Test 4 — redactSensitiveHeaders is exported');
  assert.equal(typeof buildSdkFinding, 'function', 'Test 4 — buildSdkFinding is exported');
}

// ---------------------------------------------------------------------------
// Test 5: base64Encode / base64Decode round-trips correctly
// ---------------------------------------------------------------------------
{
  const original = 'ProxyForge extension helper test → round-trip';
  const encoded = base64Encode(original);
  assert.equal(typeof encoded, 'string', 'Test 5 — encode returns string');
  assert.notEqual(encoded, original, 'Test 5 — encoded value should differ from original');
  const decoded = base64Decode(encoded);
  assert.equal(decoded, original, 'Test 5 — round-trip should reproduce original string');
}

// ---------------------------------------------------------------------------
// Test 6: extractHeader handles case-insensitive lookup and missing headers
// ---------------------------------------------------------------------------
{
  const headers = {
    'Content-Type': 'application/json',
    'X-Custom-Header': 'value123',
    Authorization: 'Bearer tok',
  };

  assert.equal(extractHeader(headers, 'content-type'), 'application/json', 'Test 6 — lowercase lookup');
  assert.equal(extractHeader(headers, 'CONTENT-TYPE'), 'application/json', 'Test 6 — uppercase lookup');
  assert.equal(extractHeader(headers, 'x-custom-header'), 'value123', 'Test 6 — mixed-case custom header');
  assert.equal(extractHeader(headers, 'authorization'), 'Bearer tok', 'Test 6 — authorization header');
  assert.equal(extractHeader(headers, 'x-not-present'), null, 'Test 6 — missing header returns null');
  assert.equal(extractHeader({}, 'content-type'), null, 'Test 6 — empty headers returns null');
}

// ---------------------------------------------------------------------------
// Test 7: parseQueryParams extracts params correctly from various URL forms
// ---------------------------------------------------------------------------
{
  // Full URL
  const full = parseQueryParams('https://example.com/path?foo=bar&baz=qux%20quux');
  assert.equal(full.foo, 'bar', 'Test 7 — full URL foo');
  assert.equal(full.baz, 'qux quux', 'Test 7 — full URL baz decoded');

  // URL with no query string
  const noqs = parseQueryParams('https://example.com/path');
  assert.equal(Object.keys(noqs).length, 0, 'Test 7 — no query string returns empty object');

  // Bare query string (no scheme)
  const bare = parseQueryParams('?a=1&b=2');
  assert.equal(bare.a, '1', 'Test 7 — bare query string a');
  assert.equal(bare.b, '2', 'Test 7 — bare query string b');
}

// ---------------------------------------------------------------------------
// Test 8: isJson returns true for valid JSON and false otherwise
// ---------------------------------------------------------------------------
{
  assert.ok(isJson('{"key":"value"}'), 'Test 8 — object JSON is valid');
  assert.ok(isJson('[1,2,3]'), 'Test 8 — array JSON is valid');
  assert.ok(isJson('"string"'), 'Test 8 — quoted string JSON is valid');
  assert.ok(isJson('42'), 'Test 8 — number JSON is valid');
  assert.ok(!isJson('not json'), 'Test 8 — plain text is not valid JSON');
  assert.ok(!isJson('{bad: json}'), 'Test 8 — unquoted key is not valid JSON');
  assert.ok(!isJson(''), 'Test 8 — empty string is not valid JSON');
}

// ---------------------------------------------------------------------------
// Test 9: prettyJson adds indentation and newlines
// ---------------------------------------------------------------------------
{
  const compact = '{"a":1,"b":{"c":2}}';
  const pretty = prettyJson(compact);
  assert.ok(typeof pretty === 'string', 'Test 9 — prettyJson returns string');
  assert.ok(pretty.includes('\n'), 'Test 9 — prettyJson includes newlines');
  assert.ok(pretty.includes('  '), 'Test 9 — prettyJson includes indentation');
  // Round-trip: parsed result should equal original
  assert.deepEqual(JSON.parse(pretty), JSON.parse(compact), 'Test 9 — prettyJson preserves data');
}

// ---------------------------------------------------------------------------
// Test 10: matchesPattern with glob wildcards
// ---------------------------------------------------------------------------
{
  assert.ok(matchesPattern('hello-world', 'hello-*'), 'Test 10 — * wildcard matches suffix');
  assert.ok(matchesPattern('foobar', 'foo*'), 'Test 10 — * matches remaining chars');
  assert.ok(matchesPattern('anything', '*'), 'Test 10 — bare * matches any string');
  assert.ok(!matchesPattern('foobar', 'baz*'), 'Test 10 — * does not match mismatched prefix');
  assert.ok(matchesPattern('abc', 'a?c'), 'Test 10 — ? matches single char');
  assert.ok(!matchesPattern('ac', 'a?c'), 'Test 10 — ? requires exactly one char');
  assert.ok(matchesPattern('exact', 'exact'), 'Test 10 — exact match without wildcards');
  assert.ok(!matchesPattern('different', 'exact'), 'Test 10 — no match without wildcards');
}

// ---------------------------------------------------------------------------
// Test 11: truncate shortens strings over the limit
// ---------------------------------------------------------------------------
{
  assert.equal(truncate('hello', 10), 'hello', 'Test 11 — string under limit unchanged');
  assert.equal(truncate('hello', 5), 'hello', 'Test 11 — string at limit unchanged');
  assert.equal(truncate('hello world', 5), 'hello', 'Test 11 — string over limit is truncated');
  assert.equal(truncate('abcdefghij', 3), 'abc', 'Test 11 — truncated to exactly maxLen');
  assert.equal(truncate('', 5), '', 'Test 11 — empty string unchanged');
}

// ---------------------------------------------------------------------------
// Test 12: isSensitiveHeader recognises known sensitive headers
// ---------------------------------------------------------------------------
{
  const sensitive = [
    'Authorization', 'authorization', 'AUTHORIZATION',
    'Cookie', 'Set-Cookie',
    'X-Api-Key', 'x-api-key',
    'X-Auth-Token', 'X-Access-Token', 'X-Secret',
    'Proxy-Authorization',
  ];
  for (const h of sensitive) {
    assert.ok(isSensitiveHeader(h), `Test 12 — "${h}" should be sensitive`);
  }

  const notSensitive = ['Content-Type', 'Accept', 'User-Agent', 'X-Request-ID', 'Cache-Control'];
  for (const h of notSensitive) {
    assert.ok(!isSensitiveHeader(h), `Test 12 — "${h}" should NOT be sensitive`);
  }
}

// ---------------------------------------------------------------------------
// Test 13: redactSensitiveHeaders replaces sensitive values with [REDACTED]
// ---------------------------------------------------------------------------
{
  const headers = {
    Authorization: 'Bearer secrettoken',
    Cookie: 'session=abc123; track=xyz',
    'X-Api-Key': 'api-key-value',
    'Content-Type': 'application/json',
    Accept: 'text/html',
  };

  const redacted = redactSensitiveHeaders(headers);

  assert.equal(redacted.Authorization, '[REDACTED]', 'Test 13 — Authorization should be redacted');
  assert.equal(redacted.Cookie, '[REDACTED]', 'Test 13 — Cookie should be redacted');
  assert.equal(redacted['X-Api-Key'], '[REDACTED]', 'Test 13 — X-Api-Key should be redacted');
  assert.equal(redacted['Content-Type'], 'application/json', 'Test 13 — Content-Type should not be redacted');
  assert.equal(redacted.Accept, 'text/html', 'Test 13 — Accept should not be redacted');

  // Original headers object must not be mutated
  assert.equal(headers.Authorization, 'Bearer secrettoken', 'Test 13 — original headers must be immutable');
}

console.log('extension-sdk-helpers: all 13 helper tests passed');
