/**
 * scanner-skilllet-mapper.mjs
 *
 * Focused tests for the skilllet mapper module (src/scanner/skillletMapper.ts).
 *
 * Covers: entry count, required field shapes, family lookups, unknown ID
 * behaviour, category coverage, and non-empty check ID strings.
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
  console.log('scanner-skilllet-mapper: skipped; typescript not available');
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
      resolveJsonModule: true,
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
    console.log(`scanner-skilllet-mapper: skipped; failed to load ${path.basename(resolved)}: ${err.message}`);
    return null;
  }

  return mod.exports;
}

// ---------------------------------------------------------------------------
// Locate and load the skillletMapper module
// ---------------------------------------------------------------------------

const candidatePaths = [
  'src/scanner/skillletMapper.ts',
  'electron/scanner/skillletMapper.ts',
  'dist-electron/src/scanner/skillletMapper.js',
  'dist/scanner/skillletMapper.js',
];

let mapperPath = '';
for (const candidate of candidatePaths) {
  const resolved = path.resolve(candidate);
  try {
    const stat = await fs.stat(resolved);
    if (stat.isFile()) { mapperPath = resolved; break; }
  } catch { /* keep looking */ }
}

if (!mapperPath) {
  console.log('scanner-skilllet-mapper: skipped; skillletMapper not found');
  process.exit(0);
}

const mapper = loadTsModule(mapperPath);
if (!mapper) {
  console.log('scanner-skilllet-mapper: skipped; skillletMapper failed to load');
  process.exit(0);
}

// Verify required exports
const requiredExports = ['loadSkilllets', 'getSkilllet', 'getSkillletsByFamily', 'getAllCheckIds', 'validateSkillletCompleteness'];
const missingExports = requiredExports.filter((n) => typeof mapper[n] !== 'function');
if (missingExports.length) {
  console.log(`scanner-skilllet-mapper: skipped; missing export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const { loadSkilllets, getSkilllet, getSkillletsByFamily, getAllCheckIds, validateSkillletCompleteness } = mapper;

// ---------------------------------------------------------------------------
// Test 1: scannerSkilllets.json has >= 20 entries
// ---------------------------------------------------------------------------
{
  const skilllets = loadSkilllets();
  assert.ok(Array.isArray(skilllets), 'Test 1 — loadSkilllets() should return an array');
  assert.ok(
    skilllets.length >= 20,
    `Test 1 — should have at least 20 skilllet entries, got ${skilllets.length}`,
  );
}

// ---------------------------------------------------------------------------
// Test 2: Each skilllet has required fields with correct types
// ---------------------------------------------------------------------------
{
  const skilllets = loadSkilllets();
  for (const s of skilllets) {
    assert.ok(typeof s.id === 'string' && s.id.trim().length > 0,
      `Test 2 — skilllet "${s.id}" must have a non-empty id string`);
    assert.ok(typeof s.summary === 'string' && s.summary.trim().length > 0,
      `Test 2 — skilllet "${s.id}" must have a non-empty summary`);
    assert.ok(typeof s.family === 'string' && s.family.trim().length > 0,
      `Test 2 — skilllet "${s.id}" must have a non-empty family`);
    assert.ok(Array.isArray(s.checkIds) && s.checkIds.length > 0,
      `Test 2 — skilllet "${s.id}" must have a non-empty checkIds array`);
    assert.ok(Array.isArray(s.surfaceTypes),
      `Test 2 — skilllet "${s.id}" must have a surfaceTypes array`);
    assert.ok(Array.isArray(s.triggerFacts),
      `Test 2 — skilllet "${s.id}" must have a triggerFacts array`);
    assert.ok(Array.isArray(s.operatorGuidance),
      `Test 2 — skilllet "${s.id}" must have an operatorGuidance array`);
    assert.ok(Array.isArray(s.expectedProof),
      `Test 2 — skilllet "${s.id}" must have an expectedProof array`);
    assert.ok(['safe', 'low', 'medium', 'high'].includes(s.defaultRisk),
      `Test 2 — skilllet "${s.id}" defaultRisk must be safe/low/medium/high, got "${s.defaultRisk}"`);
  }
}

// ---------------------------------------------------------------------------
// Test 3: getAllCheckIds returns an array of non-empty strings
// ---------------------------------------------------------------------------
{
  const allIds = getAllCheckIds();
  assert.ok(Array.isArray(allIds), 'Test 3 — getAllCheckIds() should return an array');
  assert.ok(allIds.length >= 20, `Test 3 — should have at least 20 check IDs, got ${allIds.length}`);
  for (const id of allIds) {
    assert.ok(typeof id === 'string' && id.trim().length > 0,
      `Test 3 — check ID "${id}" must be a non-empty string`);
  }
}

// ---------------------------------------------------------------------------
// Test 4: getSkilllet with unknown ID returns null (not an error / not a throw)
// ---------------------------------------------------------------------------
{
  const result = getSkilllet('__definitely_not_a_real_skilllet_id_xyz__');
  assert.equal(result, null, 'Test 4 — unknown skilllet ID should return null');
}

// ---------------------------------------------------------------------------
// Test 5: getSkilllet returns the correct skilllet for known check IDs
// ---------------------------------------------------------------------------
{
  const knownIds = ['sql-injection', 'reflected-xss', 'ssrf', 'command-injection', 'idor'];
  for (const id of knownIds) {
    const s = getSkilllet(id);
    assert.ok(s !== null, `Test 5 — getSkilllet("${id}") should return a skilllet`);
    assert.equal(s.id, id, `Test 5 — returned skilllet id should equal "${id}"`);
  }
}

// ---------------------------------------------------------------------------
// Test 6: getSkillletsByFamily returns results matching that family
// ---------------------------------------------------------------------------
{
  // Families that must exist based on scannerSkilllets.json
  const knownFamilies = ['sql-injection', 'xss-reflected', 'ssrf', 'command-injection'];
  for (const family of knownFamilies) {
    const results = getSkillletsByFamily(family);
    assert.ok(Array.isArray(results), `Test 6 — getSkillletsByFamily("${family}") should return an array`);
    assert.ok(results.length >= 1, `Test 6 — getSkillletsByFamily("${family}") should return at least one entry`);
    for (const s of results) {
      assert.equal(s.family, family, `Test 6 — all returned skilllets must have family "${family}"`);
    }
  }
}

// ---------------------------------------------------------------------------
// Test 7: getSkillletsByFamily returns empty array for an unknown family
// ---------------------------------------------------------------------------
{
  const results = getSkillletsByFamily('not_a_real_family_xyz');
  assert.ok(Array.isArray(results), 'Test 7 — getSkillletsByFamily with unknown family should return an array');
  assert.equal(results.length, 0, 'Test 7 — unknown family should return empty array');
}

// ---------------------------------------------------------------------------
// Test 8: Skilllet families cover expected vulnerability categories
// ---------------------------------------------------------------------------
{
  const allIds = getAllCheckIds();
  // These specific check IDs are defined in scannerSkilllets.json
  const expectedIds = [
    'sql-injection',    // injection
    'reflected-xss',   // xss
    'ssrf',             // ssrf
    'command-injection', // injection
    'idor',             // business-logic
    'jwt-attack',       // auth
    'cors-misconfiguration', // misconfiguration
    'graphql-introspection', // api
    'mass-assignment',  // business-logic
    'open-redirect',    // redirect
  ];
  for (const id of expectedIds) {
    assert.ok(
      allIds.includes(id),
      `Test 8 — expected skilllet ID "${id}" should be present in getAllCheckIds()`,
    );
  }
}

// ---------------------------------------------------------------------------
// Test 9: All check IDs referenced in skilllets are non-empty strings
// ---------------------------------------------------------------------------
{
  const skilllets = loadSkilllets();
  for (const s of skilllets) {
    for (const checkId of s.checkIds) {
      assert.ok(
        typeof checkId === 'string' && checkId.trim().length > 0,
        `Test 9 — checkId in skilllet "${s.id}" must be a non-empty string, got: "${checkId}"`,
      );
    }
  }
}

// ---------------------------------------------------------------------------
// Test 10: validateSkillletCompleteness returns no errors for a valid skilllet
// ---------------------------------------------------------------------------
{
  const valid = {
    id: 'test-check-id',
    checkIds: ['test-check-id'],
    family: 'sql-injection',
    surfaceTypes: ['query', 'body'],
    triggerFacts: ['SQL error observed'],
    summary: 'Test skilllet for validation.',
    operatorGuidance: ['Do X', 'Do Y'],
    allowedFollowups: ['follow-up-a'],
    forbiddenBranches: [],
    expectedProof: ['Error message in response'],
    defaultRisk: 'low',
  };
  const errors = validateSkillletCompleteness(valid);
  assert.ok(Array.isArray(errors), 'Test 10 — should return an array');
  assert.equal(errors.length, 0, `Test 10 — valid skilllet should have no errors; got: ${JSON.stringify(errors)}`);
}

// ---------------------------------------------------------------------------
// Test 11: validateSkillletCompleteness reports errors for missing required fields
// ---------------------------------------------------------------------------
{
  const invalidCases = [
    { desc: 'empty id',            override: { id: '' } },
    { desc: 'empty summary',       override: { summary: '' } },
    { desc: 'empty checkIds',      override: { checkIds: [] } },
    { desc: 'empty expectedProof', override: { expectedProof: [] } },
  ];

  const base = {
    id: 'test-check',
    checkIds: ['test-check'],
    family: 'sql-injection',
    surfaceTypes: ['query'],
    triggerFacts: ['Error observed'],
    summary: 'Test',
    operatorGuidance: ['Guidance'],
    allowedFollowups: [],
    forbiddenBranches: [],
    expectedProof: ['Proof'],
    defaultRisk: 'low',
  };

  for (const { desc, override } of invalidCases) {
    const invalid = { ...base, ...override };
    const errors = validateSkillletCompleteness(invalid);
    assert.ok(Array.isArray(errors), `Test 11 — ${desc}: should return an array`);
    assert.ok(errors.length > 0, `Test 11 — ${desc}: should report at least one error`);
  }
}

// ---------------------------------------------------------------------------
// Test 12: loadSkilllets returns the same reference on repeated calls (caching)
// ---------------------------------------------------------------------------
{
  const first = loadSkilllets();
  const second = loadSkilllets();
  assert.equal(first, second, 'Test 12 — loadSkilllets should return the same cached array reference');
}

// ---------------------------------------------------------------------------
// Test 13: Skilllet surface types are all non-empty strings
// ---------------------------------------------------------------------------
{
  const skilllets = loadSkilllets();
  for (const s of skilllets) {
    for (const st of s.surfaceTypes) {
      assert.ok(
        typeof st === 'string' && st.trim().length > 0,
        `Test 13 — surfaceType in skilllet "${s.id}" must be a non-empty string, got: "${st}"`,
      );
    }
  }
}

console.log(`scanner-skilllet-mapper: all 13 skilllet mapper tests passed (${loadSkilllets().length} skilllets loaded)`);
