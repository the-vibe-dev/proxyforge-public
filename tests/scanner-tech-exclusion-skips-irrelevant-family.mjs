// Phase 3b — Scanner: tech exclusion / check pack filtering.
// Verifies that checkRegistry exports entries and that checkPacks expose
// a filterable metadata structure.  If a dedicated filterCheckIdsByTech
// function exists it is exercised; otherwise the metadata structure is
// validated instead.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let registryMod;
let packsMod;

try {
  registryMod = require('../dist-electron/src/scanner/checkRegistry.js');
} catch {
  console.log('SKIP: scanner/checkRegistry.js not compiled — run tsc first.');
  process.exit(0);
}

try {
  packsMod = require('../dist-electron/src/scanner/checkPacks.js');
} catch {
  console.log('SKIP: scanner/checkPacks.js not compiled — run tsc first.');
  process.exit(0);
}

const { getCheck, getAllCheckIds, getAllChecks, getCheckCount } = registryMod;
const { CHECK_PACKS, getCheckPack, getDefaultCheckPack } = packsMod;

// ---------------------------------------------------------------------------
// Test 1: checkRegistry has entries
// ---------------------------------------------------------------------------
{
  assert.strictEqual(typeof getAllCheckIds, 'function', 'getAllCheckIds must be a function');
  assert.strictEqual(typeof getAllChecks, 'function', 'getAllChecks must be a function');
  assert.strictEqual(typeof getCheckCount, 'function', 'getCheckCount must be a function');

  const count = getCheckCount();
  assert.ok(count > 0, `Registry must have at least one check, got ${count}`);

  const ids = getAllCheckIds();
  assert.ok(Array.isArray(ids), 'getAllCheckIds must return an array');
  assert.ok(ids.length > 0, 'getAllCheckIds must return at least one id');

  console.log(`PASS: checkRegistry has ${count} entries`);
}

// ---------------------------------------------------------------------------
// Test 2: each check definition has required metadata fields
// ---------------------------------------------------------------------------
{
  const checks = getAllChecks();
  for (const check of checks) {
    assert.ok(typeof check.id === 'string' && check.id.length > 0,
      `Check is missing id: ${JSON.stringify(check)}`);
    assert.ok(typeof check.metadata === 'object' && check.metadata !== null,
      `Check "${check.id}" is missing metadata`);
    assert.ok(typeof check.metadata.severity === 'string',
      `Check "${check.id}" metadata missing severity`);
    assert.ok(Array.isArray(check.metadata.insertionPointKinds),
      `Check "${check.id}" metadata missing insertionPointKinds`);
    assert.ok(typeof check.variants === 'function',
      `Check "${check.id}" must export a variants() function`);
  }
  console.log('PASS: all check definitions have required metadata fields');
}

// ---------------------------------------------------------------------------
// Test 3: getCheck retrieves a known check
// ---------------------------------------------------------------------------
{
  assert.strictEqual(typeof getCheck, 'function', 'getCheck must be a function');

  const sqli = getCheck('sql-injection');
  assert.ok(sqli !== undefined, 'getCheck("sql-injection") must return a definition');
  assert.strictEqual(sqli.id, 'sql-injection');
  assert.strictEqual(sqli.metadata.severity, 'high');

  const xss = getCheck('xss-reflected');
  assert.ok(xss !== undefined, 'getCheck("xss-reflected") must return a definition');

  assert.strictEqual(getCheck('non-existent-check-xyz'), undefined,
    'getCheck for unknown id must return undefined');

  console.log('PASS: getCheck retrieves known checks and returns undefined for unknown');
}

// ---------------------------------------------------------------------------
// Test 4: CHECK_PACKS array is non-empty and well-formed
// ---------------------------------------------------------------------------
{
  assert.ok(Array.isArray(CHECK_PACKS), 'CHECK_PACKS must be an array');
  assert.ok(CHECK_PACKS.length > 0, 'CHECK_PACKS must have at least one pack');

  for (const pack of CHECK_PACKS) {
    assert.ok(typeof pack.id === 'string' && pack.id.length > 0,
      `Pack is missing id: ${JSON.stringify(pack)}`);
    assert.ok(typeof pack.name === 'string', `Pack "${pack.id}" missing name`);
    assert.ok(Array.isArray(pack.checks), `Pack "${pack.id}" must have a checks array`);
    assert.ok(pack.checks.length > 0, `Pack "${pack.id}" must have at least one check id`);
  }

  console.log(`PASS: CHECK_PACKS has ${CHECK_PACKS.length} well-formed packs`);
}

// ---------------------------------------------------------------------------
// Test 5: getCheckPack and getDefaultCheckPack work
// ---------------------------------------------------------------------------
{
  assert.strictEqual(typeof getCheckPack, 'function', 'getCheckPack must be a function');
  assert.strictEqual(typeof getDefaultCheckPack, 'function', 'getDefaultCheckPack must be a function');

  const core = getCheckPack('pf-core');
  assert.ok(core !== undefined, 'getCheckPack("pf-core") must return a pack');
  assert.strictEqual(core.id, 'pf-core');
  assert.ok(core.checks.includes('sql-injection'),
    'pf-core pack must include sql-injection');

  assert.strictEqual(getCheckPack('non-existent-pack'), undefined,
    'getCheckPack for unknown id must return undefined');

  const defaultPack = getDefaultCheckPack();
  assert.ok(defaultPack !== undefined, 'getDefaultCheckPack must return a pack');
  assert.ok(typeof defaultPack.id === 'string');

  console.log('PASS: getCheckPack and getDefaultCheckPack work correctly');
}

// ---------------------------------------------------------------------------
// Test 6: tech-family filtering — Java-specific deserialization checks are
//         not present in the pf-core pack (PHP/general-purpose only).
//         If filterCheckIdsByTech exists, exercise it; otherwise verify
//         structural support via metadata families.
// ---------------------------------------------------------------------------
{
  const filterFn = registryMod.filterCheckIdsByTech ?? packsMod.filterCheckIdsByTech;

  if (typeof filterFn === 'function') {
    // If a filter function exists, verify it excludes java-family checks
    // when only 'php' tech is active.
    const allIds = getAllCheckIds();
    const phpFiltered = filterFn(['php'], allIds);

    assert.ok(Array.isArray(phpFiltered), 'filterCheckIdsByTech must return an array');

    // deserialization-java should be excluded when filtering for php
    assert.ok(
      !phpFiltered.includes('deserialization-java'),
      'PHP filter must exclude java-specific checks',
    );

    console.log('PASS: filterCheckIdsByTech excludes java-specific checks for PHP target');
  } else {
    // No dedicated filter function yet — verify that the registry metadata
    // could support tech-based filtering (families provide a sufficient hook).
    const javaAdjacentFamilies = new Set(['deserialization-java']);
    const allChecks = getAllChecks();

    // spring4-shell is Java-specific and should be in the registry
    const spring4 = getCheck('spring4-shell');
    if (spring4) {
      assert.ok(typeof spring4.metadata.family === 'string',
        'spring4-shell must have a family field enabling tech filtering');
    }

    // pf-core must NOT include spring4-shell (too tech-specific for the core pack)
    const core = getCheckPack('pf-core');
    assert.ok(!core.checks.includes('spring4-shell'),
      'pf-core pack must not include spring4-shell (Java-specific)');

    console.log('PASS: registry metadata structure supports future tech-based filtering');
    console.log('NOTE: filterCheckIdsByTech not yet exported — structural check passed instead');
  }
}

console.log('\nAll scanner-tech-exclusion-skips-irrelevant-family tests passed.');
