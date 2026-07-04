// Tests: checkPacks.ts + checkRegistry.ts
// Verifies DEFAULT/core pack exists with required check IDs, and registry maps those IDs.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let packs, registry;
try {
  packs    = require('../dist-electron/src/scanner/checkPacks.js');
  registry = require('../dist-electron/src/scanner/checkRegistry.js');
} catch {
  console.log('SKIP: scanner/checkPacks or scanner/checkRegistry not compiled');
  process.exit(0);
}

try {
  const { CHECK_PACKS, getCheckPack, getDefaultCheckPack } = packs;
  const { getAllCheckIds, getCheck, getAllChecks, getCheckCount } = registry;

  // ── CHECK_PACKS array exists and is large enough ─────────────────────────
  assert.ok(Array.isArray(CHECK_PACKS), 'CHECK_PACKS must be an array');
  assert.ok(CHECK_PACKS.length >= 1, 'CHECK_PACKS must have at least one pack');

  // ── pf-core pack has ≥7 check IDs ────────────────────────────────────────
  const corePack = getCheckPack('pf-core');
  assert.ok(corePack, 'getCheckPack("pf-core") must return a pack');
  assert.ok(Array.isArray(corePack.checks), 'pf-core.checks must be an array');
  assert.ok(corePack.checks.length >= 7, `pf-core must have ≥7 checks, got ${corePack.checks.length}`);

  // ── pf-core includes the canonical injection check IDs ───────────────────
  const requiredIds = ['sql-injection', 'xss-reflected', 'command-injection', 'ssrf', 'open-redirect'];
  for (const id of requiredIds) {
    assert.ok(
      corePack.checks.includes(id),
      `pf-core.checks must include '${id}'`,
    );
  }

  // ── getDefaultCheckPack returns pf-core ──────────────────────────────────
  const defaultPack = getDefaultCheckPack();
  assert.ok(defaultPack, 'getDefaultCheckPack() must return a pack');
  assert.equal(defaultPack.id, 'pf-core', 'Default pack must be pf-core');

  // ── getAllCheckIds returns all registry IDs ───────────────────────────────
  const allIds = getAllCheckIds();
  assert.ok(Array.isArray(allIds), 'getAllCheckIds() must return an array');
  assert.ok(allIds.length >= 7, `Registry must have ≥7 checks, got ${allIds.length}`);

  for (const id of requiredIds) {
    assert.ok(allIds.includes(id), `Registry must include check '${id}'`);
  }

  // ── getCheck returns a definition object for each required ID ────────────
  for (const id of requiredIds) {
    const def = getCheck(id);
    assert.ok(def, `getCheck('${id}') must return a definition`);
    assert.equal(def.id, id, `definition.id must equal '${id}'`);
    assert.ok(def.family, `definition for '${id}' must have a family`);
    assert.ok(def.metadata, `definition for '${id}' must have metadata`);
    assert.equal(typeof def.variants, 'function', `definition for '${id}' must have a variants function`);
  }

  // ── getAllChecks returns objects with id + family ─────────────────────────
  const allChecks = getAllChecks();
  assert.ok(Array.isArray(allChecks), 'getAllChecks() must return an array');
  assert.ok(allChecks.length >= 7, `getAllChecks() must return ≥7 entries`);
  for (const check of allChecks) {
    assert.ok(check.id, 'Each check must have an id');
    assert.ok(check.family, 'Each check must have a family');
  }

  // ── getCheckCount matches length of getAllCheckIds ────────────────────────
  assert.equal(getCheckCount(), allIds.length, 'getCheckCount() must match getAllCheckIds().length');

  console.log(`PASS scanner-vantix-core-fixture (${allIds.length} checks, pf-core has ${corePack.checks.length})`);
} catch (err) {
  console.error('FAIL scanner-vantix-core-fixture:', err.message);
  process.exit(1);
}
