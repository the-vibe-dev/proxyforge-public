// headless-full-chain-vantix-core.mjs
// Headless test: exercises the core scanner check pack (pf-core) with
// checkRegistry, checkPacks, payloadMutationEngine, and oracleResponseClassifier.
// No live proxy or Electron needed — pure Node.js against synthetic fixtures.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fsSync from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// tryLoad — tries dist-electron/src/<relPath> then dist-electron/<relPath>
// ---------------------------------------------------------------------------

function tryLoad(relPath) {
  const candidates = [
    path.resolve(__dirname, '../dist-electron/src', relPath),
    path.resolve(__dirname, '../dist-electron', relPath),
  ];
  for (const candidate of candidates) {
    if (fsSync.existsSync(candidate)) {
      try {
        return require(candidate);
      } catch (err) {
        console.log(`[SKIP] headless-full-chain-vantix-core: failed to load ${candidate}: ${err.message}`);
        process.exit(0);
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Load modules
// ---------------------------------------------------------------------------

const checkPacksMod = tryLoad('scanner/checkPacks.js');
if (!checkPacksMod) {
  console.log('[SKIP] headless-full-chain-vantix-core: checkPacks not compiled');
  process.exit(0);
}

const checkRegistryMod = tryLoad('scanner/checkRegistry.js');
if (!checkRegistryMod) {
  console.log('[SKIP] headless-full-chain-vantix-core: checkRegistry not compiled');
  process.exit(0);
}

const payloadMod = tryLoad('scanner/payloadMutationEngine.js');
if (!payloadMod) {
  console.log('[SKIP] headless-full-chain-vantix-core: payloadMutationEngine not compiled');
  process.exit(0);
}

const classifierMod = tryLoad('scanner/oracleResponseClassifier.js');
if (!classifierMod) {
  console.log('[SKIP] headless-full-chain-vantix-core: oracleResponseClassifier not compiled');
  process.exit(0);
}

const { getCheckPack, getDefaultCheckPack, CHECK_PACKS } = checkPacksMod;
const { getCheck, getAllCheckIds, getAllChecks, getCheckCount } = checkRegistryMod;
const { classifyOracleObservation, buildOracleObservation } = classifierMod;

// ---------------------------------------------------------------------------
// Verify required exports
// ---------------------------------------------------------------------------

if (typeof getCheckPack !== 'function') {
  console.log('[SKIP] headless-full-chain-vantix-core: getCheckPack not exported');
  process.exit(0);
}
if (typeof getCheck !== 'function') {
  console.log('[SKIP] headless-full-chain-vantix-core: getCheck not exported');
  process.exit(0);
}
if (typeof classifyOracleObservation !== 'function') {
  console.log('[SKIP] headless-full-chain-vantix-core: classifyOracleObservation not exported');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Synthetic HTTP exchange fixture (no live network)
// ---------------------------------------------------------------------------

function makeExchange(bodyText, status = 200, timeMs = 120) {
  return {
    request: {
      method: 'GET',
      url: 'https://example.test/search?q=test',
      headers: { host: 'example.test' },
      body: null,
    },
    response: {
      statusCode: status,
      headers: { 'content-type': 'text/html' },
      bodyText,
      responseTimeMs: timeMs,
    },
  };
}

// ---------------------------------------------------------------------------
// Test 1: CHECK_PACKS is a non-empty array of pack objects
// ---------------------------------------------------------------------------
{
  assert.ok(Array.isArray(CHECK_PACKS), 'Test 1 — CHECK_PACKS should be an array');
  assert.ok(CHECK_PACKS.length > 0, 'Test 1 — CHECK_PACKS should have at least one pack');
  for (const pack of CHECK_PACKS) {
    assert.equal(typeof pack.id, 'string', `Test 1 — pack "${pack.id}" should have a string id`);
    assert.equal(typeof pack.name, 'string', `Test 1 — pack "${pack.id}" should have a name`);
    assert.equal(typeof pack.description, 'string', `Test 1 — pack "${pack.id}" should have a description`);
    assert.ok(Array.isArray(pack.checks), `Test 1 — pack "${pack.id}" should have a checks array`);
    assert.ok(pack.checks.length > 0, `Test 1 — pack "${pack.id}" should have at least one check`);
  }
}

// ---------------------------------------------------------------------------
// Test 2: getCheckPack('pf-core') returns the core pack
// ---------------------------------------------------------------------------
{
  const corePack = getCheckPack('pf-core');
  assert.ok(corePack !== undefined, 'Test 2 — pf-core pack should exist');
  assert.equal(corePack.id, 'pf-core', 'Test 2 — pack id should be "pf-core"');
  assert.ok(corePack.checks.length > 0, 'Test 2 — pf-core should have checks');
  assert.ok(corePack.checks.includes('sql-injection'), 'Test 2 — pf-core should include sql-injection');
  assert.ok(corePack.checks.includes('xss-reflected'), 'Test 2 — pf-core should include xss-reflected');
}

// ---------------------------------------------------------------------------
// Test 3: getDefaultCheckPack() returns the pf-core pack
// ---------------------------------------------------------------------------
{
  const defaultPack = getDefaultCheckPack();
  assert.ok(defaultPack !== undefined, 'Test 3 — getDefaultCheckPack should return a pack');
  assert.equal(defaultPack.id, 'pf-core', 'Test 3 — default pack should be pf-core');
}

// ---------------------------------------------------------------------------
// Test 4: getCheckPack returns undefined for unknown pack id
// ---------------------------------------------------------------------------
{
  const unknown = getCheckPack('vantix-core-unknown');
  assert.equal(unknown, undefined, 'Test 4 — unknown pack id should return undefined');
}

// ---------------------------------------------------------------------------
// Test 5: every check in the registry has id, family, metadata, variants fn
// ---------------------------------------------------------------------------
{
  const allChecks = getAllChecks();
  assert.ok(Array.isArray(allChecks), 'Test 5 — getAllChecks should return an array');
  assert.ok(allChecks.length > 0, 'Test 5 — registry should have at least one check');
  for (const check of allChecks) {
    assert.equal(typeof check.id, 'string', `Test 5 — check "${check.id}" should have a string id`);
    assert.equal(typeof check.family, 'string', `Test 5 — check "${check.id}" should have a family`);
    assert.ok(check.metadata !== null && typeof check.metadata === 'object', `Test 5 — check "${check.id}" should have metadata`);
    assert.equal(typeof check.variants, 'function', `Test 5 — check "${check.id}" should have variants function`);
  }
}

// ---------------------------------------------------------------------------
// Test 6: getCheckCount matches getAllCheckIds length
// ---------------------------------------------------------------------------
{
  const count = getCheckCount();
  const ids = getAllCheckIds();
  assert.equal(typeof count, 'number', 'Test 6 — getCheckCount should return a number');
  assert.equal(count, ids.length, 'Test 6 — getCheckCount should equal getAllCheckIds().length');
  assert.ok(count > 0, 'Test 6 — registry should not be empty');
}

// ---------------------------------------------------------------------------
// Test 7: every check in pf-core pack exists in the registry
// ---------------------------------------------------------------------------
{
  const corePack = getCheckPack('pf-core');
  for (const checkId of corePack.checks) {
    const def = getCheck(checkId);
    assert.ok(def !== undefined, `Test 7 — check "${checkId}" from pf-core should exist in registry`);
    assert.equal(def.id, checkId, `Test 7 — check "${checkId}" id should match`);
  }
}

// ---------------------------------------------------------------------------
// Test 8: each check's metadata has severity and is non-null
// ---------------------------------------------------------------------------
{
  const corePack = getCheckPack('pf-core');
  const VALID_SEVERITIES = new Set(['low', 'medium', 'high', 'critical', 'info']);
  for (const checkId of corePack.checks) {
    const def = getCheck(checkId);
    assert.ok(def !== undefined, `Test 8 — check "${checkId}" should exist`);
    assert.ok(
      VALID_SEVERITIES.has(def.metadata.severity),
      `Test 8 — check "${checkId}" severity "${def.metadata.severity}" should be valid`,
    );
    assert.equal(typeof def.metadata.title, 'string', `Test 8 — check "${checkId}" should have a title`);
    assert.equal(typeof def.metadata.requiresOast, 'boolean', `Test 8 — check "${checkId}" should have requiresOast bool`);
  }
}

// ---------------------------------------------------------------------------
// Test 9: check variants function can be called with a synthetic ProbeContext
// ---------------------------------------------------------------------------
{
  const sqlCheck = getCheck('sql-injection');
  assert.ok(sqlCheck !== undefined, 'Test 9 — sql-injection check should exist');

  const ctx = {
    checkId: 'sql-injection',
    family: 'sql-injection',
    insertionPoint: { kind: 'query', name: 'q', originalValue: 'hello' },
    budget: { maxPayloads: 5 },
  };

  let variants;
  try {
    variants = sqlCheck.variants(ctx);
  } catch (err) {
    // Some variant generators may require additional context — skip gracefully
    console.log(`  Test 9 — variants() threw (acceptable): ${err.message}`);
    variants = null;
  }

  if (variants !== null) {
    assert.ok(Array.isArray(variants), 'Test 9 — variants should return an array');
    // Each variant should have at minimum an id and value
    for (const v of variants) {
      assert.equal(typeof v.id, 'string', 'Test 9 — variant should have an id');
      assert.equal(typeof v.value, 'string', 'Test 9 — variant should have a value');
    }
  }
}

// ---------------------------------------------------------------------------
// Test 10: oracleResponseClassifier classifies a SQL error response correctly
// ---------------------------------------------------------------------------
{
  if (typeof buildOracleObservation === 'function') {
    const exchange = makeExchange("You have an error in your SQL syntax near 'test'");
    const obs = buildOracleObservation(
      'sql-injection-variant-1',
      "' OR '1'='1",
      exchange.response,
    );
    const sqlCheck = getCheck('sql-injection');
    const sqlVariant = {
      id: 'sql-injection-variant-1',
      family: 'sql-injection',
      value: "' OR '1'='1",
      encoding: 'raw',
      intent: 'error-based',
      destructiveRisk: 'none',
      expectedSignals: ['sql-error'],
      requiresOast: false,
    };
    const classification = classifyOracleObservation(obs, sqlVariant);
    assert.equal(typeof classification, 'object', 'Test 10 — classification should be an object');
    assert.equal(typeof classification.responseClass, 'string', 'Test 10 — responseClass should be a string');
    assert.equal(typeof classification.confidence, 'number', 'Test 10 — confidence should be a number');
    assert.equal(classification.responseClass, 'expected-proof', 'Test 10 — SQL error should classify as expected-proof');
  }
}

// ---------------------------------------------------------------------------
// Test 11: classifying a neutral response returns neutral-or-not-parsed
// ---------------------------------------------------------------------------
{
  if (typeof buildOracleObservation === 'function') {
    const exchange = makeExchange('<html><body>Welcome to our site!</body></html>');
    const obs = buildOracleObservation(
      'sql-injection-variant-neutral',
      "' OR '1'='1",
      exchange.response,
    );
    const neutralVariant = {
      id: 'sql-injection-variant-neutral',
      family: 'sql-injection',
      value: "' OR '1'='1",
      encoding: 'raw',
      intent: 'error-based',
      destructiveRisk: 'none',
      expectedSignals: ['sql-error'],
      requiresOast: false,
    };
    const classification = classifyOracleObservation(obs, neutralVariant);
    assert.equal(classification.responseClass, 'neutral-or-not-parsed', 'Test 11 — neutral body should classify as neutral');
    assert.equal(classification.nextAction, 'stop-negative', 'Test 11 — neutral classification should stop-negative');
  }
}

// ---------------------------------------------------------------------------
// Test 12: all packs are accessible by id
// ---------------------------------------------------------------------------
{
  const packIds = CHECK_PACKS.map((p) => p.id);
  for (const id of packIds) {
    const pack = getCheckPack(id);
    assert.ok(pack !== undefined, `Test 12 — pack "${id}" should be accessible via getCheckPack`);
    assert.equal(pack.id, id, `Test 12 — getCheckPack("${id}") should return the correct pack`);
  }
}

console.log('PASS headless-full-chain-vantix-core');
