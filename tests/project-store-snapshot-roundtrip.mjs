// Phase 8.5 — Tests for electron/projectStore/snapshotEngine.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let snapshotModule;
try {
  snapshotModule = require('../dist-electron/projectStore/snapshotEngine.js');
} catch {
  console.log('SKIP project-store-snapshot-roundtrip (module not compiled)');
  process.exit(0);
}

const {
  serializeSnapshot,
  deserializeSnapshot,
  validateSnapshot,
  EXPECTED_TABLES,
} = snapshotModule;

// EXPECTED_TABLES is a non-empty array-like with the right entries
assert.ok(EXPECTED_TABLES && EXPECTED_TABLES.length >= 23, `EXPECTED_TABLES should have at least 23 entries, got ${EXPECTED_TABLES?.length}`);
assert.ok(EXPECTED_TABLES.includes('scanner_probe_runs'), 'EXPECTED_TABLES includes scanner_probe_runs');
assert.ok(EXPECTED_TABLES.includes('traffic_rule_packs'), 'EXPECTED_TABLES includes traffic_rule_packs');
assert.ok(EXPECTED_TABLES.includes('playbook_recipes'), 'EXPECTED_TABLES includes playbook_recipes');
console.log('  EXPECTED_TABLES contains required table names: PASS');

// serializeSnapshot produces a correctly shaped snapshot
const inputTables = { scanner_probe_runs: [{ id: 'run-1' }] };
const snapshot = serializeSnapshot('proj-1', inputTables);
assert.equal(snapshot.projectId, 'proj-1', 'snapshot.projectId matches');
assert.equal(typeof snapshot.version, 'string', 'snapshot.version is a string');
assert.equal(typeof snapshot.capturedAt, 'string', 'snapshot.capturedAt is a string');
assert.ok(snapshot.capturedAt.length > 0, 'snapshot.capturedAt is non-empty');
assert.deepEqual(snapshot.tables, inputTables, 'snapshot.tables matches input');
assert.deepEqual(snapshot.tables.scanner_probe_runs, [{ id: 'run-1' }], 'scanner_probe_runs row preserved');
console.log('  serializeSnapshot: PASS');

// deserializeSnapshot round-trips correctly
const json = JSON.stringify(snapshot);
const restored = deserializeSnapshot(json);
assert.equal(restored.projectId, 'proj-1', 'restored projectId');
assert.equal(restored.version, snapshot.version, 'restored version');
assert.equal(restored.capturedAt, snapshot.capturedAt, 'restored capturedAt');
assert.deepEqual(restored.tables.scanner_probe_runs, [{ id: 'run-1' }], 'restored scanner_probe_runs rows');
console.log('  deserializeSnapshot round-trip: PASS');

// deserializeSnapshot throws on invalid JSON
assert.throws(() => deserializeSnapshot('not json'), /invalid JSON|JSON/i, 'throws on invalid JSON');
console.log('  deserializeSnapshot rejects invalid JSON: PASS');

// validateSnapshot returns missing tables for an empty snapshot
const emptySnapshot = serializeSnapshot('proj-empty', {});
const emptyResult = validateSnapshot(emptySnapshot);
assert.equal(emptyResult.valid, false, 'empty snapshot is not valid');
assert.ok(emptyResult.missingTables.length >= 23, `empty snapshot should report at least 23 missing tables, got ${emptyResult.missingTables.length}`);
assert.ok(emptyResult.missingTables.includes('scanner_probe_runs'), 'missing tables includes scanner_probe_runs');
assert.ok(emptyResult.missingTables.includes('traffic_rule_packs'), 'missing tables includes traffic_rule_packs');
console.log('  validateSnapshot empty snapshot missing tables: PASS');

// validateSnapshot with all tables present returns valid: true, missingTables: []
const allTables = Object.fromEntries(EXPECTED_TABLES.map((name) => [name, []]));
const fullSnapshot = serializeSnapshot('proj-full', allTables);
const fullResult = validateSnapshot(fullSnapshot);
assert.equal(fullResult.valid, true, 'full snapshot is valid');
assert.deepEqual(fullResult.missingTables, [], 'full snapshot has no missing tables');
console.log('  validateSnapshot all tables present: PASS');

// validateSnapshot with partial tables reports the right missing ones
const partialTables = { scanner_probe_runs: [], traffic_rule_packs: [] };
const partialSnapshot = serializeSnapshot('proj-partial', partialTables);
const partialResult = validateSnapshot(partialSnapshot);
assert.equal(partialResult.valid, false, 'partial snapshot is not valid');
assert.ok(!partialResult.missingTables.includes('scanner_probe_runs'), 'scanner_probe_runs not in missing');
assert.ok(!partialResult.missingTables.includes('traffic_rule_packs'), 'traffic_rule_packs not in missing');
assert.ok(partialResult.missingTables.includes('playbook_recipes'), 'playbook_recipes is missing');
console.log('  validateSnapshot partial tables: PASS');

console.log('PASS project-store-snapshot-roundtrip');
