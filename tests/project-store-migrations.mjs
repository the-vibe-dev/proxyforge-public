// Phase 8.5 — Tests for electron/projectStore/migrations.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let migrationsModule;
try {
  migrationsModule = require('../dist-electron/projectStore/migrations.js');
} catch {
  console.log('SKIP project-store-migrations (module not compiled)');
  process.exit(0);
}

const { MIGRATIONS, getMigration, getLatestMigration, getMigrationsUpTo } = migrationsModule;

// MIGRATIONS array length
assert.ok(
  Array.isArray(MIGRATIONS),
  'MIGRATIONS is an array',
);
assert.ok(
  MIGRATIONS.length >= 23,
  `MIGRATIONS should have at least 23 entries, got ${MIGRATIONS.length}`,
);
console.log(`  MIGRATIONS.length = ${MIGRATIONS.length}: PASS`);

// Each migration has required fields
for (const m of MIGRATIONS) {
  assert.ok(typeof m.id === 'string' && m.id.length > 0, `migration id must be a non-empty string (got ${JSON.stringify(m.id)})`);
  assert.ok(typeof m.version === 'number' && Number.isInteger(m.version) && m.version >= 1, `migration version must be a positive integer (id=${m.id})`);
  assert.ok(typeof m.description === 'string' && m.description.length > 0, `migration description must be a non-empty string (id=${m.id})`);
  assert.ok(typeof m.up === 'string' && m.up.length > 0, `migration up must be a non-empty string (id=${m.id})`);
}
console.log('  All migrations have id, version, description, up fields: PASS');

// All up fields contain CREATE TABLE IF NOT EXISTS
for (const m of MIGRATIONS) {
  assert.ok(
    m.up.includes('CREATE TABLE IF NOT EXISTS'),
    `migration "${m.id}" up DDL should contain CREATE TABLE IF NOT EXISTS`,
  );
}
console.log('  All up fields contain CREATE TABLE IF NOT EXISTS: PASS');

// getMigration('scanner_check_packs')
const checkPacksMigration = getMigration('scanner_check_packs');
assert.ok(checkPacksMigration !== null, 'getMigration("scanner_check_packs") should return a migration');
assert.equal(checkPacksMigration.id, 'scanner_check_packs', 'getMigration id matches');
assert.equal(checkPacksMigration.version, 1, 'scanner_check_packs is version 1');
assert.ok(checkPacksMigration.up.includes('scanner_check_packs'), 'up DDL references the table name');
console.log('  getMigration("scanner_check_packs"): PASS');

// getMigration for unknown id returns null
assert.equal(getMigration('nonexistent_table'), null, 'getMigration returns null for unknown id');
console.log('  getMigration unknown id returns null: PASS');

// getLatestMigration returns the last migration
const latest = getLatestMigration();
assert.ok(latest !== null && latest !== undefined, 'getLatestMigration returns a migration');
assert.equal(
  latest.version,
  Math.max(...MIGRATIONS.map((m) => m.version)),
  'getLatestMigration returns the highest-versioned migration',
);
console.log(`  getLatestMigration() = "${latest.id}" (v${latest.version}): PASS`);

// getMigrationsUpTo(5) returns exactly 5 migrations
const upTo5 = getMigrationsUpTo(5);
assert.ok(Array.isArray(upTo5), 'getMigrationsUpTo returns an array');
assert.equal(upTo5.length, 5, `getMigrationsUpTo(5) should return 5 migrations, got ${upTo5.length}`);
for (const m of upTo5) {
  assert.ok(m.version <= 5, `all returned migrations should have version <= 5 (got ${m.version})`);
}
// Verify ascending sort
for (let i = 1; i < upTo5.length; i++) {
  assert.ok(upTo5[i].version > upTo5[i - 1].version, 'getMigrationsUpTo returns migrations in ascending version order');
}
console.log('  getMigrationsUpTo(5) returns 5 sorted migrations: PASS');

// Versions are unique
const versions = MIGRATIONS.map((m) => m.version);
const uniqueVersions = new Set(versions);
assert.equal(uniqueVersions.size, versions.length, 'All migration versions are unique');
console.log('  Migration versions are unique: PASS');

// ids are unique
const ids = MIGRATIONS.map((m) => m.id);
const uniqueIds = new Set(ids);
assert.equal(uniqueIds.size, ids.length, 'All migration ids are unique');
console.log('  Migration ids are unique: PASS');

console.log('PASS project-store-migrations');
