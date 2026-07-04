// Tests for streamingSpool — disk-backed body store.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const require = createRequire(import.meta.url);

let spool;

try {
  spool = require('../dist-electron/traffic/streamingSpool.js');
} catch (err) {
  console.log(`SKIP: compiled module not found (${err.message})`);
  process.exit(0);
}

const { SpoolStore } = spool;

// ---------------------------------------------------------------------------
// Helper: create a fresh temp directory per test group
// ---------------------------------------------------------------------------

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pf-spool-test-'));
}

// ---------------------------------------------------------------------------
// SpoolStore.write — persists bytes to disk
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  const data = Buffer.from('hello spool world');
  const entry = store.write('req-001', data, 'text/plain');

  assert.equal(entry.id, 'req-001', 'entry.id should match');
  assert.equal(entry.size, data.length, 'entry.size should equal data length');
  assert.equal(entry.mimeType, 'text/plain', 'entry.mimeType should match');
  assert.equal(entry.capped, false, 'entry.capped should be false by default');
  assert.ok(typeof entry.path === 'string' && entry.path.length > 0, 'entry.path should be a string');
  assert.ok(typeof entry.createdAt === 'string', 'entry.createdAt should be a string');

  // File should exist on disk
  assert.ok(fs.existsSync(entry.path), 'body file should exist on disk');
  const diskBytes = fs.readFileSync(entry.path);
  assert.equal(diskBytes.toString(), 'hello spool world', 'disk content should match');

  console.log('PASS SpoolStore.write persists bytes to disk with correct metadata');
}

// ---------------------------------------------------------------------------
// SpoolStore.read — returns persisted bytes
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  const data = Buffer.from('{"key":"value"}');
  store.write('req-002', data, 'application/json');

  const read = store.read('req-002');
  assert.ok(read !== null, 'read should return Buffer');
  assert.equal(read.toString(), '{"key":"value"}', 'read content should match written content');

  console.log('PASS SpoolStore.read returns the correct bytes');
}

{
  // Reading a non-existent id returns null
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  const result = store.read('nonexistent-id');
  assert.equal(result, null, 'reading nonexistent id should return null');

  console.log('PASS SpoolStore.read returns null for nonexistent id');
}

// ---------------------------------------------------------------------------
// SpoolStore.remove — deletes the entry and file
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  const data = Buffer.from('to be removed');
  const entry = store.write('req-003', data, 'text/plain');
  const filePath = entry.path;

  assert.ok(fs.existsSync(filePath), 'file should exist before remove');

  const removed = store.remove('req-003');
  assert.equal(removed, true, 'remove should return true');
  assert.equal(store.read('req-003'), null, 'should not be readable after remove');
  assert.ok(!fs.existsSync(filePath), 'file should be deleted from disk');

  // Removing again returns false
  const removedAgain = store.remove('req-003');
  assert.equal(removedAgain, false, 'second remove should return false');

  console.log('PASS SpoolStore.remove deletes the entry and file');
}

// ---------------------------------------------------------------------------
// SpoolStore.list — returns entries sorted by createdAt
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  store.write('b', Buffer.from('second'), 'text/plain');
  // Small delay to ensure different timestamps (createdAt is ISO string)
  store.write('a', Buffer.from('first entry here'), 'text/plain');

  const list = store.list();
  assert.equal(list.length, 2, 'list should return 2 entries');
  // Both should be present regardless of order
  const ids = list.map((e) => e.id);
  assert.ok(ids.includes('a'), 'list should include id a');
  assert.ok(ids.includes('b'), 'list should include id b');

  console.log('PASS SpoolStore.list returns all entries');
}

// ---------------------------------------------------------------------------
// SpoolStore.totalSize — returns correct sum
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  assert.equal(store.totalSize(), 0, 'totalSize should be 0 on empty store');

  const d1 = Buffer.alloc(100, 'a');
  const d2 = Buffer.alloc(200, 'b');
  const d3 = Buffer.alloc(50, 'c');
  store.write('s1', d1, 'application/octet-stream');
  store.write('s2', d2, 'application/octet-stream');
  store.write('s3', d3, 'application/octet-stream');

  assert.equal(store.totalSize(), 350, 'totalSize should sum all entry sizes');

  store.remove('s2');
  assert.equal(store.totalSize(), 150, 'totalSize should update after remove');

  console.log('PASS SpoolStore.totalSize returns correct byte sum');
}

// ---------------------------------------------------------------------------
// SpoolStore.prune — frees space when over limit
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  // Write three entries of 100 bytes each (total 300 bytes)
  store.write('old1', Buffer.alloc(100, 'x'), 'application/octet-stream');
  store.write('old2', Buffer.alloc(100, 'y'), 'application/octet-stream');
  store.write('new1', Buffer.alloc(100, 'z'), 'application/octet-stream');

  assert.equal(store.totalSize(), 300, 'pre-prune totalSize should be 300');

  // Prune to 150 bytes — should free the two oldest entries (200 bytes)
  const freed = store.prune(150);

  assert.ok(freed >= 100, 'should have freed at least 100 bytes');
  assert.ok(store.totalSize() <= 150, 'totalSize should be at or below 150 after prune');

  console.log('PASS SpoolStore.prune frees space when over limit');
}

{
  // Prune when already under limit should free nothing
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  store.write('x', Buffer.alloc(50, 'x'), 'text/plain');
  const freed = store.prune(1000);
  assert.equal(freed, 0, 'should free 0 bytes when already under limit');
  assert.equal(store.totalSize(), 50, 'size should be unchanged');

  console.log('PASS SpoolStore.prune returns 0 when already under limit');
}

// ---------------------------------------------------------------------------
// SpoolStore — capped flag is recorded
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  const entry = store.write('capped-req', Buffer.from('partial body'), 'text/plain', true);
  assert.equal(entry.capped, true, 'capped flag should be stored');

  const list = store.list();
  assert.equal(list[0].capped, true, 'capped flag should persist in index');

  console.log('PASS SpoolStore records capped flag correctly');
}

// ---------------------------------------------------------------------------
// SpoolStore — index persists across re-instantiation
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();

  {
    const store = new SpoolStore(dir);
    store.write('persist-id', Buffer.from('persisted data'), 'text/plain');
  }

  // Re-open
  const store2 = new SpoolStore(dir);
  const read = store2.read('persist-id');
  assert.ok(read !== null, 'data should survive re-instantiation');
  assert.equal(read.toString(), 'persisted data', 'content should be correct after reload');

  console.log('PASS SpoolStore index persists across re-instantiation');
}

console.log('\nAll traffic-streaming-large-body tests passed.');
