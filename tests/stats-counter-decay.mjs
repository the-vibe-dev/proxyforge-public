// Phase 12 — Tests for stats/countersEngine.ts + countersStore.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let engine, store;
try {
  engine = require('../dist-electron/src/stats/countersEngine.js');
  store = require('../dist-electron/src/stats/countersStore.js');
} catch {
  console.log('SKIP stats-counter-decay (module not compiled)');
  process.exit(0);
}

const { increment, getCount, getAllEntries, getTopEvents, resetAll, resetBucket, resetCounter, snapshot, pruneExpiredWindows, configureDecay } = engine;
const { serializeSnapshot, deserializeSnapshot, mergeSnapshots, filterSnapshotByWindow } = store;

// Reset before tests
resetAll();

// Basic increment
increment('proxy.exchange.captured');
increment('proxy.exchange.captured');
increment('proxy.exchange.5xx', 'host:example.com');
assert.equal(getCount('proxy.exchange.captured'), 2, 'global count = 2');
assert.equal(getCount('proxy.exchange.5xx', 'host:example.com'), 1, 'host bucket count = 1');
assert.equal(getCount('proxy.exchange.5xx'), 0, 'wrong bucket → 0');
console.log('  increment / getCount: PASS');

// getAllEntries
const entries = getAllEntries();
assert.ok(entries.length >= 2, 'at least 2 entries');
const hostEntries = getAllEntries('host:example.com');
assert.equal(hostEntries.length, 1, 'filter by bucket');
console.log('  getAllEntries: PASS');

// getTopEvents
increment('proxy.exchange.captured', 'global', 10); // now 12
const top = getTopEvents('global', 5);
assert.ok(top.length >= 1, 'getTopEvents returns results');
assert.equal(top[0].event, 'proxy.exchange.captured', 'top event is captured');
console.log('  getTopEvents: PASS');

// resetCounter
resetCounter('proxy.exchange.captured');
assert.equal(getCount('proxy.exchange.captured'), 0, 'reset single counter');
console.log('  resetCounter: PASS');

// resetBucket
increment('scanner.probe', 'host:evil.com', 5);
resetBucket('host:evil.com');
assert.equal(getCount('scanner.probe', 'host:evil.com'), 0, 'bucket reset');
console.log('  resetBucket: PASS');

// snapshot + serialize/deserialize
increment('test.event', 'global', 3);
const snap = snapshot();
assert.ok(snap.capturedAt, 'snapshot has capturedAt');
assert.ok(snap.entries.length > 0, 'snapshot has entries');

const json = serializeSnapshot(snap);
const reparsed = deserializeSnapshot(json);
assert.equal(reparsed.entries.length, snap.entries.length, 'serialize round-trip');
console.log('  snapshot serialize/deserialize: PASS');

// mergeSnapshots
const snapA = { capturedAt: new Date().toISOString(), entries: [{ event: 'a', bucket: 'global', count: 5, lastUpdatedAt: new Date().toISOString(), windowStart: new Date().toISOString() }] };
const snapB = { capturedAt: new Date().toISOString(), entries: [{ event: 'a', bucket: 'global', count: 3, lastUpdatedAt: new Date().toISOString(), windowStart: new Date().toISOString() }, { event: 'b', bucket: 'global', count: 2, lastUpdatedAt: new Date().toISOString(), windowStart: new Date().toISOString() }] };
const merged = mergeSnapshots(snapA, snapB);
const aEntry = merged.entries.find((e) => e.event === 'a');
const bEntry = merged.entries.find((e) => e.event === 'b');
assert.equal(aEntry?.count, 8, 'merged count a = 8');
assert.equal(bEntry?.count, 2, 'merged count b = 2');
console.log('  mergeSnapshots: PASS');

// filterSnapshotByWindow
const oldWindowStart = new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString();
const snapWithOld = {
  capturedAt: new Date().toISOString(),
  entries: [
    { event: 'recent', bucket: 'global', count: 1, lastUpdatedAt: new Date().toISOString(), windowStart: new Date().toISOString() },
    { event: 'old', bucket: 'global', count: 1, lastUpdatedAt: new Date().toISOString(), windowStart: oldWindowStart },
  ],
};
const filtered = filterSnapshotByWindow(snapWithOld, 60 * 60 * 1000); // 1 hour window
assert.equal(filtered.entries.length, 1, 'old entry filtered out');
assert.equal(filtered.entries[0].event, 'recent', 'recent entry kept');
console.log('  filterSnapshotByWindow: PASS');

// pruneExpiredWindows
configureDecay({ windowMs: 1 }); // 1ms window → everything is old
const pruned = pruneExpiredWindows();
assert.ok(pruned >= 0, 'pruneExpiredWindows returns number');
console.log('  pruneExpiredWindows: PASS');

console.log('PASS stats-counter-decay');
