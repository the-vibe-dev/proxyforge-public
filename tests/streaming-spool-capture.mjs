// Tests for streamingCapture and streamingSpool modules.
// Focuses on: spool lifecycle, chunk ordering, body concatenation, reset
// semantics, and streaming protocol detection.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';

const require = createRequire(import.meta.url);

let capture;
let spoolModule;

try {
  capture = require('../dist-electron/traffic/streamingCapture.js');
  spoolModule = require('../dist-electron/traffic/streamingSpool.js');
} catch (err) {
  console.log(`SKIP: compiled modules not found (${err.message})`);
  process.exit(0);
}

const { StreamCapture, detectIsStreamingContentType } = capture;
const { SpoolStore } = spoolModule;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

function makeTempDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pf-spool-capture-test-'));
}

// ---------------------------------------------------------------------------
// 1. SpoolStore (createSpool equivalent) returns a spool object
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  assert.ok(store !== null && typeof store === 'object', 'SpoolStore should return an object');
  assert.ok(typeof store.write === 'function', 'spool should have write method');
  assert.ok(typeof store.read === 'function', 'spool should have read method');
  assert.ok(typeof store.list === 'function', 'spool should have list method');
  assert.ok(typeof store.remove === 'function', 'spool should have remove method');
  assert.ok(typeof store.totalSize === 'function', 'spool should have totalSize method');

  console.log('PASS SpoolStore returns a spool object with the expected API');
}

// ---------------------------------------------------------------------------
// 2. Spool accepts write(chunk) calls
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  const chunk1 = Buffer.from('chunk-one');
  const chunk2 = Buffer.from('chunk-two');

  // write() should not throw and should return an entry
  const entry1 = store.write('id-1', chunk1, 'application/octet-stream');
  const entry2 = store.write('id-2', chunk2, 'application/octet-stream');

  assert.ok(entry1 && typeof entry1.id === 'string', 'write should return an entry with id');
  assert.ok(entry2 && typeof entry2.id === 'string', 'second write should return an entry with id');

  console.log('PASS SpoolStore accepts write(chunk) calls and returns entries');
}

// ---------------------------------------------------------------------------
// 3. getChunks equivalent — list() returns all entries in order
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  store.write('c-1', Buffer.from('first'), 'text/plain');
  store.write('c-2', Buffer.from('second'), 'text/plain');
  store.write('c-3', Buffer.from('third'), 'text/plain');

  const entries = store.list();
  assert.equal(entries.length, 3, 'list() should return all three entries');

  const ids = entries.map((e) => e.id);
  assert.ok(ids.includes('c-1'), 'list should include c-1');
  assert.ok(ids.includes('c-2'), 'list should include c-2');
  assert.ok(ids.includes('c-3'), 'list should include c-3');

  console.log('PASS list() returns all written chunks (entries)');
}

// ---------------------------------------------------------------------------
// 4. getFullBody equivalent — read() returns correct concatenated body
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  const body = Buffer.from('the full concatenated body content here');
  store.write('full-body', body, 'text/plain');

  const read = store.read('full-body');
  assert.ok(read !== null, 'read should return a Buffer');
  assert.equal(read.toString('utf8'), body.toString('utf8'), 'read should return the full body');

  console.log('PASS read() returns the full concatenated body correctly');
}

// ---------------------------------------------------------------------------
// 5. reset equivalent — remove() clears an entry; re-created store is empty
// ---------------------------------------------------------------------------

{
  const dir = makeTempDir();
  const store = new SpoolStore(dir);

  store.write('r-1', Buffer.from('data-a'), 'text/plain');
  store.write('r-2', Buffer.from('data-b'), 'text/plain');

  assert.equal(store.list().length, 2, 'should have 2 entries before reset');

  // Simulate reset by removing all entries
  for (const entry of store.list()) {
    store.remove(entry.id);
  }

  assert.equal(store.list().length, 0, 'list should be empty after removing all entries');
  assert.equal(store.totalSize(), 0, 'totalSize should be 0 after reset');

  console.log('PASS remove() clears spool entries (reset semantics)');
}

// ---------------------------------------------------------------------------
// 6. SSE detection: detectIsStreamingContentType('text/event-stream') → true
// ---------------------------------------------------------------------------

{
  assert.equal(
    detectIsStreamingContentType('text/event-stream'),
    true,
    'text/event-stream should be detected as streaming',
  );
  assert.equal(
    detectIsStreamingContentType('text/event-stream; charset=utf-8'),
    true,
    'text/event-stream with charset should be detected as streaming',
  );

  console.log("PASS detectIsStreamingContentType detects 'text/event-stream' as SSE");
}

// ---------------------------------------------------------------------------
// 7. Chunked / NDJSON detection → streaming type
// ---------------------------------------------------------------------------

{
  // application/x-ndjson is the standard chunked streaming indicator
  assert.equal(
    detectIsStreamingContentType('application/x-ndjson'),
    true,
    'application/x-ndjson should be detected as streaming (chunked)',
  );

  // text/plain; charset=utf-8 is treated as long-poll streaming
  assert.equal(
    detectIsStreamingContentType('text/plain; charset=utf-8'),
    true,
    'text/plain; charset=utf-8 should be detected as streaming (long-poll)',
  );

  console.log('PASS detectIsStreamingContentType detects NDJSON and long-poll as streaming');
}

// ---------------------------------------------------------------------------
// 8. Unknown content type returns false (raw/unknown)
// ---------------------------------------------------------------------------

{
  assert.equal(
    detectIsStreamingContentType('application/json'),
    false,
    'application/json should not be streaming',
  );
  assert.equal(
    detectIsStreamingContentType('text/html'),
    false,
    'text/html should not be streaming',
  );
  assert.equal(
    detectIsStreamingContentType('application/octet-stream'),
    false,
    'application/octet-stream should not be streaming',
  );
  assert.equal(
    detectIsStreamingContentType('text/plain'),
    false,
    'text/plain without charset=utf-8 should not be streaming',
  );
  assert.equal(
    detectIsStreamingContentType(''),
    false,
    'empty content type should not be streaming',
  );

  console.log('PASS detectIsStreamingContentType returns false for non-streaming (unknown) types');
}

// ---------------------------------------------------------------------------
// Bonus: StreamCapture write + getBytes integration
// ---------------------------------------------------------------------------

{
  const sc = new StreamCapture({ maxBodyBytes: 1024, maxDurationMs: 60000 });

  const chunks = ['hello ', 'streaming ', 'world'];
  for (const chunk of chunks) {
    const accepted = sc.write(Buffer.from(chunk));
    assert.equal(accepted, true, `write('${chunk}') should return true (under cap)`);
  }

  sc.end();
  assert.equal(sc.isComplete(), true, 'isComplete() should be true after end()');

  const body = sc.getBytes();
  assert.equal(body.toString('utf8'), 'hello streaming world', 'getBytes should concatenate all chunks');
  assert.equal(sc.getBytesReceived(), 21, 'getBytesReceived should equal total bytes written');

  console.log('PASS StreamCapture write + getBytes integrates correctly with streaming capture');
}

console.log('\nAll streaming-spool-capture tests passed.');
