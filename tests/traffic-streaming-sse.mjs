// Tests for streamingCapture — SSE parsing, content-type detection, StreamCapture, capBodySize.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let capture;

try {
  capture = require('../dist-electron/traffic/streamingCapture.js');
} catch (err) {
  console.log(`SKIP: compiled module not found (${err.message})`);
  process.exit(0);
}

const {
  parseSSEChunks,
  detectIsStreamingContentType,
  StreamCapture,
  capBodySize,
} = capture;

// ---------------------------------------------------------------------------
// parseSSEChunks
// ---------------------------------------------------------------------------

{
  const raw = 'data: hello world\n\n';
  const events = parseSSEChunks(raw);
  assert.equal(events.length, 1, 'should parse one event');
  assert.equal(events[0].data, 'hello world', 'data should be "hello world"');
  assert.equal(events[0].event, undefined, 'event field should be absent');
  assert.equal(events[0].id, undefined, 'id field should be absent');
  assert.equal(events[0].retry, undefined, 'retry field should be absent');

  console.log('PASS parseSSEChunks parses simple data event');
}

{
  // Event with all fields
  const raw = 'event: update\ndata: {"key":"value"}\nid: 42\nretry: 3000\n\n';
  const events = parseSSEChunks(raw);
  assert.equal(events.length, 1, 'should parse one event');
  assert.equal(events[0].event, 'update', 'event field');
  assert.equal(events[0].data, '{"key":"value"}', 'data field');
  assert.equal(events[0].id, '42', 'id field');
  assert.equal(events[0].retry, 3000, 'retry field as number');

  console.log('PASS parseSSEChunks parses event with all fields (event, data, id, retry)');
}

{
  // Multiple events separated by blank lines
  const raw =
    'data: first\n\n' +
    'data: second\nid: 2\n\n' +
    'event: close\ndata: done\n\n';

  const events = parseSSEChunks(raw);
  assert.equal(events.length, 3, 'should parse three events');
  assert.equal(events[0].data, 'first');
  assert.equal(events[1].data, 'second');
  assert.equal(events[1].id, '2');
  assert.equal(events[2].event, 'close');
  assert.equal(events[2].data, 'done');

  console.log('PASS parseSSEChunks parses multiple events');
}

{
  // Multi-line data (multiple data: fields in one event)
  const raw = 'data: line1\ndata: line2\ndata: line3\n\n';
  const events = parseSSEChunks(raw);
  assert.equal(events.length, 1, 'should be one event');
  assert.equal(events[0].data, 'line1\nline2\nline3', 'multi-line data joined with newline');

  console.log('PASS parseSSEChunks joins multi-line data fields');
}

{
  // Comments (lines starting with :) should be ignored
  const raw = ': this is a comment\ndata: actual data\n\n';
  const events = parseSSEChunks(raw);
  assert.equal(events.length, 1, 'should parse one event');
  assert.equal(events[0].data, 'actual data', 'comment should be ignored');

  console.log('PASS parseSSEChunks ignores comment lines');
}

{
  // Empty string / no data events
  const events = parseSSEChunks('');
  assert.deepEqual(events, [], 'empty input should return empty array');

  const eventsNoData = parseSSEChunks('event: heartbeat\n\n');
  assert.deepEqual(eventsNoData, [], 'event without data field should be ignored');

  console.log('PASS parseSSEChunks handles empty input and missing data fields');
}

// ---------------------------------------------------------------------------
// detectIsStreamingContentType
// ---------------------------------------------------------------------------

{
  assert.equal(detectIsStreamingContentType('text/event-stream'), true, 'text/event-stream');
  assert.equal(detectIsStreamingContentType('text/event-stream; charset=utf-8'), true, 'text/event-stream with charset');
  assert.equal(detectIsStreamingContentType('application/x-ndjson'), true, 'application/x-ndjson');
  assert.equal(detectIsStreamingContentType('text/plain; charset=utf-8'), true, 'text/plain charset=utf-8 (long-poll)');

  console.log('PASS detectIsStreamingContentType returns true for streaming types');
}

{
  assert.equal(detectIsStreamingContentType('application/json'), false, 'application/json');
  assert.equal(detectIsStreamingContentType('text/html'), false, 'text/html');
  assert.equal(detectIsStreamingContentType('application/octet-stream'), false, 'application/octet-stream');
  assert.equal(detectIsStreamingContentType('text/plain'), false, 'text/plain without charset=utf-8');

  console.log('PASS detectIsStreamingContentType returns false for non-streaming types');
}

// ---------------------------------------------------------------------------
// StreamCapture — caps at maxBodyBytes
// ---------------------------------------------------------------------------

{
  const sc = new StreamCapture({ maxBodyBytes: 10, maxDurationMs: 60000 });
  const result1 = sc.write(Buffer.from('hello'));
  assert.equal(result1, true, 'write within cap should return true');
  assert.equal(sc.getBytesReceived(), 5, 'should have 5 bytes');
  assert.equal(sc.isCapped(), false, 'should not be capped yet');

  const result2 = sc.write(Buffer.from('world'));
  assert.equal(result2, false, 'write hitting cap should return false');
  assert.equal(sc.isCapped(), true, 'should now be capped');
  assert.equal(sc.getBytesReceived(), 10, 'should have exactly 10 bytes');

  // Further writes should be rejected
  const result3 = sc.write(Buffer.from('!'));
  assert.equal(result3, false, 'write after cap should return false');
  assert.equal(sc.getBytesReceived(), 10, 'bytes should not increase after cap');

  const bytes = sc.getBytes();
  assert.equal(bytes.length, 10, 'getBytes should return 10 bytes');
  assert.equal(bytes.toString('utf8'), 'helloworld', 'content should be helloworld');

  console.log('PASS StreamCapture caps at maxBodyBytes and write returns false when capped');
}

{
  // Partial accept when chunk straddles the cap
  const sc = new StreamCapture({ maxBodyBytes: 7, maxDurationMs: 60000 });
  sc.write(Buffer.from('hello'));  // 5 bytes
  sc.write(Buffer.from('world')); // would be 10 — 7 cap means 2 more accepted
  assert.equal(sc.isCapped(), true, 'should be capped');
  assert.equal(sc.getBytesReceived(), 7, 'should have exactly 7 bytes');
  const bytes = sc.getBytes();
  assert.equal(bytes.toString('utf8'), 'hellowo', 'should truncate at cap boundary');

  console.log('PASS StreamCapture partially accepts chunks that straddle the cap');
}

{
  // isComplete before and after end()
  const sc = new StreamCapture({ maxBodyBytes: 1024, maxDurationMs: 60000 });
  assert.equal(sc.isComplete(), false, 'should not be complete initially');
  sc.write(Buffer.from('data'));
  assert.equal(sc.isComplete(), false, 'should not be complete before end()');
  sc.end();
  assert.equal(sc.isComplete(), true, 'should be complete after end()');

  console.log('PASS StreamCapture.isComplete() tracks end() call');
}

{
  // chunkCallback is invoked
  const received = [];
  const sc = new StreamCapture({
    maxBodyBytes: 1024,
    maxDurationMs: 60000,
    chunkCallback: (chunk, total) => received.push({ len: chunk.length, total }),
  });
  sc.write(Buffer.from('abc'));
  sc.write(Buffer.from('de'));
  assert.equal(received.length, 2, 'callback should be called twice');
  assert.equal(received[0].total, 3, 'first callback total should be 3');
  assert.equal(received[1].total, 5, 'second callback total should be 5');

  console.log('PASS StreamCapture.chunkCallback is invoked with correct totals');
}

// ---------------------------------------------------------------------------
// capBodySize
// ---------------------------------------------------------------------------

{
  const body = Buffer.from('hello world');
  const result = capBodySize(body, 100);
  assert.equal(result.capped, false, 'should not be capped when under limit');
  assert.equal(result.originalSize, 11, 'originalSize should be 11');
  assert.equal(result.body.length, 11, 'body should be unchanged');

  console.log('PASS capBodySize returns uncapped result when body is within limit');
}

{
  const body = Buffer.from('hello world');
  const result = capBodySize(body, 5);
  assert.equal(result.capped, true, 'should be capped');
  assert.equal(result.originalSize, 11, 'originalSize should be original 11');
  assert.equal(result.body.length, 5, 'body should be truncated to 5');
  assert.equal(result.body.toString('utf8'), 'hello', 'truncated content should be "hello"');

  console.log('PASS capBodySize truncates and sets capped=true when over limit');
}

{
  // Exact boundary
  const body = Buffer.from('exactly');
  const result = capBodySize(body, 7);
  assert.equal(result.capped, false, 'exact boundary should not be capped');
  assert.equal(result.body.length, 7, 'body should be 7 bytes');

  console.log('PASS capBodySize does not cap when body equals maxBytes exactly');
}

console.log('\nAll traffic-streaming-sse tests passed.');
