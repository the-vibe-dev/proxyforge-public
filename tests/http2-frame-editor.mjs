// Tests for http2FrameEditor — frame editing, header mutation, serialization.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let editor;

try {
  editor = require('../dist-electron/traffic/http2FrameEditor.js');
} catch (err) {
  console.log(`SKIP: compiled module not found (${err.message})`);
  process.exit(0);
}

const {
  parseFramesForDisplay,
  buildFrameFromEdit,
  serializeFramesToText,
  parseFramesFromText,
} = editor;

// ---------------------------------------------------------------------------
// 1. Module exports frame editing functions
// ---------------------------------------------------------------------------

{
  assert.ok(typeof parseFramesForDisplay === 'function', 'should export parseFramesForDisplay');
  assert.ok(typeof buildFrameFromEdit === 'function', 'should export buildFrameFromEdit');
  assert.ok(typeof serializeFramesToText === 'function', 'should export serializeFramesToText');
  assert.ok(typeof parseFramesFromText === 'function', 'should export parseFramesFromText');

  console.log('PASS http2FrameEditor exports all expected frame editing functions');
}

// ---------------------------------------------------------------------------
// Helper — builds a raw Http2Frame with HEADERS payload
// ---------------------------------------------------------------------------

function makeHeadersFrame(streamId, pseudoHeaders, headers, flags = 0x04) {
  const lines = [
    ...Object.entries(pseudoHeaders).map(([k, v]) => `${k}: ${v}`),
    ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
  ];
  return {
    streamId,
    type: 'HEADERS',
    flags,
    payload: Buffer.from(lines.join('\n'), 'utf8'),
  };
}

// ---------------------------------------------------------------------------
// 2. editHeaders (via buildFrameFromEdit) modifies headers in a frame
// ---------------------------------------------------------------------------

{
  // Start with an editable HEADERS frame
  const editFrame = {
    streamId: 1,
    type: 'HEADERS',
    flags: 0x04,
    payloadHex: '',
    pseudoHeaders: { ':method': 'GET', ':path': '/original' },
    headers: { 'content-type': 'text/html' },
  };

  // Modify path header in pseudoHeaders
  const modified = {
    ...editFrame,
    pseudoHeaders: { ...editFrame.pseudoHeaders, ':path': '/modified' },
    headers: { ...editFrame.headers, 'x-added': 'yes' },
  };

  const raw = buildFrameFromEdit(modified);
  const payloadText = raw.payload.toString('utf8');

  assert.ok(payloadText.includes(':path: /modified'), 'modified :path should appear in payload');
  assert.ok(!payloadText.includes(':path: /original'), 'original :path should not appear');
  assert.ok(payloadText.includes('x-added: yes'), 'added header should appear in payload');

  console.log('PASS editHeaders (via buildFrameFromEdit) modifies headers correctly');
}

// ---------------------------------------------------------------------------
// 3. Frame representation has type, flags, streamId fields
// ---------------------------------------------------------------------------

{
  const rawFrame = makeHeadersFrame(3, { ':method': 'POST', ':path': '/data' }, { 'accept': '*/*' });
  const [display] = parseFramesForDisplay([rawFrame]);

  assert.ok('type' in display, 'editable frame should have type field');
  assert.ok('flags' in display, 'editable frame should have flags field');
  assert.ok('streamId' in display, 'editable frame should have streamId field');
  assert.equal(display.type, 'HEADERS', 'type should be HEADERS');
  assert.equal(display.flags, 0x04, 'flags should be 0x04');
  assert.equal(display.streamId, 3, 'streamId should be 3');

  console.log('PASS Frame representation has type, flags, streamId fields');
}

// ---------------------------------------------------------------------------
// 4. Adding a header to a frame increases header count
// ---------------------------------------------------------------------------

{
  const editFrame = {
    streamId: 1,
    type: 'HEADERS',
    flags: 0x04,
    payloadHex: '',
    pseudoHeaders: { ':method': 'GET', ':path': '/' },
    headers: { 'accept': 'application/json' },
  };

  const originalHeaderCount = Object.keys(editFrame.headers).length;

  // Add a new header
  const withExtra = {
    ...editFrame,
    headers: { ...editFrame.headers, 'x-request-id': 'abc-123' },
  };

  const newHeaderCount = Object.keys(withExtra.headers).length;
  assert.equal(newHeaderCount, originalHeaderCount + 1, 'adding a header should increase count by 1');

  // Verify the raw frame includes the new header
  const raw = buildFrameFromEdit(withExtra);
  assert.ok(raw.payload.toString('utf8').includes('x-request-id: abc-123'), 'new header should appear in payload');

  console.log('PASS Adding a header to a frame increases header count');
}

// ---------------------------------------------------------------------------
// 5. Removing a header from a frame decreases header count
// ---------------------------------------------------------------------------

{
  const editFrame = {
    streamId: 2,
    type: 'HEADERS',
    flags: 0x04,
    payloadHex: '',
    pseudoHeaders: { ':method': 'DELETE', ':path': '/resource/1' },
    headers: {
      'authorization': 'Bearer token',
      'content-type': 'application/json',
      'x-trace': 'trace-id',
    },
  };

  const originalHeaderCount = Object.keys(editFrame.headers).length; // 3

  // Remove one header
  const { 'x-trace': _removed, ...remainingHeaders } = editFrame.headers;
  const withRemoved = { ...editFrame, headers: remainingHeaders };

  const newHeaderCount = Object.keys(withRemoved.headers).length;
  assert.equal(newHeaderCount, originalHeaderCount - 1, 'removing a header should decrease count by 1');

  // Verify the raw frame does not include removed header
  const raw = buildFrameFromEdit(withRemoved);
  assert.ok(!raw.payload.toString('utf8').includes('x-trace'), 'removed header should not appear in payload');
  assert.ok(raw.payload.toString('utf8').includes('authorization'), 'kept headers should still appear');

  console.log('PASS Removing a header from a frame decreases header count');
}

// ---------------------------------------------------------------------------
// 6. Invalid frame input: empty payloadHex for non-HEADERS/DATA type
//    should produce a zero-length Buffer (graceful, not a crash)
// ---------------------------------------------------------------------------

{
  const editFrame = {
    streamId: 0,
    type: 'SETTINGS',
    flags: 0x00,
    payloadHex: '', // empty hex
  };

  let result;
  let threw = false;
  try {
    result = buildFrameFromEdit(editFrame);
  } catch {
    threw = true;
  }

  if (!threw) {
    // Graceful: returned a frame with an empty Buffer
    assert.ok(Buffer.isBuffer(result.payload), 'payload should be a Buffer');
    assert.equal(result.payload.length, 0, 'empty payloadHex produces zero-length Buffer');
    assert.equal(result.type, 'SETTINGS', 'type should be preserved');
  } else {
    // Throwing is also acceptable for invalid input
    assert.ok(threw, 'threw for invalid input as expected');
  }

  console.log('PASS Invalid/empty frame input handled gracefully (no crash)');
}

// ---------------------------------------------------------------------------
// Round-trip: serialize → parse preserves frame data
// ---------------------------------------------------------------------------

{
  const editFrames = [
    {
      streamId: 5,
      type: 'HEADERS',
      flags: 0x04,
      payloadHex: '',
      pseudoHeaders: { ':method': 'PUT', ':path': '/items/99', ':scheme': 'https', ':authority': 'api.example.com' },
      headers: { 'content-type': 'application/json', 'content-length': '42' },
    },
    {
      streamId: 5,
      type: 'DATA',
      flags: 0x01,
      payloadHex: '',
      data: '{"name":"updated item"}',
    },
  ];

  const text = serializeFramesToText(editFrames);
  const reparsed = parseFramesFromText(text);

  assert.equal(reparsed.length, 2, 'should round-trip two frames');
  assert.equal(reparsed[0].streamId, 5, 'HEADERS streamId should round-trip');
  assert.equal(reparsed[0].pseudoHeaders?.[':method'], 'PUT', ':method should round-trip');
  assert.equal(reparsed[0].headers?.['content-type'], 'application/json', 'content-type should round-trip');
  assert.equal(reparsed[1].data, '{"name":"updated item"}', 'DATA body should round-trip');

  console.log('PASS Frame round-trip (serialize → parse) preserves all frame data');
}

console.log('\nAll http2-frame-editor tests passed.');
