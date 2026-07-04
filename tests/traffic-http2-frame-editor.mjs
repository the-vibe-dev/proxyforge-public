// Tests for http2FrameEditor — parse, serialize, round-trip.

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
// Helper: build a raw Http2Frame from display fields
// ---------------------------------------------------------------------------

function makeRawHeadersFrame(streamId, pseudoHeaders, headers) {
  const lines = [
    ...Object.entries(pseudoHeaders).map(([k, v]) => `${k}: ${v}`),
    ...Object.entries(headers).map(([k, v]) => `${k}: ${v}`),
  ];
  return {
    streamId,
    type: 'HEADERS',
    flags: 0x04,
    payload: Buffer.from(lines.join('\n'), 'utf8'),
  };
}

function makeRawDataFrame(streamId, body, flags = 0x01) {
  return {
    streamId,
    type: 'DATA',
    flags,
    payload: Buffer.from(body, 'utf8'),
  };
}

// ---------------------------------------------------------------------------
// serializeFramesToText — produces readable output
// ---------------------------------------------------------------------------

{
  const editableFrames = [
    {
      streamId: 1,
      type: 'HEADERS',
      flags: 0x04,
      payloadHex: '',
      pseudoHeaders: { ':method': 'POST', ':path': '/api/v1/users' },
      headers: { 'content-type': 'application/json' },
    },
    {
      streamId: 1,
      type: 'DATA',
      flags: 0x01,
      payloadHex: '',
      data: '{"user":"alice"}',
    },
  ];

  const text = serializeFramesToText(editableFrames);

  assert.ok(text.includes('HEADERS'), 'should include HEADERS frame type');
  assert.ok(text.includes('stream=1'), 'should include stream id');
  assert.ok(text.includes(':method: POST'), 'should include :method pseudo-header');
  assert.ok(text.includes(':path: /api/v1/users'), 'should include :path pseudo-header');
  assert.ok(text.includes('content-type: application/json'), 'should include content-type');
  assert.ok(text.includes('DATA'), 'should include DATA frame type');
  assert.ok(text.includes('{"user":"alice"}'), 'should include data body');

  console.log('PASS serializeFramesToText produces readable output with pseudo/regular headers');
}

{
  // Flags should be formatted as hex
  const editableFrames = [
    {
      streamId: 3,
      type: 'HEADERS',
      flags: 0x25,
      payloadHex: '',
      pseudoHeaders: { ':method': 'GET', ':path': '/' },
      headers: {},
    },
  ];

  const text = serializeFramesToText(editableFrames);
  assert.ok(text.includes('0x25'), 'should format flags as hex');

  console.log('PASS serializeFramesToText formats flags as hex');
}

// ---------------------------------------------------------------------------
// parseFramesFromText — round-trips HEADERS + DATA pair
// ---------------------------------------------------------------------------

{
  const original = [
    {
      streamId: 1,
      type: 'HEADERS',
      flags: 0x04,
      payloadHex: '',
      pseudoHeaders: { ':method': 'POST', ':path': '/api/v1/users' },
      headers: { 'content-type': 'application/json', 'accept': 'application/json' },
    },
    {
      streamId: 1,
      type: 'DATA',
      flags: 0x01,
      payloadHex: '',
      data: '{"user":"alice"}',
    },
  ];

  const text = serializeFramesToText(original);
  const parsed = parseFramesFromText(text);

  assert.equal(parsed.length, 2, 'should parse two frames');

  const headersFrame = parsed[0];
  assert.equal(headersFrame.type, 'HEADERS', 'first frame should be HEADERS');
  assert.equal(headersFrame.streamId, 1, 'stream id should be 1');
  assert.equal(headersFrame.flags, 0x04, 'flags should be 0x04');
  assert.equal(headersFrame.pseudoHeaders?.[':method'], 'POST', ':method pseudo-header');
  assert.equal(headersFrame.pseudoHeaders?.[':path'], '/api/v1/users', ':path pseudo-header');
  assert.equal(headersFrame.headers?.['content-type'], 'application/json', 'content-type header');
  assert.equal(headersFrame.headers?.['accept'], 'application/json', 'accept header');

  const dataFrame = parsed[1];
  assert.equal(dataFrame.type, 'DATA', 'second frame should be DATA');
  assert.equal(dataFrame.streamId, 1, 'DATA stream id should be 1');
  assert.equal(dataFrame.flags, 0x01, 'DATA flags should be 0x01');
  assert.equal(dataFrame.data, '{"user":"alice"}', 'DATA body should round-trip');

  console.log('PASS parseFramesFromText round-trips a HEADERS + DATA frame pair');
}

{
  // Empty string should produce empty array
  const parsed = parseFramesFromText('');
  assert.deepEqual(parsed, [], 'empty text should produce empty array');

  console.log('PASS parseFramesFromText handles empty input');
}

// ---------------------------------------------------------------------------
// buildFrameFromEdit — converts display form back to raw frame
// ---------------------------------------------------------------------------

{
  const edit = {
    streamId: 5,
    type: 'HEADERS',
    flags: 0x04,
    payloadHex: '',
    pseudoHeaders: { ':method': 'DELETE', ':path': '/resource/42' },
    headers: { 'authorization': 'Bearer token123' },
  };

  const raw = buildFrameFromEdit(edit);

  assert.equal(raw.streamId, 5, 'streamId should match');
  assert.equal(raw.type, 'HEADERS', 'type should match');
  assert.equal(raw.flags, 0x04, 'flags should match');
  assert.ok(Buffer.isBuffer(raw.payload), 'payload should be a Buffer');
  const payloadText = raw.payload.toString('utf8');
  assert.ok(payloadText.includes(':method: DELETE'), 'payload should contain :method');
  assert.ok(payloadText.includes(':path: /resource/42'), 'payload should contain :path');
  assert.ok(payloadText.includes('authorization: Bearer token123'), 'payload should contain authorization');

  console.log('PASS buildFrameFromEdit converts HEADERS display form to raw frame');
}

{
  // DATA frame from edit
  const edit = {
    streamId: 7,
    type: 'DATA',
    flags: 0x01,
    payloadHex: '',
    data: 'hello world',
  };

  const raw = buildFrameFromEdit(edit);
  assert.equal(raw.streamId, 7, 'streamId should match');
  assert.equal(raw.type, 'DATA', 'type should be DATA');
  assert.equal(raw.payload.toString('utf8'), 'hello world', 'payload should be UTF-8 of data');

  console.log('PASS buildFrameFromEdit converts DATA display form to raw frame');
}

{
  // Non-HEADERS non-DATA frame falls back to payloadHex
  const edit = {
    streamId: 0,
    type: 'SETTINGS',
    flags: 0x00,
    payloadHex: 'deadbeef',
  };

  const raw = buildFrameFromEdit(edit);
  assert.equal(raw.type, 'SETTINGS', 'type should be SETTINGS');
  assert.equal(raw.payload.toString('hex'), 'deadbeef', 'payload should decode from hex');

  console.log('PASS buildFrameFromEdit uses payloadHex for non-HEADERS/DATA frames');
}

// ---------------------------------------------------------------------------
// parseFramesForDisplay — integration with raw frames
// ---------------------------------------------------------------------------

{
  const rawFrames = [
    makeRawHeadersFrame(1,
      { ':method': 'GET', ':path': '/index.html' },
      { 'host': 'www.example.com' }),
    makeRawDataFrame(1, 'response body here'),
  ];

  const display = parseFramesForDisplay(rawFrames);
  assert.equal(display.length, 2, 'should return two editable frames');
  assert.equal(display[0].type, 'HEADERS', 'first should be HEADERS');
  assert.equal(display[1].type, 'DATA', 'second should be DATA');
  assert.equal(display[1].data, 'response body here', 'DATA body should be decoded');

  console.log('PASS parseFramesForDisplay converts raw frames to editable form');
}

console.log('\nAll traffic-http2-frame-editor tests passed.');
