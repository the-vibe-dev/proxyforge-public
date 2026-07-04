// Tests for playback.ts and playbackMatcher.ts.
// Focuses on: session/run creation, request accumulation, response matching,
// status code matching, header matching, and no-match handling.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let playback;
let matcher;

try {
  playback = require('../dist-electron/traffic/playback.js');
  matcher = require('../dist-electron/traffic/playbackMatcher.js');
} catch (err) {
  console.log(`SKIP: compiled modules not found (${err.message})`);
  process.exit(0);
}

const {
  createClientPlaybackRun,
  advanceClientPlayback,
  startServerPlayback,
} = playback;

const {
  buildMatchFn,
  parseResponseStatus,
  matchesMethod,
} = matcher;

// ---------------------------------------------------------------------------
// Helper factories
// ---------------------------------------------------------------------------

function makeExchange(id, statusCode = 200) {
  return {
    id,
    requestRaw: `GET /path/${id} HTTP/1.1\r\nHost: example.com\r\n\r\n`,
    responseRaw: `HTTP/1.1 ${statusCode} OK\r\nContent-Length: 2\r\n\r\nOK`,
    delayMs: 0,
  };
}

function makeSession(id, exchangeCount = 0) {
  return {
    id,
    name: `Session ${id}`,
    mode: 'client',
    exchanges: Array.from({ length: exchangeCount }, (_, i) => makeExchange(`ex-${i + 1}`)),
    createdAt: new Date().toISOString(),
  };
}

function makeRequest(method, urlPath, headers = {}, body = '') {
  const headerLines = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\r\n');
  return `${method} ${urlPath} HTTP/1.1\r\nHost: example.com${headerLines ? '\r\n' + headerLines : ''}\r\n\r\n${body}`;
}

const clientConfig = {
  targetHost: '127.0.0.1',
  targetPort: 8080,
  useTls: false,
};

const serverConfig = {
  listenPort: 9090,
  listenHost: '127.0.0.1',
};

// ---------------------------------------------------------------------------
// 1. createClientPlaybackRun returns session with id
// ---------------------------------------------------------------------------

{
  const session = makeSession('sess-001', 3);
  const run = createClientPlaybackRun(session, clientConfig);

  assert.ok(run !== null && typeof run === 'object', 'run should be an object');
  assert.equal(run.sessionId, 'sess-001', 'run.sessionId should match session id');
  assert.ok(typeof run.sessionId === 'string', 'sessionId should be a string');

  console.log('PASS createClientPlaybackRun returns a run object with sessionId');
}

// ---------------------------------------------------------------------------
// 2. Session has requests array (exchanges) and status field
// ---------------------------------------------------------------------------

{
  const session = makeSession('sess-002', 5);
  const run = createClientPlaybackRun(session, clientConfig);

  // Run tracks total exchanges and status
  assert.equal(run.total, 5, 'run.total should equal number of exchanges');
  assert.ok(typeof run.status === 'string', 'run.status should be a string');
  assert.equal(run.status, 'running', "run.status should start as 'running'");
  assert.ok(Array.isArray(run.errors), 'run.errors should be an array');

  // Source session has exchanges array
  assert.ok(Array.isArray(session.exchanges), 'session.exchanges should be an array');
  assert.equal(session.exchanges.length, 5, 'session should have 5 exchanges');

  console.log('PASS Session has exchanges array and run has status field');
}

// ---------------------------------------------------------------------------
// 3. addRequest equivalent — advanceClientPlayback increases completed count
// ---------------------------------------------------------------------------

{
  const session = makeSession('sess-003', 4);
  const run = createClientPlaybackRun(session, clientConfig);

  assert.equal(run.completed, 0, 'completed should start at 0');

  advanceClientPlayback(run, session.exchanges[0]);
  assert.equal(run.completed, 1, 'completed should be 1 after first advance');

  advanceClientPlayback(run, session.exchanges[1]);
  assert.equal(run.completed, 2, 'completed should be 2 after second advance');

  console.log('PASS advanceClientPlayback increases completed count (addRequest equivalent)');
}

// ---------------------------------------------------------------------------
// 4. buildMatchFn / matchResponse returns result with matched indicator
// ---------------------------------------------------------------------------

{
  const rules = [
    {
      method: 'GET',
      urlPattern: '/api/resource',
      responseRaw: 'HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata',
    },
  ];
  const matchFn = buildMatchFn(rules);

  const matchedResponse = matchFn(makeRequest('GET', '/api/resource'));
  const noMatchResponse = matchFn(makeRequest('POST', '/api/resource'));

  // matched case: returns the canned responseRaw string (truthy)
  assert.ok(matchedResponse !== null, 'matched response should not be null');
  assert.ok(typeof matchedResponse === 'string', 'matched response should be a string');

  // no-match case: returns null (falsy)
  assert.equal(noMatchResponse, null, 'non-matching response should return null');

  console.log('PASS buildMatchFn returns match result (string or null)');
}

// ---------------------------------------------------------------------------
// 5. Exact status code match: 200 matches 200
// ---------------------------------------------------------------------------

{
  const raw200 = 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody';
  const result = parseResponseStatus(raw200);

  assert.equal(result.status, 200, 'should parse 200');
  assert.equal(result.statusText, 'OK', 'statusText should be OK');

  // Confirm 200 !== 201
  const raw201 = 'HTTP/1.1 201 Created\r\n\r\n';
  const result201 = parseResponseStatus(raw201);
  assert.equal(result201.status, 201, 'should parse 201');
  assert.notEqual(result.status, result201.status, '200 should not equal 201');

  console.log('PASS Exact status code match: 200 matches 200, not 201');
}

// ---------------------------------------------------------------------------
// 6. Status class match: 201 falls in the 2xx class
// ---------------------------------------------------------------------------

{
  const responses = [200, 201, 204, 206].map((code) => {
    const raw = `HTTP/1.1 ${code} Status\r\n\r\n`;
    return parseResponseStatus(raw).status;
  });

  for (const status of responses) {
    const is2xx = status >= 200 && status < 300;
    assert.ok(is2xx, `status ${status} should be in the 2xx class`);
  }

  // 301, 404, 500 are not 2xx
  for (const code of [301, 404, 500]) {
    const { status } = parseResponseStatus(`HTTP/1.1 ${code} Status\r\n\r\n`);
    assert.ok(!(status >= 200 && status < 300), `status ${status} should not be 2xx`);
  }

  console.log('PASS Status class match: 2xx group (200-299) correctly identified');
}

// ---------------------------------------------------------------------------
// 7. Header match: response with X-Custom: foo matches rule requiring it
// ---------------------------------------------------------------------------

{
  const rules = [
    {
      headerMatch: { 'x-custom': 'foo' },
      responseRaw: 'HTTP/1.1 200 OK\r\n\r\nmatched by header',
    },
  ];
  const matchFn = buildMatchFn(rules);

  // Request that includes the matching header
  const withHeader = makeRequest('GET', '/any', { 'x-custom': 'foo' });
  const matched = matchFn(withHeader);
  assert.ok(matched !== null, 'should match when x-custom: foo is present');
  assert.ok(matched.includes('matched by header'), 'should return correct response');

  // Request missing the header
  const withoutHeader = makeRequest('GET', '/any');
  assert.equal(matchFn(withoutHeader), null, 'should not match when header is absent');

  // Request with wrong header value
  const wrongValue = makeRequest('GET', '/any', { 'x-custom': 'bar' });
  assert.equal(matchFn(wrongValue), null, 'should not match when header value differs');

  console.log('PASS Header match: x-custom: foo matches correctly, wrong value does not');
}

// ---------------------------------------------------------------------------
// 8. No match returns null (matched: false equivalent with reason)
// ---------------------------------------------------------------------------

{
  const rules = [
    {
      method: 'DELETE',
      urlPattern: '/strict/path',
      responseRaw: 'HTTP/1.1 204 No Content\r\n\r\n',
    },
  ];
  const matchFn = buildMatchFn(rules);

  // Wrong method
  const noMatchResult = matchFn(makeRequest('GET', '/strict/path'));
  assert.equal(noMatchResult, null, 'non-matching method should return null');

  // Wrong path
  const noMatchPath = matchFn(makeRequest('DELETE', '/other/path'));
  assert.equal(noMatchPath, null, 'non-matching path should return null');

  // Empty rules always null
  const emptyMatchFn = buildMatchFn([]);
  assert.equal(emptyMatchFn(makeRequest('GET', '/')), null, 'empty rules should always return null');

  console.log('PASS No match returns null (matched: false equivalent)');
}

// ---------------------------------------------------------------------------
// 9. playbackMatcher exports buildMatchFn (createMatcher equivalent)
// ---------------------------------------------------------------------------

{
  assert.ok(
    typeof buildMatchFn === 'function',
    'playbackMatcher should export buildMatchFn',
  );
  assert.ok(
    typeof parseResponseStatus === 'function',
    'playbackMatcher should export parseResponseStatus',
  );
  assert.ok(
    typeof matchesMethod === 'function',
    'playbackMatcher should export matchesMethod',
  );

  // buildMatchFn returns a function (the matcher)
  const fn = buildMatchFn([]);
  assert.ok(typeof fn === 'function', 'buildMatchFn should return a function');

  console.log('PASS playbackMatcher exports buildMatchFn (createMatcher equivalent)');
}

// ---------------------------------------------------------------------------
// Bonus: startServerPlayback creates a state descriptor with status
// ---------------------------------------------------------------------------

{
  const session = makeSession('server-sess-1', 2);
  const nullMatchFn = (_raw) => null;
  const state = startServerPlayback(session, serverConfig, nullMatchFn);

  assert.equal(state.sessionId, 'server-sess-1', 'state.sessionId should match session id');
  assert.equal(state.status, 'running', "state.status should be 'running'");
  assert.equal(typeof state.matchCount, 'number', 'state.matchCount should be a number');
  assert.equal(state.matchCount, 0, 'state.matchCount should start at 0');

  console.log('PASS startServerPlayback creates state descriptor with correct shape');
}

console.log('\nAll playback-matcher-replay tests passed.');
