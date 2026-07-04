// Tests for playbackMatcher — request matching and response dispatch.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let matcher;

try {
  matcher = require('../dist-electron/traffic/playbackMatcher.js');
} catch (err) {
  console.log(`SKIP: compiled module not found (${err.message})`);
  process.exit(0);
}

const {
  buildMatchFn,
  parseResponseStatus,
  matchesMethod,
  matchesUrlPattern,
  matchesBodyContains,
} = matcher;

// ---------------------------------------------------------------------------
// Helper: build a raw HTTP/1.1 request string
// ---------------------------------------------------------------------------

function makeRequest(method, path, headers = {}, body = '') {
  const headerLines = Object.entries(headers)
    .map(([k, v]) => `${k}: ${v}`)
    .join('\r\n');
  const sep = body ? '\r\n\r\n' : '\r\n\r\n';
  return `${method} ${path} HTTP/1.1\r\nHost: example.com${headerLines ? '\r\n' + headerLines : ''}${sep}${body}`;
}

// ---------------------------------------------------------------------------
// matchesMethod
// ---------------------------------------------------------------------------

{
  assert.equal(matchesMethod(makeRequest('GET', '/'), 'GET'), true, 'GET matches GET');
  assert.equal(matchesMethod(makeRequest('POST', '/'), 'POST'), true, 'POST matches POST');
  assert.equal(matchesMethod(makeRequest('GET', '/'), 'POST'), false, 'GET does not match POST');
  assert.equal(matchesMethod(makeRequest('DELETE', '/'), 'delete'), true, 'case-insensitive match');

  console.log('PASS matchesMethod matches request method correctly');
}

// ---------------------------------------------------------------------------
// matchesUrlPattern
// ---------------------------------------------------------------------------

{
  // Exact match
  assert.equal(matchesUrlPattern(makeRequest('GET', '/api/users'), '/api/users'), true, 'exact match');
  assert.equal(matchesUrlPattern(makeRequest('GET', '/api/users'), '/api/posts'), false, 'no exact match');

  // Wildcard *
  assert.equal(matchesUrlPattern(makeRequest('GET', '/api/users/42'), '/api/users/*'), true, 'trailing wildcard');
  assert.equal(matchesUrlPattern(makeRequest('GET', '/api/users'), '/api/*'), true, 'middle wildcard');
  assert.equal(matchesUrlPattern(makeRequest('GET', '/v1/items/5/details'), '/v1/*/5/*'), true, 'multiple wildcards');
  assert.equal(matchesUrlPattern(makeRequest('GET', '/other/path'), '/api/*'), false, 'wildcard no match');

  // Bare * matches everything
  assert.equal(matchesUrlPattern(makeRequest('GET', '/anything/here'), '*'), true, 'bare * matches everything');

  console.log('PASS matchesUrlPattern supports exact and glob wildcard matching');
}

// ---------------------------------------------------------------------------
// matchesBodyContains
// ---------------------------------------------------------------------------

{
  const req = makeRequest('POST', '/data', { 'content-type': 'application/json' }, '{"user":"alice","role":"admin"}');
  assert.equal(matchesBodyContains(req, 'alice'), true, 'body contains "alice"');
  assert.equal(matchesBodyContains(req, '"role":"admin"'), true, 'body contains role');
  assert.equal(matchesBodyContains(req, 'bob'), false, 'body does not contain "bob"');

  const emptyBody = makeRequest('GET', '/noop');
  assert.equal(matchesBodyContains(emptyBody, 'anything'), false, 'empty body matches nothing');

  console.log('PASS matchesBodyContains checks request body substring');
}

// ---------------------------------------------------------------------------
// parseResponseStatus
// ---------------------------------------------------------------------------

{
  assert.deepEqual(
    parseResponseStatus('HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nbody'),
    { status: 200, statusText: 'OK' },
    '200 OK',
  );

  assert.deepEqual(
    parseResponseStatus('HTTP/1.1 404 Not Found\r\n\r\n'),
    { status: 404, statusText: 'Not Found' },
    '404 Not Found',
  );

  assert.deepEqual(
    parseResponseStatus('HTTP/1.1 500 Internal Server Error\r\n\r\n'),
    { status: 500, statusText: 'Internal Server Error' },
    '500 Internal Server Error',
  );

  assert.deepEqual(
    parseResponseStatus('HTTP/2 201 Created\r\n\r\n'),
    { status: 201, statusText: 'Created' },
    'HTTP/2 format',
  );

  console.log('PASS parseResponseStatus extracts status code and text from raw response');
}

{
  // Malformed / empty input
  const result = parseResponseStatus('');
  assert.equal(typeof result.status, 'number', 'status should be a number');
  assert.equal(typeof result.statusText, 'string', 'statusText should be a string');

  console.log('PASS parseResponseStatus handles malformed/empty input gracefully');
}

// ---------------------------------------------------------------------------
// buildMatchFn — returns canned response for exact URL match
// ---------------------------------------------------------------------------

{
  const rules = [
    {
      method: 'GET',
      urlPattern: '/api/users',
      responseRaw: 'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]',
    },
  ];

  const matchFn = buildMatchFn(rules);
  const req = makeRequest('GET', '/api/users');
  const response = matchFn(req);

  assert.ok(response !== null, 'should return a response for matching request');
  assert.ok(response.includes('200 OK'), 'response should contain 200 OK');

  console.log('PASS buildMatchFn returns canned response for exact URL + method match');
}

{
  // Returns null for non-matching request
  const rules = [
    {
      method: 'POST',
      urlPattern: '/api/users',
      responseRaw: 'HTTP/1.1 201 Created\r\n\r\n',
    },
  ];

  const matchFn = buildMatchFn(rules);

  // Wrong method
  const getReq = makeRequest('GET', '/api/users');
  assert.equal(matchFn(getReq), null, 'should return null for wrong method');

  // Wrong path
  const postWrongPath = makeRequest('POST', '/api/posts');
  assert.equal(matchFn(postWrongPath), null, 'should return null for wrong path');

  console.log('PASS buildMatchFn returns null for non-matching request');
}

{
  // Wildcard URL pattern matching
  const rules = [
    {
      urlPattern: '/api/items/*',
      responseRaw: 'HTTP/1.1 200 OK\r\n\r\nitem found',
    },
  ];

  const matchFn = buildMatchFn(rules);

  assert.ok(matchFn(makeRequest('GET', '/api/items/42')) !== null, 'wildcard should match');
  assert.equal(matchFn(makeRequest('GET', '/api/other/42')), null, 'wildcard should not match different prefix');

  console.log('PASS buildMatchFn supports wildcard URL patterns');
}

{
  // Header match
  const rules = [
    {
      headerMatch: { 'x-api-key': 'secret-key' },
      responseRaw: 'HTTP/1.1 200 OK\r\n\r\nauthenticated',
    },
  ];

  const matchFn = buildMatchFn(rules);

  const authReq = makeRequest('GET', '/', { 'x-api-key': 'secret-key' });
  assert.ok(matchFn(authReq) !== null, 'should match request with correct header');

  const noAuthReq = makeRequest('GET', '/', { 'x-api-key': 'wrong-key' });
  assert.equal(matchFn(noAuthReq), null, 'should not match request with wrong header value');

  const missingHeaderReq = makeRequest('GET', '/');
  assert.equal(matchFn(missingHeaderReq), null, 'should not match request missing the header');

  console.log('PASS buildMatchFn matches header values correctly');
}

{
  // Body contains match
  const rules = [
    {
      method: 'POST',
      bodyContains: '"action":"login"',
      responseRaw: 'HTTP/1.1 200 OK\r\n\r\nlogged in',
    },
  ];

  const matchFn = buildMatchFn(rules);

  const loginReq = makeRequest('POST', '/auth', {}, '{"action":"login","user":"alice"}');
  assert.ok(matchFn(loginReq) !== null, 'should match login request');

  const otherReq = makeRequest('POST', '/auth', {}, '{"action":"logout"}');
  assert.equal(matchFn(otherReq), null, 'should not match logout request');

  console.log('PASS buildMatchFn matches body content correctly');
}

{
  // First-match-wins ordering
  const rules = [
    {
      urlPattern: '/api/users',
      responseRaw: 'HTTP/1.1 200 OK\r\n\r\nfirst',
    },
    {
      urlPattern: '/api/users',
      responseRaw: 'HTTP/1.1 200 OK\r\n\r\nsecond',
    },
  ];

  const matchFn = buildMatchFn(rules);
  const req = makeRequest('GET', '/api/users');
  const response = matchFn(req);

  assert.ok(response !== null, 'should match');
  assert.ok(response.includes('first'), 'should return first matching rule');
  assert.ok(!response.includes('second'), 'should not return second rule');

  console.log('PASS buildMatchFn uses first-match-wins ordering');
}

{
  // Empty rules → always null
  const matchFn = buildMatchFn([]);
  assert.equal(matchFn(makeRequest('GET', '/')), null, 'empty rules should always return null');

  console.log('PASS buildMatchFn with empty rules always returns null');
}

console.log('\nAll traffic-playback-server tests passed.');
