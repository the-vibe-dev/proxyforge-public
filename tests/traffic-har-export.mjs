// Phase 2 — Tests for harExport.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { exportToHar, harToJson, exchangeToHarEntry } = require('../dist-electron/traffic/harExport.js');

const exchanges = [
  {
    id: 'ex-001',
    url: 'https://target.example.com/api/users?page=1',
    method: 'GET',
    status: 200,
    host: 'target.example.com',
    path: '/api/users',
    requestRaw: [
      'GET /api/users?page=1 HTTP/1.1',
      'Host: target.example.com',
      'Authorization: Bearer token123',
      'Cookie: session=abc; pref=dark',
      'Accept: application/json',
      '',
      '',
    ].join('\n'),
    responseRaw: [
      'HTTP/1.1 200 OK',
      'Content-Type: application/json',
      'Cache-Control: no-store',
      '',
      '{"users":[],"total":0}',
    ].join('\n'),
    createdAt: '2026-05-26T12:00:00.000Z',
  },
  {
    id: 'ex-002',
    url: 'https://target.example.com/api/login',
    method: 'POST',
    status: 200,
    host: 'target.example.com',
    path: '/api/login',
    requestRaw: [
      'POST /api/login HTTP/1.1',
      'Host: target.example.com',
      'Content-Type: application/json',
      'Content-Length: 42',
      '',
      '{"username":"admin","password":"secret123"}',
    ].join('\n'),
    responseRaw: [
      'HTTP/1.1 200 OK',
      'Content-Type: application/json',
      'Set-Cookie: session=newtoken; Path=/; HttpOnly',
      '',
      '{"token":"newtoken","status":"ok"}',
    ].join('\n'),
    createdAt: '2026-05-26T12:01:00.000Z',
  },
];

// Basic HAR document structure
const har = exportToHar(exchanges, 'Test Project');
assert.equal(har.log.version, '1.2', 'HAR version should be 1.2');
assert.equal(har.log.creator.name, 'ProxyForge', 'Creator name should be ProxyForge');
assert.equal(har.log.entries.length, 2, 'Should have 2 entries');
console.log('  HAR structure: PASS');

// Entry 0: GET request
const entry0 = har.log.entries[0];
assert.equal(entry0.request.method, 'GET', 'Method should be GET');
assert.equal(entry0.request.url, 'https://target.example.com/api/users?page=1', 'URL should match');
assert.ok(entry0.request.queryString.length > 0, 'Query string should be parsed');
assert.equal(entry0.request.queryString[0].name, 'page', 'Query param name should be page');
assert.equal(entry0.request.queryString[0].value, '1', 'Query param value should be 1');
assert.ok(entry0.request.headers.length > 0, 'Request headers should be parsed');
assert.ok(entry0.request.cookies.length > 0, 'Request cookies should be parsed');
assert.equal(entry0.response.status, 200, 'Response status should be 200');
assert.ok(entry0.response.headers.some((h) => h.name.toLowerCase() === 'content-type'), 'Response should have content-type header');
console.log('  GET entry: PASS');

// Entry 1: POST with body
const entry1 = har.log.entries[1];
assert.equal(entry1.request.method, 'POST', 'Method should be POST');
assert.ok(entry1.request.postData, 'POST request should have postData');
assert.ok(entry1.request.postData?.text?.includes('admin'), 'postData should contain request body');
assert.ok(entry1.response.cookies.some((c) => c.name === 'session'), 'Response cookies should include session');
console.log('  POST entry: PASS');

// JSON serialization
const json = harToJson(har);
const reparsed = JSON.parse(json);
assert.equal(reparsed.log.version, '1.2', 'Re-parsed HAR should have correct version');
assert.equal(reparsed.log.entries.length, 2, 'Re-parsed HAR should have 2 entries');
console.log('  JSON round-trip: PASS');

// Empty exchanges
const emptyHar = exportToHar([]);
assert.equal(emptyHar.log.entries.length, 0, 'Empty input should produce empty HAR');
console.log('  Empty HAR: PASS');

console.log('PASS traffic-har-export');
