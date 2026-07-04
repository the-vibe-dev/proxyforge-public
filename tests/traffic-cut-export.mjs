// Phase 2 — Tests for cutExport.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { cutExchange, cutExchanges, formatCutResults } = require('../dist-electron/traffic/cutExport.js');

const exchange = {
  id: 'ex-001',
  url: 'https://target.example.com/api/users?page=2&sort=asc',
  method: 'POST',
  status: 403,
  host: 'target.example.com',
  path: '/api/users',
  requestRaw: [
    'POST /api/users HTTP/1.1',
    'Host: target.example.com',
    'Authorization: Bearer tok123',
    'Cookie: session=abc; pref=dark',
    'Content-Type: application/json',
    '',
    '{"username":"admin","role":"user"}',
  ].join('\n'),
  responseRaw: [
    'HTTP/1.1 403 Forbidden',
    'Content-Type: application/json',
    'X-Request-Id: req-xyz',
    '',
    '{"error":"forbidden","code":403}',
  ].join('\n'),
};

// Scalar fields
assert.equal(cutExchange(exchange, { field: 'url' }).value, exchange.url, 'url');
assert.equal(cutExchange(exchange, { field: 'method' }).value, 'POST', 'method');
assert.equal(cutExchange(exchange, { field: 'status' }).value, '403', 'status');
assert.equal(cutExchange(exchange, { field: 'host' }).value, 'target.example.com', 'host');
assert.equal(cutExchange(exchange, { field: 'path' }).value, '/api/users', 'path');
console.log('  Scalar fields: PASS');

// Request header extraction
assert.equal(cutExchange(exchange, { field: 'request-header', headerName: 'Authorization' }).value, 'Bearer tok123', 'request Authorization');
assert.equal(cutExchange(exchange, { field: 'request-header', headerName: 'Content-Type' }).value, 'application/json', 'request Content-Type');
assert.equal(cutExchange(exchange, { field: 'request-header', headerName: 'X-Missing' }).value, null, 'missing request header → null');
console.log('  Request headers: PASS');

// Response header extraction
assert.equal(cutExchange(exchange, { field: 'response-header', headerName: 'X-Request-Id' }).value, 'req-xyz', 'response X-Request-Id');
assert.equal(cutExchange(exchange, { field: 'response-header', headerName: 'Content-Type' }).value, 'application/json', 'response Content-Type');
console.log('  Response headers: PASS');

// Body extraction
const reqBody = cutExchange(exchange, { field: 'request-body' }).value;
assert.ok(typeof reqBody === 'string' && reqBody.includes('admin'), 'request body contains admin');
const resBody = cutExchange(exchange, { field: 'response-body' }).value;
assert.ok(typeof resBody === 'string' && resBody.includes('forbidden'), 'response body contains forbidden');
console.log('  Body extraction: PASS');

// Cookie extraction
assert.equal(cutExchange(exchange, { field: 'cookie', cookieName: 'session' }).value, 'abc', 'session cookie');
assert.equal(cutExchange(exchange, { field: 'cookie', cookieName: 'pref' }).value, 'dark', 'pref cookie');
assert.equal(cutExchange(exchange, { field: 'cookie', cookieName: 'missing' }).value, null, 'missing cookie → null');
console.log('  Cookie extraction: PASS');

// Query param extraction
assert.equal(cutExchange(exchange, { field: 'query-param', queryParam: 'page' }).value, '2', 'page param');
assert.equal(cutExchange(exchange, { field: 'query-param', queryParam: 'sort' }).value, 'asc', 'sort param');
assert.equal(cutExchange(exchange, { field: 'query-param', queryParam: 'missing' }).value, null, 'missing param → null');
console.log('  Query params: PASS');

// JSON path extraction
assert.equal(cutExchange(exchange, { field: 'json-path', jsonPath: '$.username' }).value, 'admin', 'json-path $.username');
assert.equal(cutExchange(exchange, { field: 'json-path', jsonPath: 'role' }).value, 'user', 'json-path role (no prefix)');
assert.equal(cutExchange(exchange, { field: 'json-path', jsonPath: '$.missing' }).value, null, 'json-path missing → null');
console.log('  JSON path: PASS');

// Multi-exchange cut
const ex2 = { id: 'ex-002', url: 'https://other.com/login', method: 'GET', status: 200, host: 'other.com', path: '/login' };
const results = cutExchanges([exchange, ex2], [{ field: 'url' }, { field: 'method' }]);
assert.equal(results.length, 2, 'two rows');
assert.equal(results[0].length, 2, 'two columns per row');
assert.equal(results[0][0].value, exchange.url, 'row 0 url');
assert.equal(results[1][0].value, 'https://other.com/login', 'row 1 url');
console.log('  Multi-exchange cut: PASS');

// formatCutResults
const formatted = formatCutResults(results);
assert.ok(formatted.includes('\t'), 'tab delimiter present');
const rows = formatted.split('\n');
assert.equal(rows.length, 2, 'two rows in output');
console.log('  formatCutResults: PASS');

// Custom delimiter
const csv = formatCutResults(results, ',');
assert.ok(csv.includes(','), 'comma delimiter present');
console.log('  Custom delimiter: PASS');

console.log('PASS traffic-cut-export');
