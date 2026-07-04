// Phase 2 — Tests for contentViews.ts + registered view implementations
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// Try the new rootDir=".." path first, fall back to old rootDir="." path
function resolveTrafficBase() {
  const newBase = path.join(__dirname, '..', 'dist-electron', 'electron', 'traffic');
  if (fs.existsSync(path.join(newBase, 'contentViews.js'))) return newBase;
  return path.join(__dirname, '..', 'dist-electron', 'traffic');
}
const trafficBase = resolveTrafficBase();
const viewsBase = path.join(trafficBase, 'views');

const { registerView, detectView, renderBody, getAllViews } = require(path.join(trafficBase, 'contentViews.js'));

// Import all views to trigger their self-registration
require(path.join(viewsBase, 'jsonView.js'));
require(path.join(viewsBase, 'xmlView.js'));
require(path.join(viewsBase, 'htmlView.js'));
require(path.join(viewsBase, 'formView.js'));
require(path.join(viewsBase, 'jwtView.js'));
require(path.join(viewsBase, 'csvView.js'));
require(path.join(viewsBase, 'graphqlView.js'));
require(path.join(viewsBase, 'multipartView.js'));
require(path.join(viewsBase, 'sseView.js'));
require(path.join(viewsBase, 'protobufView.js'));

// getAllViews returns at least the registered views
const views = getAllViews();
assert.ok(views.length >= 5, `At least 5 views registered, got ${views.length}`);
console.log(`  View registry: ${views.length} views — PASS`);

// JSON view detection and render
const jsonBody = '{"user":"alice","admin":true}';
const jsonResult = renderBody(jsonBody, 'application/json');
assert.equal(jsonResult.viewId, 'json', 'JSON view selected for application/json');
assert.ok(jsonResult.rendered.includes('alice'), 'JSON rendered includes alice');
console.log('  JSON view: PASS');

// XML view
const xmlBody = '<?xml version="1.0"?><root><item>hello</item></root>';
const xmlResult = renderBody(xmlBody, 'text/xml');
assert.equal(xmlResult.viewId, 'xml', 'XML view selected for text/xml');
assert.ok(xmlResult.rendered.includes('hello'), 'XML rendered includes hello');
console.log('  XML view: PASS');

// HTML view
const htmlBody = '<html><head><title>Test</title></head><body><p>Hello</p></body></html>';
const htmlResult = renderBody(htmlBody, 'text/html');
assert.equal(htmlResult.viewId, 'html', 'HTML view selected for text/html');
assert.ok(htmlResult.rendered.length > 0, 'HTML rendered is non-empty');
console.log('  HTML view: PASS');

// Form-encoded view
const formBody = 'username=admin&password=secret&remember=1';
const formResult = renderBody(formBody, 'application/x-www-form-urlencoded');
assert.equal(formResult.viewId, 'form', 'Form view selected');
assert.ok(formResult.rendered.includes('admin'), 'Form rendered includes admin');
console.log('  Form view: PASS');

// JWT view
const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' })).toString('base64url');
const payload = Buffer.from(JSON.stringify({ sub: '1234', role: 'admin' })).toString('base64url');
const jwtBody = `${header}.${payload}.signature123`;
const jwtResult = renderBody(jwtBody, 'text/plain');
assert.equal(jwtResult.viewId, 'jwt', 'JWT view detected from content shape');
assert.ok(jwtResult.rendered.includes('sub') || jwtResult.rendered.includes('1234'), 'JWT rendered includes sub claim');
console.log('  JWT view: PASS');

// CSV view
const csvBody = 'name,age,city\nalice,30,nyc\nbob,25,la';
const csvResult = renderBody(csvBody, 'text/csv');
assert.equal(csvResult.viewId, 'csv', 'CSV view selected for text/csv');
assert.ok(csvResult.rendered.includes('alice'), 'CSV rendered includes alice');
console.log('  CSV view: PASS');

// GraphQL view
const gqlBody = JSON.stringify({ query: '{ user { id name } }', variables: {} });
const gqlResult = renderBody(gqlBody, 'application/json', 'https://api.example.com/graphql');
assert.equal(gqlResult.viewId, 'graphql', 'GraphQL view selected by URL path');
assert.ok(gqlResult.rendered.length > 0, 'GraphQL rendered is non-empty');
console.log('  GraphQL view: PASS');

// SSE view
const sseBody = 'data: {"event":"ping"}\n\ndata: {"event":"message","text":"hello"}\n\n';
const sseResult = renderBody(sseBody, 'text/event-stream');
assert.equal(sseResult.viewId, 'sse', 'SSE view selected for text/event-stream');
assert.ok(sseResult.rendered.includes('ping') || sseResult.rendered.includes('event'), 'SSE rendered includes event data');
console.log('  SSE view: PASS');

// Raw fallback — unknown content type with non-matching content
const rawResult = renderBody('just some plain text', 'text/plain');
assert.equal(rawResult.viewId, 'raw', 'Raw fallback for unmatched content');
assert.equal(rawResult.rendered, 'just some plain text', 'Raw passthrough');
console.log('  Raw fallback: PASS');

// 2MB cap: body larger than cap should be truncated in detect/render (no crash)
const bigBody = 'x'.repeat(3 * 1024 * 1024);
const bigResult = renderBody(bigBody, 'text/plain');
assert.equal(bigResult.viewId, 'raw', 'Large body falls through to raw');
assert.ok(bigResult.rendered.length <= 2 * 1024 * 1024, '2MB cap applied');
console.log('  2MB cap: PASS');

// Custom view registration
registerView({
  id: 'test-custom',
  name: 'Test Custom',
  detect: (body) => body.startsWith('CUSTOM:'),
  render: (body) => body.replace('CUSTOM:', '[custom] '),
});
const customResult = renderBody('CUSTOM:payload', 'application/octet-stream');
assert.equal(customResult.viewId, 'test-custom', 'Custom view selected');
assert.equal(customResult.rendered, '[custom] payload', 'Custom view rendered correctly');
console.log('  Custom view registration: PASS');

console.log('PASS traffic-content-views');
