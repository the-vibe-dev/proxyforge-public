// Tests for src/scanner/passive/reflectedXss.ts
// Imports from dist-electron — run after `npm run build:electron` or equivalent.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let check;
try {
  ({ check } = require('../dist-electron/src/scanner/passive/reflectedXss.js'));
} catch (err) {
  // Fallback: try TypeScript source directly if ts-node is available
  try {
    ({ check } = require('../src/scanner/passive/reflectedXss.ts'));
  } catch {
    console.error('Could not load reflectedXss module. Build the project first: npm run build:electron');
    process.exit(1);
  }
}

// Helper to build a minimal exchange object
function makeExchange({ url = 'https://example.com/', requestRaw = '', responseRaw = '', status = 200 } = {}) {
  return { url, requestRaw, responseRaw, status, host: 'example.com' };
}

// Test 1: No parameters → no fire
{
  const result = check(makeExchange({
    url: 'https://example.com/page',
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>hello</body></html>',
  }));
  assert.equal(result.fired, false, 'Should not fire on page with no query params');
}

// Test 2: Benign param not reflected → no fire
{
  const result = check(makeExchange({
    url: 'https://example.com/search?q=hello',
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>results</body></html>',
  }));
  assert.equal(result.fired, false, 'Should not fire when param is not reflected');
}

// Test 3: Param with angle brackets reflected unencoded → fires
{
  const result = check(makeExchange({
    url: 'https://example.com/search?q=<script>alert(1)</script>',
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><script>alert(1)</script></body></html>',
  }));
  assert.equal(result.fired, true, 'Should fire when unencoded script tag in reflected param');
  assert.ok(result.evidence.length > 0, 'Should have evidence');
  assert.equal(result.title, 'Passive reflected XSS detection');
  assert.equal(result.severity, 'high');
}

// Test 4: Param with javascript: scheme reflected → fires
{
  const result = check(makeExchange({
    url: 'https://example.com/link?url=javascript:alert(1)',
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><a href="javascript:alert(1)">click</a></body></html>',
  }));
  assert.equal(result.fired, true, 'Should fire on reflected javascript: in href');
}

// Test 5: Param reflected but HTML-encoded → no fire on XSS pattern (encoded)
{
  const encoded = '&lt;script&gt;alert(1)&lt;/script&gt;';
  const result = check(makeExchange({
    url: 'https://example.com/search?q=%3Cscript%3Ealert(1)%3C/script%3E',
    responseRaw: `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>${encoded}</body></html>`,
  }));
  // Value is not literally in body (encoded), so should not fire
  assert.equal(result.fired, false, 'Should not fire when param is HTML-encoded in response');
}

// Test 6: Non-HTML content type → no fire
{
  const result = check(makeExchange({
    url: 'https://example.com/api?x=<script>',
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"q":"<script>"}',
  }));
  assert.equal(result.fired, false, 'Should not fire on non-HTML content type');
}

// Test 7: onerror event handler reflected → fires
{
  const result = check(makeExchange({
    url: 'https://example.com/img?src=x%22onerror%3Dalert(1)',
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<img src="x"onerror=alert(1)>',
  }));
  assert.equal(result.fired, true, 'Should fire on reflected onerror event handler');
}

console.log('PASS scanner-passive-reflected-xss');
