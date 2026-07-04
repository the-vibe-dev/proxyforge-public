// Tests for src/scanner/passive/reflectedRedirectParam.ts
// Imports from dist-electron — run after `npm run build:electron` or equivalent.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let check;
try {
  ({ check } = require('../dist-electron/src/scanner/passive/reflectedRedirectParam.js'));
} catch {
  try {
    ({ check } = require('../src/scanner/passive/reflectedRedirectParam.ts'));
  } catch {
    console.error('Could not load reflectedRedirectParam module. Build first: npm run build:electron');
    process.exit(1);
  }
}

function makeExchange({ url = 'https://example.com/', requestRaw = 'GET / HTTP/1.1\r\n\r\n', responseRaw = 'HTTP/1.1 200 OK\r\n\r\n', status = 200 } = {}) {
  return { url, requestRaw, responseRaw, status, host: 'example.com' };
}

// Test 1: No redirect param → no fire
{
  const result = check(makeExchange({ url: 'https://example.com/page?foo=bar' }));
  assert.equal(result.fired, false, 'Should not fire with no redirect param');
}

// Test 2: javascript: scheme in redirect param → fires
{
  const result = check(makeExchange({ url: 'https://example.com/login?next=javascript:alert(1)' }));
  assert.equal(result.fired, true, 'Should fire on javascript: in next param');
  assert.ok(result.evidence.some((e) => e.toLowerCase().includes('javascript:')), 'Evidence should mention javascript:');
  assert.equal(result.title, 'Suspicious redirect parameter');
}

// Test 3: data: scheme in redirect param → fires
{
  const result = check(makeExchange({ url: 'https://example.com/login?redirect=data:text/html,<h1>hi</h1>' }));
  assert.equal(result.fired, true, 'Should fire on data: scheme in redirect param');
}

// Test 4: Protocol-relative // in redirect param → fires
{
  const result = check(makeExchange({ url: 'https://example.com/out?url=//evil.com/xss' }));
  assert.equal(result.fired, true, 'Should fire on // protocol-relative URL');
}

// Test 5: Backslash in redirect → fires
{
  const result = check(makeExchange({ url: 'https://example.com/out?return=\\evil.com' }));
  assert.equal(result.fired, true, 'Should fire on backslash-prefixed redirect value');
}

// Test 6: External absolute URL in redirect param → fires
{
  const result = check(makeExchange({
    url: 'https://example.com/auth?redirect_uri=https://attacker.com/steal',
    requestRaw: 'GET /auth?redirect_uri=https://attacker.com/steal HTTP/1.1\r\n\r\n',
  }));
  assert.equal(result.fired, true, 'Should fire on cross-origin absolute URL in redirect_uri');
  assert.ok(result.evidence.some((e) => e.includes('attacker.com')), 'Evidence should mention attacker host');
}

// Test 7: Same-host absolute URL → no fire (not cross-origin)
{
  const result = check(makeExchange({ url: 'https://example.com/login?next=https://example.com/dashboard' }));
  assert.equal(result.fired, false, 'Should not fire on same-host redirect URL');
}

// Test 8: Location header with dangerous scheme → fires
{
  const result = check(makeExchange({
    url: 'https://example.com/go',
    responseRaw: 'HTTP/1.1 302 Found\r\nLocation: javascript:alert(1)\r\n\r\n',
    status: 302,
  }));
  assert.equal(result.fired, true, 'Should fire on dangerous Location header in response');
}

// Test 9: Normal non-redirect param → no fire
{
  const result = check(makeExchange({ url: 'https://example.com/search?q=hello&page=2' }));
  assert.equal(result.fired, false, 'Should not fire on non-redirect param names');
}

console.log('PASS scanner-passive-redirect-scheme');
