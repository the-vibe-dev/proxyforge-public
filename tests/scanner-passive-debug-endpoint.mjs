// Tests for src/scanner/passive/debugEndpoint.ts
// Imports from dist-electron — run after `npm run build:electron` or equivalent.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let check;
try {
  ({ check } = require('../dist-electron/src/scanner/passive/debugEndpoint.js'));
} catch {
  try {
    ({ check } = require('../src/scanner/passive/debugEndpoint.ts'));
  } catch {
    console.error('Could not load debugEndpoint module. Build first: npm run build:electron');
    process.exit(1);
  }
}

function makeExchange({ url = 'https://example.com/', requestRaw = '', responseRaw = 'HTTP/1.1 200 OK\r\n\r\n', status = 200 } = {}) {
  return { url, requestRaw, responseRaw, status, host: 'example.com' };
}

// Test 1: Normal page → no fire
{
  const result = check(makeExchange({ url: 'https://example.com/home' }));
  assert.equal(result.fired, false, 'Should not fire on normal page URL');
}

// Test 2: /debug path with 200 → fires
{
  const result = check(makeExchange({ url: 'https://example.com/debug', status: 200 }));
  assert.equal(result.fired, true, 'Should fire on /debug path returning 200');
  assert.equal(result.title, 'Debug endpoint / debug mode detected');
}

// Test 3: /actuator path → fires
{
  const result = check(makeExchange({ url: 'https://example.com/actuator', status: 200 }));
  assert.equal(result.fired, true, 'Should fire on Spring /actuator endpoint');
}

// Test 4: /debug path with 404 → no fire (not accessible)
{
  const result = check(makeExchange({ url: 'https://example.com/debug', status: 404 }));
  assert.equal(result.fired, false, 'Should not fire on /debug returning 404');
}

// Test 5: ?debug=1 query parameter → fires
{
  const result = check(makeExchange({ url: 'https://example.com/app?debug=1', status: 200 }));
  assert.equal(result.fired, true, 'Should fire on debug query parameter');
}

// Test 6: ?XDEBUG_SESSION_START=1 → fires
{
  const result = check(makeExchange({ url: 'https://example.com/app?XDEBUG_SESSION=1', status: 200 }));
  assert.equal(result.fired, true, 'Should fire on XDEBUG_SESSION parameter');
}

// Test 7: phpinfo() in response body → fires
{
  const result = check(makeExchange({
    url: 'https://example.com/info.php',
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>phpinfo()</body></html>',
    status: 200,
  }));
  assert.equal(result.fired, true, 'Should fire on phpinfo() in response body');
}

// Test 8: Werkzeug debugger in response → fires with high severity
{
  const result = check(makeExchange({
    url: 'https://example.com/error',
    responseRaw: 'HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/html\r\n\r\n<div class="debugger">Werkzeug Debugger</div>',
    status: 500,
  }));
  assert.equal(result.fired, true, 'Should fire on Werkzeug Debugger in body');
}

// Test 9: /trace path → fires
{
  const result = check(makeExchange({ url: 'https://example.com/trace', status: 200 }));
  assert.equal(result.fired, true, 'Should fire on /trace endpoint');
}

// Test 10: /metrics → fires
{
  const result = check(makeExchange({ url: 'https://example.com/metrics', status: 200 }));
  assert.equal(result.fired, true, 'Should fire on /metrics endpoint');
}

// Test 11: Normal API endpoint → no fire
{
  const result = check(makeExchange({ url: 'https://example.com/api/v1/users', status: 200 }));
  assert.equal(result.fired, false, 'Should not fire on normal API endpoint');
}

// Test 12: /heapdump → fires
{
  const result = check(makeExchange({ url: 'https://example.com/heapdump', status: 200 }));
  assert.equal(result.fired, true, 'Should fire on /heapdump actuator endpoint');
}

console.log('PASS scanner-passive-debug-endpoint');
