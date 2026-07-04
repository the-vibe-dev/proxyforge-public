// Tests: token refresher produces a fresh token map before replay.
// Uses a local HTTP server to simulate the application returning CSRF tokens.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';

const require = createRequire(import.meta.url);

let antiCsrfModule;
let tokenRefresherModule;

try {
  antiCsrfModule = require('../dist-electron/antiCsrf/index.js');
} catch {
  try {
    antiCsrfModule = require('../dist-electron/antiCsrfIndex.js');
  } catch {
    console.log('anti-csrf-refresh-before-replay: skipped — antiCsrf module not compiled yet');
    process.exit(0);
  }
}

try {
  tokenRefresherModule = require('../dist-electron/antiCsrf/tokenRefresher.js');
} catch {
  try {
    tokenRefresherModule = require('../dist-electron/antiCsrfTokenRefresher.js');
  } catch {
    console.log('anti-csrf-refresh-before-replay: skipped — tokenRefresher not compiled yet');
    process.exit(0);
  }
}

const { registerAntiCsrfToken, getTokensForContext, deregisterAntiCsrfToken } = antiCsrfModule;
const { refreshAntiCsrfTokens } = tokenRefresherModule;

if (typeof registerAntiCsrfToken !== 'function' || typeof refreshAntiCsrfTokens !== 'function') {
  console.log('anti-csrf-refresh-before-replay: skipped — missing exports');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function startMockServer(handler) {
  return new Promise((resolve) => {
    const server = http.createServer(handler);
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port });
    });
  });
}

function stopServer(server) {
  return new Promise((resolve) => server.close(resolve));
}

// ---------------------------------------------------------------------------
// Test 1: registerAntiCsrfToken creates a token record
// ---------------------------------------------------------------------------
{
  const token = registerAntiCsrfToken({
    name: 'csrf_token',
    contextId: 'ctx-001',
    refreshUrl: 'http://127.0.0.1:9999/form',
  });

  assert.ok(typeof token.id === 'string' && token.id.length > 0);
  assert.strictEqual(token.name, 'csrf_token');
  assert.strictEqual(token.contextId, 'ctx-001');
  deregisterAntiCsrfToken(token.id);
  console.log('PASS: registerAntiCsrfToken creates a token record');
}

// ---------------------------------------------------------------------------
// Test 2: getTokensForContext returns only matching context tokens
// ---------------------------------------------------------------------------
{
  const t1 = registerAntiCsrfToken({ name: 'tok1', contextId: 'ctx-A' });
  const t2 = registerAntiCsrfToken({ name: 'tok2', contextId: 'ctx-B' });
  const t3 = registerAntiCsrfToken({ name: 'tok3', contextId: 'ctx-A' });

  const forA = getTokensForContext('ctx-A');
  assert.strictEqual(forA.length, 2);
  assert.ok(forA.some((t) => t.id === t1.id));
  assert.ok(forA.some((t) => t.id === t3.id));
  assert.ok(!forA.some((t) => t.id === t2.id));

  deregisterAntiCsrfToken(t1.id);
  deregisterAntiCsrfToken(t2.id);
  deregisterAntiCsrfToken(t3.id);
  console.log('PASS: getTokensForContext returns only tokens for the specified context');
}

// ---------------------------------------------------------------------------
// Test 3: refreshAntiCsrfTokens extracts a token from an HTML form
// ---------------------------------------------------------------------------
{
  const FRESH_TOKEN = 'live-csrf-value-' + Math.random().toString(36).slice(2);
  const CONTEXT_ID = 'ctx-html-form';

  const { server, port } = await startMockServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<html><body>
      <form method="POST" action="/submit">
        <input type="hidden" name="csrf_token" value="${FRESH_TOKEN}">
        <button type="submit">Go</button>
      </form>
    </body></html>`);
  });

  const token = registerAntiCsrfToken({
    name: 'csrf_token',
    contextId: CONTEXT_ID,
    refreshUrl: `http://127.0.0.1:${port}/form`,
  });

  const freshTokens = await refreshAntiCsrfTokens(
    getTokensForContext(CONTEXT_ID),
    CONTEXT_ID,
    {
      rawRequest: 'POST /submit HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n',
      targetUrl: `http://127.0.0.1:${port}/submit`,
    },
  );

  assert.strictEqual(freshTokens['csrf_token'], FRESH_TOKEN,
    'refresher must extract the token from the HTML form');

  deregisterAntiCsrfToken(token.id);
  await stopServer(server);
  console.log('PASS: refreshAntiCsrfTokens extracts token from HTML hidden input');
}

// ---------------------------------------------------------------------------
// Test 4: refreshAntiCsrfTokens extracts a token from a JSON response
// ---------------------------------------------------------------------------
{
  const JSON_TOKEN = 'json-csrf-' + Math.random().toString(36).slice(2);
  const CONTEXT_ID = 'ctx-json-api';

  const { server, port } = await startMockServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ _csrf: JSON_TOKEN, user: 'alice' }));
  });

  const token = registerAntiCsrfToken({
    name: '_csrf',
    contextId: CONTEXT_ID,
    refreshUrl: `http://127.0.0.1:${port}/api/meta`,
  });

  const freshTokens = await refreshAntiCsrfTokens(
    getTokensForContext(CONTEXT_ID),
    CONTEXT_ID,
    { rawRequest: '', targetUrl: `http://127.0.0.1:${port}/api/action` },
  );

  assert.strictEqual(freshTokens['_csrf'], JSON_TOKEN,
    'refresher must extract the token from a JSON response');

  deregisterAntiCsrfToken(token.id);
  await stopServer(server);
  console.log('PASS: refreshAntiCsrfTokens extracts token from JSON response');
}

// ---------------------------------------------------------------------------
// Test 5: refreshAntiCsrfTokens extracts a token via Set-Cookie
// ---------------------------------------------------------------------------
{
  const COOKIE_TOKEN = 'cookie-csrf-' + Math.random().toString(36).slice(2);
  const CONTEXT_ID = 'ctx-cookie-csrf';

  const { server, port } = await startMockServer((_req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Set-Cookie': `XSRF-TOKEN=${COOKIE_TOKEN}; Path=/; SameSite=Strict`,
    });
    res.end('<html><body>ok</body></html>');
  });

  const token = registerAntiCsrfToken({
    name: 'X-XSRF-TOKEN',
    contextId: CONTEXT_ID,
    cookieName: 'XSRF-TOKEN',
    refreshUrl: `http://127.0.0.1:${port}/`,
  });

  const freshTokens = await refreshAntiCsrfTokens(
    getTokensForContext(CONTEXT_ID),
    CONTEXT_ID,
    { rawRequest: '', targetUrl: `http://127.0.0.1:${port}/api` },
  );

  assert.strictEqual(freshTokens['X-XSRF-TOKEN'], COOKIE_TOKEN,
    'refresher must extract the token from a Set-Cookie header');

  deregisterAntiCsrfToken(token.id);
  await stopServer(server);
  console.log('PASS: refreshAntiCsrfTokens extracts token via Set-Cookie header');
}

// ---------------------------------------------------------------------------
// Test 6: refreshAntiCsrfTokens returns empty map when server is unreachable
// ---------------------------------------------------------------------------
{
  const CONTEXT_ID = 'ctx-unreachable';

  const token = registerAntiCsrfToken({
    name: 'csrf_token',
    contextId: CONTEXT_ID,
    // Port 1 is effectively always unreachable (ECONNREFUSED on Linux)
    refreshUrl: 'http://127.0.0.1:1/no-server',
  });

  const freshTokens = await refreshAntiCsrfTokens(
    getTokensForContext(CONTEXT_ID),
    CONTEXT_ID,
    { rawRequest: '', targetUrl: 'http://127.0.0.1:1/action' },
  );

  // No crash expected — just an empty result for the unreachable token
  assert.strictEqual(Object.keys(freshTokens).length, 0,
    'unreachable server must yield empty token map, not throw');

  deregisterAntiCsrfToken(token.id);
  console.log('PASS: refreshAntiCsrfTokens handles unreachable server gracefully');
}

console.log('\nAll anti-csrf-refresh-before-replay tests passed.');
