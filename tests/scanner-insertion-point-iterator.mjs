// Tests: probeRenderer.ts — renderProbeForInsertionPoint injects payload into correct location.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let mod;
try {
  mod = require('../dist-electron/src/scanner/probeRenderer.js');
} catch {
  console.log('SKIP: scanner/probeRenderer not compiled');
  process.exit(0);
}

try {
  const {
    renderProbeForInsertionPoint,
    renderProbeForQuery,
    renderProbeForHeader,
    renderProbeForFormField,
    renderProbeForJsonField,
  } = mod;

  const stubVariant = {
    id: 'pv-xss-reflected-000-raw',
    family: 'xss-reflected',
    value: '<script>alert(1)</script>',
    encoding: 'raw',
    intent: 'HTML context script injection',
    destructiveRisk: 'none',
    expectedSignals: ['xss-reflection', 'script-tag'],
  };

  // ── Query param insertion point ────────────────────────────────────────────
  const baseRequest = {
    method: 'GET',
    url: 'https://app.example.com/search?search=hello&page=1',
    headers: { Host: 'app.example.com', Accept: '*/*' },
    body: '',
  };

  const queryProbe = renderProbeForInsertionPoint(baseRequest, 'query', 'search', stubVariant);

  assert.ok(queryProbe, 'renderProbeForInsertionPoint must return a result');
  assert.ok(queryProbe.url, 'rendered probe must have url');
  assert.ok(queryProbe.rawRequest, 'rendered probe must have rawRequest');
  assert.equal(queryProbe.insertionPointKind, 'query', 'insertionPointKind must be "query"');
  assert.equal(queryProbe.insertionPointName, 'search', 'insertionPointName must be "search"');
  assert.equal(queryProbe.variantId, stubVariant.id, 'variantId must match');
  // The payload value (or its encoded form) must appear somewhere in the rendered request
  const queryUrlDecoded = decodeURIComponent(queryProbe.url);
  assert.ok(
    queryUrlDecoded.includes(stubVariant.value) || queryProbe.url.includes(encodeURIComponent(stubVariant.value)),
    `Query probe url must contain the injected payload. Got: ${queryProbe.url}`,
  );

  // ── Body (form) insertion point ────────────────────────────────────────────
  const postRequest = {
    method: 'POST',
    url: 'https://app.example.com/login',
    headers: { Host: 'app.example.com', 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'username=admin&password=secret',
  };

  const bodyVariant = {
    id: 'pv-sqli-000-raw',
    family: 'sql-injection',
    value: "' OR '1'='1",
    encoding: 'raw',
    intent: 'tautology',
    destructiveRisk: 'none',
    expectedSignals: ['sql-error'],
  };

  const bodyProbe = renderProbeForInsertionPoint(postRequest, 'form', 'username', bodyVariant);

  assert.ok(bodyProbe, 'body probe must be returned');
  assert.ok(bodyProbe.rawRequest, 'body probe must have rawRequest');
  // Form encoding may use + for spaces and %27 for quotes — decode via URLSearchParams
  const rawBodyLine = bodyProbe.rawRequest.split('\r\n\r\n').pop() ?? bodyProbe.rawRequest.split('\n\n').pop() ?? '';
  const parsedBody = new URLSearchParams(rawBodyLine);
  const usernameValue = parsedBody.get('username') ?? '';
  assert.ok(
    usernameValue === bodyVariant.value ||
    bodyProbe.rawRequest.includes(encodeURIComponent(bodyVariant.value)) ||
    bodyProbe.rawRequest.includes(bodyVariant.value),
    `Body probe rawRequest must contain the injected payload. Got: ${bodyProbe.rawRequest}`,
  );
  assert.equal(bodyProbe.insertionPointName, 'username', 'insertionPointName must be "username"');

  // ── renderProbeForQuery directly ───────────────────────────────────────────
  const directQueryProbe = renderProbeForQuery(baseRequest, 'search', stubVariant);
  assert.ok(directQueryProbe.url, 'direct query probe must have url');
  assert.equal(directQueryProbe.insertionPointKind, 'query');

  // ── renderProbeForHeader directly ─────────────────────────────────────────
  const headerVariant = {
    id: 'pv-host-000-raw',
    family: 'host-header',
    value: 'evil.example.com',
    encoding: 'header-safe',
    intent: 'Host header injection',
    destructiveRisk: 'none',
    expectedSignals: ['host-reflected'],
  };
  const headerProbe = renderProbeForHeader(baseRequest, 'X-Forwarded-Host', headerVariant);
  assert.equal(headerProbe.insertionPointKind, 'header');
  assert.ok(
    headerProbe.rawRequest.includes('evil.example.com'),
    'Header probe rawRequest must contain injected value',
  );

  // ── renderProbeForJsonField directly ──────────────────────────────────────
  const jsonRequest = {
    method: 'POST',
    url: 'https://app.example.com/api/search',
    headers: { Host: 'app.example.com', 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: 'hello', limit: 10 }),
  };
  const jsonProbe = renderProbeForJsonField(jsonRequest, 'query', bodyVariant);
  assert.equal(jsonProbe.insertionPointKind, 'json');
  assert.ok(jsonProbe.rawRequest.includes(bodyVariant.value), 'JSON probe must contain injected value');

  console.log('PASS scanner-insertion-point-iterator');
} catch (err) {
  console.error('FAIL scanner-insertion-point-iterator:', err.message);
  process.exit(1);
}
