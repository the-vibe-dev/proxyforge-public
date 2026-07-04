// Phase 1 — Tests for probeRenderer.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  renderProbeForQuery,
  renderProbeForHeader,
  renderProbeForJsonField,
  renderProbeForCookie,
  renderProbeForFormField,
  renderProbeForInsertionPoint,
} = require('../dist-electron/src/scanner/probeRenderer.js');

const baseRequest = {
  method: 'GET',
  url: 'https://target.example.com/search?q=hello&page=1',
  headers: { 'Accept': 'text/html', 'Cookie': 'session=abc123' },
  body: '',
};

const postRequest = {
  method: 'POST',
  url: 'https://target.example.com/api/data',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'test', role: 'user' }),
};

function makeVariant(value, encoding = 'raw') {
  return {
    id: `v-${Math.random().toString(36).slice(2)}`,
    family: 'xss-reflected',
    value,
    encoding,
    intent: 'test',
    destructiveRisk: 'none',
    expectedSignals: ['test'],
  };
}

// Query parameter injection
{
  const probe = renderProbeForQuery(baseRequest, 'q', makeVariant('<script>alert(1)</script>'));
  assert.ok(probe.rawRequest.includes('GET'), 'Raw request should include method');
  assert.ok(probe.url.includes('q='), 'URL should include the modified param');
  assert.equal(probe.insertionPointKind, 'query', 'Kind should be query');
  assert.equal(probe.insertionPointName, 'q', 'Name should be q');
  console.log('  Query probe: PASS');
}

// Header injection
{
  const probe = renderProbeForHeader(
    baseRequest,
    'X-Forwarded-Host',
    makeVariant('evil.example.com'),
  );
  assert.ok(probe.rawRequest.includes('X-Forwarded-Host: evil.example.com'), 'Header should appear in raw request');
  assert.equal(probe.insertionPointKind, 'header', 'Kind should be header');
  console.log('  Header probe: PASS');
}

// JSON field injection
{
  const probe = renderProbeForJsonField(postRequest, 'role', makeVariant("admin' OR '1'='1"));
  const body = JSON.parse(probe.rawRequest.split('\r\n\r\n')[1] ?? '{}');
  assert.equal(body.role, "admin' OR '1'='1", 'JSON field should contain injected value');
  assert.equal(body.name, 'test', 'Other JSON fields should be preserved');
  assert.equal(probe.insertionPointKind, 'json', 'Kind should be json');
  console.log('  JSON probe: PASS');
}

// Cookie injection
{
  const probe = renderProbeForCookie(baseRequest, 'session', makeVariant("'; DROP TABLE sessions;--"));
  assert.ok(probe.rawRequest.toLowerCase().includes('cookie:'), 'Cookie header should be present');
  assert.equal(probe.insertionPointKind, 'cookie', 'Kind should be cookie');
  console.log('  Cookie probe: PASS');
}

// Form field injection
{
  const formRequest = {
    method: 'POST',
    url: 'https://target.example.com/login',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'username=admin&password=secret',
  };
  const probe = renderProbeForFormField(formRequest, 'username', makeVariant("admin' OR '1'='1"));
  const bodyPart = probe.rawRequest.split('\r\n\r\n')[1] ?? '';
  const params = new URLSearchParams(bodyPart);
  assert.equal(params.get('username'), "admin' OR '1'='1", 'Form field should contain injected value');
  assert.equal(params.get('password'), 'secret', 'Other form fields should be preserved');
  console.log('  Form probe: PASS');
}

// renderProbeForInsertionPoint dispatcher
{
  const probe = renderProbeForInsertionPoint(baseRequest, 'query', 'page', makeVariant("1' OR '1'='1"));
  assert.equal(probe.insertionPointKind, 'query');
  console.log('  Dispatcher probe: PASS');
}

// URL encoding
{
  const probe = renderProbeForQuery(baseRequest, 'q', makeVariant('%3Cscript%3E', 'url'));
  assert.ok(probe.rawRequest, 'URL-encoded probe should render');
  console.log('  URL-encoded probe: PASS');
}

console.log('PASS scanner-probe-renderer');
