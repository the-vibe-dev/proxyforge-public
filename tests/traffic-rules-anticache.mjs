// Tests: applyRequestRules with anticache rule
// Verifies Cache-Control and Pragma headers are set, and If-None-Match is removed.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { applyRequestRules } = require('../dist-electron/traffic/trafficRules.js');

try {
  // ── Test 1: Anticache sets required headers and removes conditional headers ──
  const rules = [
    {
      id: 'ac-1',
      name: 'No Cache',
      enabled: true,
      action: 'anticache',
    },
  ];

  const inputHeaders = {
    'Accept': 'text/html',
    'If-None-Match': '"abc123"',
    'If-Modified-Since': 'Mon, 01 Jan 2024 00:00:00 GMT',
    'Cache-Control': 'max-age=3600',
  };

  const exchange = {
    url: 'https://example.com/page',
    method: 'GET',
    status: 0,
  };

  const result = applyRequestRules(rules, inputHeaders, '', exchange);

  assert.equal(result.blocked, false, 'anticache should not block');
  assert.equal(result.headers['Cache-Control'], 'no-cache, no-store', 'Cache-Control should be overwritten');
  assert.equal(result.headers['Pragma'], 'no-cache', 'Pragma header should be set');
  assert.equal(result.headers['If-None-Match'], undefined, 'If-None-Match should be removed');
  assert.equal(result.headers['If-Modified-Since'], undefined, 'If-Modified-Since should be removed');
  assert.equal(result.headers['Accept'], 'text/html', 'Other headers should be preserved');
  assert.equal(result.annotations.length, 1);
  assert.equal(result.annotations[0].action, 'anticache');
  assert.equal(result.annotations[0].ruleId, 'ac-1');

  // ── Test 2: Disabled rule is skipped ──────────────────────────────────────
  const disabledRules = [{ id: 'ac-2', name: 'Disabled', enabled: false, action: 'anticache' }];
  const result2 = applyRequestRules(disabledRules, inputHeaders, '', exchange);
  assert.equal(result2.headers['If-None-Match'], '"abc123"', 'Disabled rule should not modify headers');
  assert.equal(result2.annotations.length, 0, 'Disabled rule should not produce annotations');

  // ── Test 3: Anticache on request scope (no scope = applies everywhere) ────
  const scopedRule = [{ id: 'ac-3', name: 'Scoped', enabled: true, action: 'anticache', scope: 'response' }];
  const result3 = applyRequestRules(scopedRule, inputHeaders, '', exchange);
  assert.equal(result3.headers['If-None-Match'], '"abc123"', 'Response-scoped rule should not apply to requests');

  // ── Test 4: Multiple rules — anticache + anticomp both apply ──────────────
  const multiRules = [
    { id: 'ac-4a', name: 'AntiCache', enabled: true, action: 'anticache' },
    { id: 'ac-4b', name: 'AntiComp', enabled: true, action: 'anticomp' },
  ];
  const headersWithEncoding = { ...inputHeaders, 'Accept-Encoding': 'gzip, br' };
  const result4 = applyRequestRules(multiRules, headersWithEncoding, '', exchange);
  assert.equal(result4.headers['Cache-Control'], 'no-cache, no-store');
  assert.equal(result4.headers['Accept-Encoding'], undefined, 'Accept-Encoding should be removed by anticomp');
  assert.equal(result4.annotations.length, 2);

  console.log('PASS traffic-rules-anticache');
} catch (err) {
  console.error('FAIL traffic-rules-anticache:', err.message);
  process.exit(1);
}
