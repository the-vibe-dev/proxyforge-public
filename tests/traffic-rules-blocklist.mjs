// Tests: applyRequestRules with block rule — verifies blocked flag is set
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { applyRequestRules, applyResponseRules } = require('../dist-electron/traffic/trafficRules.js');

try {
  const exchange = {
    url: 'https://ads.tracker.io/beacon',
    method: 'GET',
    status: 0,
    host: 'ads.tracker.io',
  };

  // ── Test 1: Block rule sets blocked=true and returns early ─────────────────
  const rules = [
    { id: 'bl-1', name: 'Block Trackers', enabled: true, action: 'block' },
  ];

  const result = applyRequestRules(rules, { 'Accept': '*/*' }, '', exchange);
  assert.equal(result.blocked, true, 'blocked should be true');
  assert.equal(result.annotations.length, 1);
  assert.equal(result.annotations[0].action, 'block');
  assert.equal(result.annotations[0].ruleId, 'bl-1');

  // ── Test 2: Rules after block are not evaluated ────────────────────────────
  const rulesWithTrailing = [
    { id: 'bl-2a', name: 'Block First', enabled: true, action: 'block' },
    { id: 'bl-2b', name: 'Anticache After Block', enabled: true, action: 'anticache' },
  ];

  const result2 = applyRequestRules(rulesWithTrailing, { 'If-None-Match': '"etag"' }, '', exchange);
  assert.equal(result2.blocked, true);
  // If-None-Match should NOT be removed — anticache rule was never reached
  assert.equal(result2.headers['If-None-Match'], '"etag"', 'Rules after block should not execute');
  assert.equal(result2.annotations.length, 1, 'Only the block annotation should be present');

  // ── Test 3: Disabled block rule does not block ────────────────────────────
  const disabledBlock = [
    { id: 'bl-3', name: 'Disabled Block', enabled: false, action: 'block' },
  ];
  const result3 = applyRequestRules(disabledBlock, {}, '', exchange);
  assert.equal(result3.blocked, false, 'Disabled block rule should not block');

  // ── Test 4: Filter-scoped block — matching exchange ───────────────────────
  // The filter '~u tracker' will match the URL containing "tracker"
  const filteredBlock = [
    { id: 'bl-4', name: 'Block Trackers By URL', enabled: true, action: 'block', filter: '~u tracker' },
  ];
  const result4 = applyRequestRules(filteredBlock, {}, '', exchange);
  assert.equal(result4.blocked, true, 'Filter-matched block rule should block');

  // ── Test 5: Filter-scoped block — non-matching exchange ───────────────────
  const safeExchange = { url: 'https://example.com/page', method: 'GET', status: 0 };
  const result5 = applyRequestRules(filteredBlock, {}, '', safeExchange);
  assert.equal(result5.blocked, false, 'Block rule with non-matching filter should not block');

  // ── Test 6: Block on response scope — not applied in request pipeline ──────
  const responseScoped = [
    { id: 'bl-6', name: 'Response Block', enabled: true, action: 'block', scope: 'response' },
  ];
  const result6 = applyRequestRules(responseScoped, {}, '', exchange);
  assert.equal(result6.blocked, false, 'Response-scoped block should not apply in request pipeline');

  // ── Test 7: Multiple non-block rules execute before block ──────────────────
  const mixedRules = [
    { id: 'bl-7a', name: 'AntiComp', enabled: true, action: 'anticomp' },
    { id: 'bl-7b', name: 'Block', enabled: true, action: 'block' },
  ];
  const mixedHeaders = { 'Accept-Encoding': 'gzip', 'If-None-Match': '"tag"' };
  const result7 = applyRequestRules(mixedRules, mixedHeaders, '', exchange);
  assert.equal(result7.blocked, true);
  assert.equal(result7.headers['Accept-Encoding'], undefined, 'anticomp should have run before block');
  assert.equal(result7.annotations.length, 2, 'Should have anticomp + block annotations');

  console.log('PASS traffic-rules-blocklist');
} catch (err) {
  console.error('FAIL traffic-rules-blocklist:', err.message);
  process.exit(1);
}
