// Phase 1 — Tests for oracleResponseClassifier.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const {
  classifyOracleObservation,
  buildOracleObservation,
  fingerprintResponse,
  shouldPromoteToFinding,
  highestConfidenceClassification,
} = require('../dist-electron/src/scanner/oracleResponseClassifier.js');

function makeVariant(family, requiresOast = false) {
  return {
    id: `test-${family}`,
    family,
    value: 'test-payload',
    encoding: 'raw',
    intent: 'test',
    destructiveRisk: 'none',
    expectedSignals: ['test'],
    requiresOast,
  };
}

function makeResponse(body, status = 200, timeMs = 100) {
  return {
    statusCode: status,
    headers: { 'content-type': 'text/html' },
    bodyText: body,
    responseTimeMs: timeMs,
  };
}

// SQL injection: error pattern → expected-proof
{
  const variant = makeVariant('sql-injection');
  const resp = makeResponse("You have an error in your SQL syntax near 'test'");
  const obs = buildOracleObservation(variant.id, variant.value, resp);
  const classification = classifyOracleObservation(obs, variant);
  assert.equal(classification.responseClass, 'expected-proof', 'SQL error should classify as expected-proof');
  assert.ok(classification.confidence >= 0.7, 'SQL error confidence should be ≥0.7');
  assert.equal(classification.nextAction, 'promote-finding', 'SQL error should trigger promote-finding');
  console.log('  SQL injection oracle: PASS');
}

// XSS reflected: active execution → expected-proof
{
  const variant = makeVariant('xss-reflected');
  variant.value = '<script>alert(1)</script>';
  const resp = makeResponse('<html><script>alert(1)</script></html>');
  const obs = buildOracleObservation(variant.id, variant.value, resp);
  const classification = classifyOracleObservation(obs, variant);
  assert.equal(classification.responseClass, 'expected-proof', 'XSS active execution should be expected-proof');
  console.log('  XSS oracle (active): PASS');
}

// XSS reflected: inert reflection only → reflected-inert (must NOT promote)
{
  const variant = makeVariant('xss-reflected');
  variant.value = '<script>alert(1)</script>';
  const resp = makeResponse('<html>&lt;script&gt;alert(1)&lt;/script&gt;</html>');
  const obs = buildOracleObservation(variant.id, variant.value, resp);
  const classification = classifyOracleObservation(obs, variant);
  // Escaped reflection should be reflected-inert or neutral
  assert.ok(
    classification.responseClass !== 'expected-proof',
    'Entity-escaped reflection must not classify as expected-proof',
  );
  console.log('  XSS oracle (inert): PASS');
}

// SSTI: math eval → expected-proof
{
  const variant = makeVariant('ssti');
  const resp = makeResponse('Result: 49 items found');
  const obs = buildOracleObservation(variant.id, variant.value, resp);
  const classification = classifyOracleObservation(obs, variant);
  assert.equal(classification.responseClass, 'expected-proof', 'SSTI math result should be expected-proof');
  console.log('  SSTI oracle (49): PASS');
}

// LFI: passwd content → expected-proof
{
  const variant = makeVariant('lfi-traversal');
  const resp = makeResponse('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:');
  const obs = buildOracleObservation(variant.id, variant.value, resp);
  const classification = classifyOracleObservation(obs, variant);
  assert.equal(classification.responseClass, 'expected-proof', 'File content should be expected-proof');
  console.log('  LFI oracle: PASS');
}

// Neutral: no signals → neutral-or-not-parsed + stop-negative
{
  const variant = makeVariant('sql-injection');
  const resp = makeResponse('<html>Normal page content here</html>');
  const obs = buildOracleObservation(variant.id, variant.value, resp);
  const classification = classifyOracleObservation(obs, variant);
  assert.equal(classification.responseClass, 'neutral-or-not-parsed', 'No-signal response should be neutral');
  assert.equal(classification.nextAction, 'stop-negative', 'Neutral should trigger stop-negative');
  console.log('  Neutral oracle: PASS');
}

// OAST variant: classification deferred
{
  const variant = makeVariant('ssrf-oast', true);
  const resp = makeResponse('<html>page</html>');
  const obs = buildOracleObservation(variant.id, variant.value, resp);
  const classification = classifyOracleObservation(obs, variant);
  assert.equal(classification.responseClass, 'unknown', 'OAST variant should defer classification');
  assert.equal(classification.nextAction, 'continue', 'OAST variant should continue waiting');
  console.log('  OAST deferred: PASS');
}

// Timing delta: 5 second delay
{
  const variant = makeVariant('sql-injection');
  variant.expectedSignals = ['timing-delta'];
  const baseline = fingerprintResponse(makeResponse('<html>base</html>', 200, 100));
  const resp = makeResponse('<html>base</html>', 200, 5500);
  const obs = buildOracleObservation(variant.id, variant.value, resp, baseline);
  obs.timingMs = 5500;
  obs.baseline = baseline;
  const classification = classifyOracleObservation(obs, variant, baseline);
  assert.equal(classification.responseClass, 'timing-delta', 'Large timing delta should classify as timing-delta');
  console.log('  Timing delta oracle: PASS');
}

// shouldPromoteToFinding
assert.ok(
  shouldPromoteToFinding([{ responseClass: 'expected-proof', payloadVariantId: 'x', confidence: 0.9, evidence: [], nextAction: 'promote-finding' }]),
  'expected-proof should trigger promotion',
);
assert.ok(
  !shouldPromoteToFinding([{ responseClass: 'reflected-inert', payloadVariantId: 'x', confidence: 0.3, evidence: [], nextAction: 'continue' }]),
  'reflected-inert alone must not trigger promotion',
);
console.log('  shouldPromoteToFinding: PASS');

// highestConfidenceClassification
const best = highestConfidenceClassification([
  { responseClass: 'neutral-or-not-parsed', payloadVariantId: 'a', confidence: 0.1, evidence: [], nextAction: 'stop-negative' },
  { responseClass: 'expected-proof', payloadVariantId: 'b', confidence: 0.9, evidence: [], nextAction: 'promote-finding' },
]);
assert.equal(best?.payloadVariantId, 'b', 'highest confidence should be returned');
console.log('  highestConfidenceClassification: PASS');

console.log('PASS scanner-oracle-response-classifier');
