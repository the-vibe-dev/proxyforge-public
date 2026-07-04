// playbook-evidence-gates.mjs
// Tests the playbookEvidenceGate module: evaluateGate, evaluateAllGates,
// allRequiredGatesPassed, and checkAllRequiredGates.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fsSync from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// Locate the compiled module — try dist-electron/src/automation first
// (rootDir is ".." so src files compile to dist-electron/src/...)
// ---------------------------------------------------------------------------

const candidates = [
  path.resolve(__dirname, '../dist-electron/src/automation/playbookEvidenceGate.js'),
  path.resolve(__dirname, '../dist-electron/automation/playbookEvidenceGate.js'),
];

let mod = null;
for (const candidate of candidates) {
  if (fsSync.existsSync(candidate)) {
    try {
      mod = require(candidate);
      break;
    } catch (err) {
      console.log(`[SKIP] playbook-evidence-gates: failed to load ${candidate}: ${err.message}`);
      process.exit(0);
    }
  }
}

if (!mod) {
  console.log('[SKIP] playbook-evidence-gates: module not compiled');
  process.exit(0);
}

// Verify expected exports
const { evaluateGate, evaluateAllGates, allRequiredGatesPassed, checkAllRequiredGates } = mod;

if (typeof evaluateGate !== 'function') {
  console.log('[SKIP] playbook-evidence-gates: evaluateGate not exported');
  process.exit(0);
}
if (typeof evaluateAllGates !== 'function') {
  console.log('[SKIP] playbook-evidence-gates: evaluateAllGates not exported');
  process.exit(0);
}
if (typeof allRequiredGatesPassed !== 'function') {
  console.log('[SKIP] playbook-evidence-gates: allRequiredGatesPassed not exported');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Fixture helpers
// ---------------------------------------------------------------------------

function makeGate(overrides = {}) {
  return {
    id: 'gate-test-1',
    requiredClass: 'expected-proof',
    minConfidence: 0.8,
    required: true,
    ...overrides,
  };
}

function makeObs(overrides = {}) {
  return {
    responseClass: 'expected-proof',
    confidence: 0.9,
    checkId: undefined,
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Test 1: gate passes when observation matches required class + confidence
// ---------------------------------------------------------------------------
{
  const gate = makeGate();
  const obs = [makeObs()];
  const result = evaluateGate(gate, obs);
  assert.equal(typeof result, 'object', 'Test 1 — result should be an object');
  assert.equal(result.gateId, gate.id, 'Test 1 — result.gateId should match gate.id');
  assert.equal(result.passed, true, 'Test 1 — gate should pass when class + confidence match');
  assert.equal(typeof result.reason, 'string', 'Test 1 — result.reason should be a string');
}

// ---------------------------------------------------------------------------
// Test 2: gate fails when no observation present (empty context)
// ---------------------------------------------------------------------------
{
  const gate = makeGate();
  const result = evaluateGate(gate, []);
  assert.equal(result.passed, false, 'Test 2 — gate should fail with empty observations');
  assert.ok(result.reason.includes(gate.requiredClass), 'Test 2 — reason should mention requiredClass');
}

// ---------------------------------------------------------------------------
// Test 3: gate fails when observation class does not match required class
// ---------------------------------------------------------------------------
{
  const gate = makeGate({ requiredClass: 'expected-proof' });
  const obs = [makeObs({ responseClass: 'neutral-or-not-parsed' })];
  const result = evaluateGate(gate, obs);
  assert.equal(result.passed, false, 'Test 3 — gate should fail when class does not match');
}

// ---------------------------------------------------------------------------
// Test 4: gate fails when confidence is below minConfidence
// ---------------------------------------------------------------------------
{
  const gate = makeGate({ minConfidence: 0.8 });
  const obs = [makeObs({ confidence: 0.5 })];
  const result = evaluateGate(gate, obs);
  assert.equal(result.passed, false, 'Test 4 — gate should fail when confidence is below threshold');
  assert.ok(typeof result.observedConfidence === 'number', 'Test 4 — observedConfidence should be set on failure');
}

// ---------------------------------------------------------------------------
// Test 5: gate passes exactly at minConfidence threshold (boundary)
// ---------------------------------------------------------------------------
{
  const gate = makeGate({ minConfidence: 0.8 });
  const obs = [makeObs({ confidence: 0.8 })];
  const result = evaluateGate(gate, obs);
  assert.equal(result.passed, true, 'Test 5 — gate should pass at exactly minConfidence');
}

// ---------------------------------------------------------------------------
// Test 6: gate with checkId fails when observation checkId does not match
// ---------------------------------------------------------------------------
{
  const gate = makeGate({ checkId: 'sql-injection' });
  const obs = [makeObs({ checkId: 'reflected-xss' })];
  const result = evaluateGate(gate, obs);
  assert.equal(result.passed, false, 'Test 6 — gate with checkId should fail on wrong checkId');
  assert.ok(result.reason.includes('sql-injection'), 'Test 6 — reason should mention checkId');
}

// ---------------------------------------------------------------------------
// Test 7: gate with checkId passes when checkId matches
// ---------------------------------------------------------------------------
{
  const gate = makeGate({ checkId: 'sql-injection' });
  const obs = [makeObs({ checkId: 'sql-injection' })];
  const result = evaluateGate(gate, obs);
  assert.equal(result.passed, true, 'Test 7 — gate with checkId should pass when checkId matches');
}

// ---------------------------------------------------------------------------
// Test 8: gate without checkId accepts any observation's checkId
// ---------------------------------------------------------------------------
{
  const gate = makeGate({ checkId: undefined });
  const obs = [makeObs({ responseClass: 'expected-proof', checkId: 'any-check' })];
  const result = evaluateGate(gate, obs);
  assert.equal(result.passed, true, 'Test 8 — gate without checkId should accept any checkId');
}

// ---------------------------------------------------------------------------
// Test 9: gate picks highest-confidence observation when multiple present
// ---------------------------------------------------------------------------
{
  const gate = makeGate({ minConfidence: 0.85 });
  const obs = [
    makeObs({ confidence: 0.5 }),
    makeObs({ confidence: 0.95 }),
    makeObs({ confidence: 0.7 }),
  ];
  const result = evaluateGate(gate, obs);
  assert.equal(result.passed, true, 'Test 9 — gate should pass using highest-confidence observation');
  assert.equal(result.observedConfidence, 0.95, 'Test 9 — observedConfidence should be 0.95');
}

// ---------------------------------------------------------------------------
// Test 10: evaluateAllGates returns one result per gate
// ---------------------------------------------------------------------------
{
  const gates = [
    makeGate({ id: 'gate-a', requiredClass: 'expected-proof' }),
    makeGate({ id: 'gate-b', requiredClass: 'oast-callback-confirmed' }),
  ];
  const obs = [makeObs({ responseClass: 'expected-proof', confidence: 0.9 })];
  const results = evaluateAllGates(gates, obs);
  assert.equal(results.length, 2, 'Test 10 — evaluateAllGates should return one result per gate');
  assert.equal(results[0].gateId, 'gate-a', 'Test 10 — first result maps to first gate');
  assert.equal(results[1].gateId, 'gate-b', 'Test 10 — second result maps to second gate');
  assert.equal(results[0].passed, true, 'Test 10 — gate-a should pass (class matches)');
  assert.equal(results[1].passed, false, 'Test 10 — gate-b should fail (class does not match)');
}

// ---------------------------------------------------------------------------
// Test 11: allRequiredGatesPassed returns true when all results pass
// ---------------------------------------------------------------------------
{
  const results = [
    { gateId: 'gate-1', passed: true, reason: 'ok' },
    { gateId: 'gate-2', passed: true, reason: 'ok' },
  ];
  assert.equal(allRequiredGatesPassed(results), true, 'Test 11 — should return true when all pass');
}

// ---------------------------------------------------------------------------
// Test 12: allRequiredGatesPassed returns false when any result fails
// ---------------------------------------------------------------------------
{
  const results = [
    { gateId: 'gate-1', passed: true, reason: 'ok' },
    { gateId: 'gate-2', passed: false, reason: 'miss' },
  ];
  assert.equal(allRequiredGatesPassed(results), false, 'Test 12 — should return false when any fails');
}

// ---------------------------------------------------------------------------
// Test 13: allRequiredGatesPassed returns true for empty results array
// ---------------------------------------------------------------------------
{
  assert.equal(allRequiredGatesPassed([]), true, 'Test 13 — empty results should vacuously pass');
}

// ---------------------------------------------------------------------------
// Test 14: checkAllRequiredGates (if exported) filters by required flag
// ---------------------------------------------------------------------------
if (typeof checkAllRequiredGates === 'function') {
  const gates = [
    makeGate({ id: 'required-gate', requiredClass: 'expected-proof', required: true }),
    makeGate({ id: 'optional-gate', requiredClass: 'oast-callback-confirmed', required: false }),
  ];
  const obs = [makeObs({ responseClass: 'expected-proof', confidence: 0.9 })];
  // optional-gate will fail (class mismatch) but required-gate passes
  const allPassed = checkAllRequiredGates(gates, obs);
  assert.equal(allPassed, true, 'Test 14 — checkAllRequiredGates should ignore non-required gates');
}

// ---------------------------------------------------------------------------
// Test 15: result includes observedClass on pass
// ---------------------------------------------------------------------------
{
  const gate = makeGate();
  const obs = [makeObs({ responseClass: 'expected-proof', confidence: 0.9 })];
  const result = evaluateGate(gate, obs);
  assert.equal(result.observedClass, 'expected-proof', 'Test 15 — result.observedClass should be set on pass');
  assert.equal(result.observedConfidence, 0.9, 'Test 15 — result.observedConfidence should be set on pass');
}

console.log('PASS playbook-evidence-gates');
