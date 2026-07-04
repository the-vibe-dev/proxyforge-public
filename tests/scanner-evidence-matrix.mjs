// Phase 1 — Tests for evidenceMatrix.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { concludeMatrix, buildNegativeEvidence } = require('../dist-electron/src/scanner/evidenceMatrix.js');

function makeClassification(responseClass, confidence) {
  return {
    payloadVariantId: `pv-${Math.random().toString(36).slice(2)}`,
    responseClass,
    confidence,
    evidence: [`test evidence for ${responseClass}`],
    nextAction: responseClass === 'expected-proof' ? 'promote-finding' : 'stop-negative',
  };
}

// expected-proof → finding
{
  const matrix = {
    classifications: [
      makeClassification('expected-proof', 0.9),
      makeClassification('neutral-or-not-parsed', 0.0),
    ],
    variants: [{ id: 'v1' }, { id: 'v2' }],
  };
  const conclusion = concludeMatrix(matrix);
  assert.equal(conclusion.state, 'finding', 'expected-proof should conclude as finding');
  assert.ok(conclusion.confidence >= 0.7, 'finding confidence should be high');
  console.log('  expected-proof → finding: PASS');
}

// All neutral → negative
{
  const matrix = {
    classifications: [
      makeClassification('neutral-or-not-parsed', 0.0),
      makeClassification('neutral-or-not-parsed', 0.0),
      makeClassification('neutral-or-not-parsed', 0.0),
    ],
    variants: [{ id: 'v1' }, { id: 'v2' }, { id: 'v3' }],
  };
  const conclusion = concludeMatrix(matrix);
  assert.equal(conclusion.state, 'negative', 'All neutral should conclude as negative');
  assert.ok(conclusion.confidence >= 0.5, 'negative confidence should be ≥0.5');
  console.log('  all-neutral → negative: PASS');
}

// Timing delta → inconclusive
{
  const matrix = {
    classifications: [
      makeClassification('timing-delta', 0.6),
    ],
    variants: [{ id: 'v1' }],
  };
  const conclusion = concludeMatrix(matrix);
  assert.equal(conclusion.state, 'inconclusive', 'timing-delta should conclude as inconclusive');
  console.log('  timing-delta → inconclusive: PASS');
}

// Empty classifications → inconclusive
{
  const matrix = {
    classifications: [],
    variants: [{ id: 'v1' }],
  };
  const conclusion = concludeMatrix(matrix);
  assert.equal(conclusion.state, 'inconclusive', 'empty classifications should be inconclusive');
  console.log('  empty → inconclusive: PASS');
}

// buildNegativeEvidence shape
{
  const neg = buildNegativeEvidence('sql-injection', 'ip-001', 'ex-001', 5, 'no patterns matched');
  assert.equal(neg.kind, 'proxyforge-scanner-negative-evidence');
  assert.equal(neg.conclusion, 'negative');
  assert.equal(neg.checkId, 'sql-injection');
  assert.equal(neg.variantsTested, 5);
  console.log('  buildNegativeEvidence: PASS');
}

console.log('PASS scanner-evidence-matrix');
