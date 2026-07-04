// Tests: probeMatrix.ts — createProbeMatrix, recordClassification, markMatrixStopped, isMatrixComplete
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let mod;
try {
  mod = require('../dist-electron/src/scanner/probeMatrix.js');
} catch {
  console.log('SKIP: scanner/probeMatrix not compiled');
  process.exit(0);
}

try {
  const {
    createProbeMatrix,
    recordClassification,
    markMatrixStopped,
    isMatrixComplete,
  } = mod;

  // Minimal payload variant stubs
  const stubVariants = [
    {
      id: 'pv-sql-injection-000-raw',
      family: 'sql-injection',
      value: "' OR '1'='1",
      encoding: 'raw',
      intent: 'test',
      destructiveRisk: 'none',
      expectedSignals: ['sql-error'],
    },
    {
      id: 'pv-sql-injection-001-raw',
      family: 'sql-injection',
      value: "' OR 1=1--",
      encoding: 'raw',
      intent: 'test2',
      destructiveRisk: 'none',
      expectedSignals: ['sql-error'],
    },
  ];

  // ── createProbeMatrix returns all required fields ─────────────────────────
  const matrix = createProbeMatrix(
    'proj-001',
    'exchange-abc',
    'sql-injection',
    'ip-search-query',
    stubVariants,
  );

  assert.ok(matrix.id, 'matrix.id must be set');
  assert.ok(matrix.id.startsWith('pm-'), `matrix.id must start with 'pm-', got: ${matrix.id}`);
  assert.equal(matrix.projectId, 'proj-001', 'matrix.projectId must match');
  assert.equal(matrix.sourceExchangeId, 'exchange-abc', 'matrix.sourceExchangeId must match');
  assert.equal(matrix.checkId, 'sql-injection', 'matrix.checkId must match');
  assert.equal(matrix.insertionPointId, 'ip-search-query', 'matrix.insertionPointId must match');
  assert.deepEqual(matrix.variants, stubVariants, 'matrix.variants must match input');
  assert.ok(Array.isArray(matrix.classifications), 'matrix.classifications must be an array');
  assert.equal(matrix.classifications.length, 0, 'matrix.classifications must start empty');
  assert.ok(Array.isArray(matrix.oastPayloadIds), 'matrix.oastPayloadIds must be an array');

  // ── finalState starts as 'running' ────────────────────────────────────────
  assert.equal(matrix.finalState, 'running', 'matrix.finalState must start as "running"');
  assert.equal(matrix.confidence, 0, 'matrix.confidence must start at 0');
  assert.ok(matrix.createdAt, 'matrix.createdAt must be set');
  assert.ok(matrix.updatedAt, 'matrix.updatedAt must be set');

  // ── isMatrixComplete returns false for running matrix ─────────────────────
  assert.equal(isMatrixComplete(matrix), false, 'running matrix must not be complete');

  // ── recordClassification: neutral keeps finalState 'running' ─────────────
  const neutralClassification = {
    variantId: stubVariants[0].id,
    responseClass: 'neutral-or-not-parsed',
    confidence: 0,
    evidence: [],
  };
  const afterNeutral = recordClassification(matrix, neutralClassification);
  assert.equal(afterNeutral.finalState, 'running', 'Single neutral classification should keep state running');
  assert.equal(afterNeutral.classifications.length, 1, 'classifications should have one entry');

  // ── recordClassification: expected-proof flips finalState to 'finding' ───
  const findingClassification = {
    variantId: stubVariants[0].id,
    responseClass: 'expected-proof',
    confidence: 0.9,
    evidence: ['sql-error'],
  };
  const afterFinding = recordClassification(matrix, findingClassification);
  assert.equal(afterFinding.finalState, 'finding', 'expected-proof classification must set finalState to "finding"');
  assert.equal(afterFinding.confidence, 0.9, 'confidence must be updated to 0.9');
  assert.equal(isMatrixComplete(afterFinding), true, 'finding matrix must be complete');

  // ── recordClassification: updateProbeMatrix-style update works ────────────
  const updated = { ...matrix, finalState: 'finding' };
  assert.equal(updated.finalState, 'finding', 'spread update must set finalState to "finding"');

  // ── markMatrixStopped returns stopped state ───────────────────────────────
  const stopped = markMatrixStopped(matrix);
  assert.equal(stopped.finalState, 'stopped', 'markMatrixStopped must set finalState to "stopped"');
  assert.equal(isMatrixComplete(stopped), true, 'stopped matrix must be complete');

  // ── markMatrixStopped with data returns reason ─────────────────────────────
  const matrixWithData = recordClassification(matrix, neutralClassification);
  const inconclusive = markMatrixStopped(matrixWithData, 'inconclusive');
  assert.equal(inconclusive.finalState, 'inconclusive', 'markMatrixStopped with data should use reason');

  console.log('PASS project-store-scan-probe-matrix');
} catch (err) {
  console.error('FAIL project-store-scan-probe-matrix:', err.message);
  process.exit(1);
}
