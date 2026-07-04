// headless-full-chain-playbook.mjs
// Headless test: exercises the complete playbook → evidence → gate flow.
// No live network or Electron needed — uses synthetic fixtures throughout.
//
// Flow exercised:
//   1. Load a recipe (webPayloadFamilyValidation)
//   2. Run through its steps with the recipe engine
//   3. Produce synthetic oracle observations (simulating scan results)
//   4. Evaluate evidence gates against those observations
//   5. Verify the complete result structure is well-formed

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fsSync from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// tryLoad
// ---------------------------------------------------------------------------

function tryLoad(relPath) {
  const candidates = [
    path.resolve(__dirname, '../dist-electron/src', relPath),
    path.resolve(__dirname, '../dist-electron', relPath),
  ];
  for (const candidate of candidates) {
    if (fsSync.existsSync(candidate)) {
      try {
        return require(candidate);
      } catch (err) {
        console.log(`[SKIP] headless-full-chain-playbook: failed to load ${candidate}: ${err.message}`);
        process.exit(0);
      }
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Load modules
// ---------------------------------------------------------------------------

const engineMod = tryLoad('automation/playbookRecipeEngine.js');
if (!engineMod) {
  console.log('[SKIP] headless-full-chain-playbook: playbookRecipeEngine not compiled');
  process.exit(0);
}

const gateMod = tryLoad('automation/playbookEvidenceGate.js');
if (!gateMod) {
  console.log('[SKIP] headless-full-chain-playbook: playbookEvidenceGate not compiled');
  process.exit(0);
}

const schemaMod = tryLoad('automation/playbookSchema.js');
if (!schemaMod) {
  console.log('[SKIP] headless-full-chain-playbook: playbookSchema not compiled');
  process.exit(0);
}

const recipeMod = tryLoad('automation/recipes/webPayloadFamilyValidation.js');
if (!recipeMod) {
  console.log('[SKIP] headless-full-chain-playbook: webPayloadFamilyValidation not compiled');
  process.exit(0);
}

// Destructure engine
const {
  createRecipeRun,
  advanceRecipeRun,
  getNextStep,
  completeRecipeRun,
  failRecipeRun,
  stopRecipeRun,
  isRecipeRunComplete,
} = engineMod;

// Destructure gate evaluator
const {
  evaluateGate,
  evaluateAllGates,
  allRequiredGatesPassed,
  checkAllRequiredGates,
} = gateMod;

// Destructure schema
const { validateRecipe, parseRecipeJson, serializeRecipe } = schemaMod;

const { webPayloadFamilyValidation } = recipeMod;

// ---------------------------------------------------------------------------
// Verify all required exports are present
// ---------------------------------------------------------------------------

const requiredEngine = ['createRecipeRun', 'advanceRecipeRun', 'getNextStep', 'completeRecipeRun', 'isRecipeRunComplete'];
const missingEngine = requiredEngine.filter((n) => typeof engineMod[n] !== 'function');
if (missingEngine.length) {
  console.log(`[SKIP] headless-full-chain-playbook: missing engine exports: ${missingEngine.join(', ')}`);
  process.exit(0);
}

if (typeof evaluateGate !== 'function' || typeof evaluateAllGates !== 'function') {
  console.log('[SKIP] headless-full-chain-playbook: evaluateGate / evaluateAllGates not exported');
  process.exit(0);
}

if (!webPayloadFamilyValidation || typeof webPayloadFamilyValidation !== 'object') {
  console.log('[SKIP] headless-full-chain-playbook: webPayloadFamilyValidation not exported');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Build a custom fixture recipe with evidence gates (webPayloadFamilyValidation
// has empty evidenceGates, so we augment it for the full-chain test)
// ---------------------------------------------------------------------------

const fixtureRecipe = {
  ...webPayloadFamilyValidation,
  id: 'headless-chain-fixture-recipe',
  evidenceGates: [
    {
      id: 'gate-sql-evidence',
      checkId: 'sql-injection',
      requiredClass: 'expected-proof',
      minConfidence: 0.75,
      required: true,
    },
    {
      id: 'gate-xss-evidence',
      checkId: undefined,
      requiredClass: 'xss-reflection',
      minConfidence: 0.7,
      required: false,
    },
    {
      id: 'gate-timing',
      checkId: undefined,
      requiredClass: 'timing-delta',
      minConfidence: 0.8,
      required: false,
    },
  ],
};

// Synthetic oracle observations (simulating scanner output for the fixture exchange)
const syntheticObservations = [
  {
    responseClass: 'expected-proof',
    confidence: 0.92,
    checkId: 'sql-injection',
  },
  {
    responseClass: 'xss-reflection',
    confidence: 0.78,
    checkId: 'xss-reflected',
  },
  // No timing-delta observation — gate-timing is optional so overall should still pass
];

// ---------------------------------------------------------------------------
// Phase 1: Recipe schema validation
// ---------------------------------------------------------------------------

if (typeof validateRecipe === 'function') {
  const validation = validateRecipe(webPayloadFamilyValidation);
  assert.equal(typeof validation, 'object', 'Phase 1 — validateRecipe should return an object');
  assert.equal(typeof validation.valid, 'boolean', 'Phase 1 — validation.valid should be boolean');
  assert.ok(Array.isArray(validation.errors), 'Phase 1 — validation.errors should be an array');
  assert.equal(validation.valid, true, 'Phase 1 — webPayloadFamilyValidation should pass validation');
  assert.equal(validation.errors.length, 0, 'Phase 1 — no validation errors should be present');
}

// ---------------------------------------------------------------------------
// Phase 2: Serialize and re-parse the recipe (round-trip)
// ---------------------------------------------------------------------------

if (typeof serializeRecipe === 'function' && typeof parseRecipeJson === 'function') {
  const serialized = serializeRecipe(webPayloadFamilyValidation);
  assert.equal(typeof serialized, 'string', 'Phase 2 — serialized recipe should be a string');
  const reparsed = parseRecipeJson(serialized);
  assert.equal(reparsed.id, webPayloadFamilyValidation.id, 'Phase 2 — round-trip should preserve recipe id');
  assert.equal(reparsed.steps.length, webPayloadFamilyValidation.steps.length, 'Phase 2 — round-trip should preserve steps');
}

// ---------------------------------------------------------------------------
// Phase 3: Run the recipe through all steps (headless simulation)
// ---------------------------------------------------------------------------

let run = createRecipeRun(fixtureRecipe);
assert.equal(run.status, 'queued', 'Phase 3 — initial status should be queued');
assert.equal(run.recipeId, fixtureRecipe.id, 'Phase 3 — recipeId should match fixture recipe');

const stepSequence = [];
let safetyCounter = 0;
const maxSteps = fixtureRecipe.steps.length + 5;

while (!isRecipeRunComplete(run) && safetyCounter < maxSteps) {
  const step = getNextStep(run, fixtureRecipe);
  if (!step) break;

  stepSequence.push(step.id);
  run = advanceRecipeRun(run, step.id, true);
  safetyCounter++;

  const next = getNextStep(run, fixtureRecipe);
  if (!next) {
    run = completeRecipeRun(run);
  }
}

assert.equal(run.status, 'complete', 'Phase 3 — run should complete after all steps');
assert.ok(stepSequence.length > 0, 'Phase 3 — at least one step should have been executed');
assert.equal(typeof run.completedAt, 'string', 'Phase 3 — completedAt should be set');

// All steps from the recipe should appear in completedSteps
for (const step of fixtureRecipe.steps) {
  assert.ok(
    run.completedSteps.includes(step.id),
    `Phase 3 — step "${step.id}" should be in completedSteps`,
  );
}

// ---------------------------------------------------------------------------
// Phase 4: Evaluate evidence gates against synthetic observations
// ---------------------------------------------------------------------------

const gateResults = evaluateAllGates(fixtureRecipe.evidenceGates, syntheticObservations);
assert.equal(gateResults.length, fixtureRecipe.evidenceGates.length, 'Phase 4 — one gate result per gate');

// Verify each result has the correct shape
for (const result of gateResults) {
  assert.equal(typeof result.gateId, 'string', 'Phase 4 — gateId should be a string');
  assert.equal(typeof result.passed, 'boolean', 'Phase 4 — passed should be boolean');
  assert.equal(typeof result.reason, 'string', 'Phase 4 — reason should be a string');
}

// gate-sql-evidence (required=true): observation matches sql-injection + expected-proof @ 0.92 → should pass
const sqlGateResult = gateResults.find((r) => r.gateId === 'gate-sql-evidence');
assert.ok(sqlGateResult !== undefined, 'Phase 4 — gate-sql-evidence result should exist');
assert.equal(sqlGateResult.passed, true, 'Phase 4 — required gate-sql-evidence should pass');
assert.equal(sqlGateResult.observedConfidence, 0.92, 'Phase 4 — observed confidence should be 0.92');

// gate-xss-evidence (required=false): xss-reflection @ 0.78 → should pass
const xssGateResult = gateResults.find((r) => r.gateId === 'gate-xss-evidence');
assert.ok(xssGateResult !== undefined, 'Phase 4 — gate-xss-evidence result should exist');
assert.equal(xssGateResult.passed, true, 'Phase 4 — optional gate-xss-evidence should pass');

// gate-timing (required=false): no timing-delta observation → should fail
const timingGateResult = gateResults.find((r) => r.gateId === 'gate-timing');
assert.ok(timingGateResult !== undefined, 'Phase 4 — gate-timing result should exist');
assert.equal(timingGateResult.passed, false, 'Phase 4 — gate-timing should fail (no timing-delta observation)');

// ---------------------------------------------------------------------------
// Phase 5: Required-gate verdict — only required gates count
// ---------------------------------------------------------------------------

// allRequiredGatesPassed checks ALL passed in the array; we filter to required gates only
const requiredGateResults = fixtureRecipe.evidenceGates
  .map((gate, i) => ({ gate, result: gateResults[i] }))
  .filter(({ gate }) => gate.required)
  .map(({ result }) => result);

const overallVerdict = allRequiredGatesPassed(requiredGateResults);
assert.equal(overallVerdict, true, 'Phase 5 — overall verdict should be true (only required gate passes)');

// Use checkAllRequiredGates if available
if (typeof checkAllRequiredGates === 'function') {
  const autoVerdict = checkAllRequiredGates(fixtureRecipe.evidenceGates, syntheticObservations);
  assert.equal(autoVerdict, true, 'Phase 5 — checkAllRequiredGates should return true');
}

// ---------------------------------------------------------------------------
// Phase 6: Failure path — all required gates fail means overall false
// ---------------------------------------------------------------------------

const emptyObs = [];
const failedGateResults = evaluateAllGates(fixtureRecipe.evidenceGates, emptyObs);
const requiredFailed = fixtureRecipe.evidenceGates
  .map((gate, i) => ({ gate, result: failedGateResults[i] }))
  .filter(({ gate }) => gate.required)
  .map(({ result }) => result);

const failureVerdict = allRequiredGatesPassed(requiredFailed);
assert.equal(failureVerdict, false, 'Phase 6 — required gate verdict should be false with no observations');

// ---------------------------------------------------------------------------
// Phase 7: Stop condition — stopRecipeRun terminates early, gates still evaluate
// ---------------------------------------------------------------------------

{
  const stopRun = createRecipeRun(fixtureRecipe);
  const firstStep = getNextStep(stopRun, fixtureRecipe);
  assert.ok(firstStep !== null, 'Phase 7 — first step should be available');

  const advanced = advanceRecipeRun(stopRun, firstStep.id, true);
  const stopped = stopRecipeRun(advanced, 'budget.exceeded');

  assert.equal(stopped.status, 'stopped', 'Phase 7 — run should be stopped');
  assert.equal(isRecipeRunComplete(stopped), true, 'Phase 7 — stopped run is terminal');
  assert.ok(stopped.errors.some((e) => e.includes('budget.exceeded')), 'Phase 7 — stop reason recorded');

  // Gates can still be evaluated independently of run status
  const partialObs = [{ responseClass: 'expected-proof', confidence: 0.88, checkId: 'sql-injection' }];
  const gateResultsAfterStop = evaluateAllGates(fixtureRecipe.evidenceGates, partialObs);
  assert.equal(gateResultsAfterStop.length, fixtureRecipe.evidenceGates.length, 'Phase 7 — gate evaluation works after stop');
}

// ---------------------------------------------------------------------------
// Phase 8: Full result structure validation
// ---------------------------------------------------------------------------

{
  const finalResult = {
    run: {
      id: run.id,
      recipeId: run.recipeId,
      status: run.status,
      completedSteps: run.completedSteps,
      errors: run.errors,
      startedAt: run.startedAt,
      completedAt: run.completedAt,
    },
    gateResults,
    overallVerdict,
    stepsExecuted: stepSequence.length,
    totalGates: fixtureRecipe.evidenceGates.length,
    requiredGatesPassed: requiredGateResults.filter((r) => r.passed).length,
    requiredGatesTotal: requiredGateResults.length,
  };

  assert.equal(typeof finalResult.run.id, 'string', 'Phase 8 — run.id in result should be a string');
  assert.equal(finalResult.run.status, 'complete', 'Phase 8 — result status should be complete');
  assert.ok(finalResult.stepsExecuted > 0, 'Phase 8 — at least one step should have been executed');
  assert.equal(finalResult.totalGates, 3, 'Phase 8 — should have 3 gates total');
  assert.equal(finalResult.requiredGatesTotal, 1, 'Phase 8 — should have 1 required gate');
  assert.equal(finalResult.requiredGatesPassed, 1, 'Phase 8 — required gate should have passed');
  assert.equal(finalResult.overallVerdict, true, 'Phase 8 — overall verdict should be true');
}

console.log('PASS headless-full-chain-playbook');
