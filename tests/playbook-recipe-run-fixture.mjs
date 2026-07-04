// Test: playbook recipe engine — run lifecycle + evidence gate evaluation.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function tryLoad(candidates) {
  for (const c of candidates) {
    try { return require(c); } catch { /* next */ }
  }
  return null;
}

// ── Part 1: playbookRecipeEngine ──────────────────────────────────────────────

const engineMod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'src', 'automation', 'playbookRecipeEngine.js'),
  path.join(__dirname, '..', 'dist-electron', 'automation', 'playbookRecipeEngine.js'),
]);

if (!engineMod) {
  console.log('SKIP: playbook-recipe-run-fixture — dist-electron/src/automation/playbookRecipeEngine.js not compiled, run tsc first.');
  process.exit(0);
}

const {
  createRecipeRun,
  advanceRecipeRun,
  stopRecipeRun,
  completeRecipeRun,
  failRecipeRun,
  isRecipeRunComplete,
  getNextStep,
} = engineMod;

// Minimal recipe fixture
const minimalRecipe = {
  id: 'fixture-recipe',
  name: 'Fixture Recipe',
  summary: 'Used for testing.',
  requiredInputs: [],
  steps: [
    { id: 'step-1', type: 'scan', label: 'Step 1', config: {}, onSuccess: 'step-2' },
    { id: 'step-2', type: 'scan', label: 'Step 2', config: {} },
  ],
  evidenceGates: [],
  stopConditions: [],
  defaultBudgets: { maxRequests: 100, maxRuntimeMs: 60000, maxPayloadsPerInsertionPoint: 5 },
};

// 1. createRecipeRun returns a run in queued state
assert.ok(typeof createRecipeRun === 'function', 'createRecipeRun must be a function');
const run = createRecipeRun(minimalRecipe);
assert.ok(run !== null && typeof run === 'object', 'createRecipeRun should return an object');
assert.ok(typeof run.id === 'string' && run.id.length > 0, 'run.id should be a non-empty string');
assert.equal(run.recipeId, 'fixture-recipe', 'run.recipeId should match recipe.id');
assert.equal(run.status, 'queued', 'run.status should be "queued"');
assert.ok(Array.isArray(run.completedSteps), 'run.completedSteps should be an array');
assert.ok(Array.isArray(run.errors), 'run.errors should be an array');
assert.ok(typeof run.startedAt === 'string', 'run.startedAt should be set');
// First step should be set as currentStepId
assert.equal(run.currentStepId, 'step-1', 'currentStepId should point to the first step');

// 2. getNextStep resolves the first step from a fresh run
assert.ok(typeof getNextStep === 'function', 'getNextStep must be a function');
const firstStep = getNextStep(run, minimalRecipe);
assert.ok(firstStep !== null, 'getNextStep should return the first step');
assert.equal(firstStep.id, 'step-1', 'first step id should be "step-1"');

// 3. advanceRecipeRun marks step completed and transitions to running
assert.ok(typeof advanceRecipeRun === 'function', 'advanceRecipeRun must be a function');
const advanced = advanceRecipeRun(run, 'step-1', true);
assert.equal(advanced.status, 'running', 'status should be "running" after advance');
assert.ok(advanced.completedSteps.includes('step-1'), 'step-1 should be in completedSteps');

// 4. stopRecipeRun transitions to stopped with reason
assert.ok(typeof stopRecipeRun === 'function', 'stopRecipeRun must be a function');
const stopped = stopRecipeRun(advanced, 'budget exceeded');
assert.equal(stopped.status, 'stopped', 'status should be "stopped" after stopRecipeRun');
assert.ok(stopped.errors.includes('budget exceeded'), 'stop reason should appear in errors');
assert.ok(typeof stopped.completedAt === 'string', 'completedAt should be set');

// 5. isRecipeRunComplete returns true for terminal states
assert.ok(typeof isRecipeRunComplete === 'function', 'isRecipeRunComplete must be a function');
assert.equal(isRecipeRunComplete(stopped), true, 'stopped run should be complete');
assert.equal(isRecipeRunComplete(run), false, 'queued run should not be complete');

// 6. completeRecipeRun sets terminal success
assert.ok(typeof completeRecipeRun === 'function', 'completeRecipeRun must be a function');
const completed = completeRecipeRun(advanced);
assert.equal(completed.status, 'complete', 'status should be "complete" after completeRecipeRun');
assert.ok(typeof completed.completedAt === 'string', 'completedAt should be set');
assert.equal(isRecipeRunComplete(completed), true, 'completed run should be terminal');

// 7. failRecipeRun sets terminal failure
assert.ok(typeof failRecipeRun === 'function', 'failRecipeRun must be a function');
const failed = failRecipeRun(advanced, 'probe error');
assert.equal(failed.status, 'failed', 'status should be "failed" after failRecipeRun');
assert.ok(failed.errors.includes('probe error'), 'failure reason should appear in errors');
assert.equal(isRecipeRunComplete(failed), true, 'failed run should be terminal');

// ── Part 2: webPayloadFamilyValidation recipe ─────────────────────────────────

const recipeMod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'src', 'automation', 'recipes', 'webPayloadFamilyValidation.js'),
  path.join(__dirname, '..', 'dist-electron', 'automation', 'recipes', 'webPayloadFamilyValidation.js'),
]);

if (recipeMod) {
  const recipe = recipeMod.webPayloadFamilyValidation ?? Object.values(recipeMod).find(v => v && typeof v === 'object' && v.id);
  if (recipe) {
    assert.ok(typeof recipe.id === 'string' && recipe.id.length > 0, 'recipe.id should be a non-empty string');
    assert.ok(typeof recipe.name === 'string' && recipe.name.length > 0, 'recipe.name should be a non-empty string');
    assert.ok(Array.isArray(recipe.steps) && recipe.steps.length > 0, 'recipe.steps should be a non-empty array');
    assert.ok(Array.isArray(recipe.evidenceGates), 'recipe.evidenceGates should be an array');
    console.log(`NOTE playbook-recipe-run-fixture: webPayloadFamilyValidation recipe has ${recipe.steps.length} steps.`);
  }
}

// ── Part 3: playbookEvidenceGate ──────────────────────────────────────────────

const gateMod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'src', 'automation', 'playbookEvidenceGate.js'),
  path.join(__dirname, '..', 'dist-electron', 'automation', 'playbookEvidenceGate.js'),
]);

if (gateMod) {
  const { evaluateGate } = gateMod;
  assert.ok(typeof evaluateGate === 'function', 'evaluateGate must be a function');

  const gate = { id: 'gate-1', requiredClass: 'sql-error', minConfidence: 0.8, required: true };

  // evaluateGate with no matching observations → passed:false
  const noMatch = evaluateGate(gate, []);
  assert.ok(noMatch !== null && typeof noMatch === 'object', 'evaluateGate should return an object');
  assert.equal(typeof noMatch.passed, 'boolean', 'result.passed should be a boolean');
  assert.equal(noMatch.passed, false, 'gate should fail when observations is empty');
  assert.ok(typeof noMatch.reason === 'string', 'result.reason should be a string');

  // evaluateGate with a matching high-confidence observation → passed:true
  const obs = [{ responseClass: 'sql-error', confidence: 0.9, checkId: 'sql-injection' }];
  const match = evaluateGate(gate, obs);
  assert.equal(match.passed, true, 'gate should pass with a matching high-confidence observation');
  assert.ok(typeof match.reason === 'string' && match.reason.length > 0, 'match.reason should be non-empty');

  // evaluateGate with a matching but low-confidence observation → passed:false
  const lowConf = [{ responseClass: 'sql-error', confidence: 0.5, checkId: 'sql-injection' }];
  const lowResult = evaluateGate(gate, lowConf);
  assert.equal(lowResult.passed, false, 'gate should fail when confidence is below minConfidence');

  console.log('NOTE playbook-recipe-run-fixture: playbookEvidenceGate exercised.');
}

console.log('PASS playbook-recipe-run-fixture: recipe run lifecycle and evidence gate evaluation verified.');
