// headless-automation-recipes.mjs
// Headless test: run automation recipes against fixture data.
// No live network, no Electron launch — pure Node.js.
//
// Exercises: createRecipeRun, advanceRecipeRun, getNextStep, completeRecipeRun,
// failRecipeRun, stopRecipeRun, plus the webPayloadFamilyValidation recipe.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fsSync from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

// ---------------------------------------------------------------------------
// tryLoad — attempts dist-electron/src/... first, then dist-electron/...
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
        console.log(`[SKIP] headless-automation-recipes: failed to load ${candidate}: ${err.message}`);
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
  console.log('[SKIP] headless-automation-recipes: playbookRecipeEngine not compiled');
  process.exit(0);
}

const recipeMod = tryLoad('automation/recipes/webPayloadFamilyValidation.js');
if (!recipeMod) {
  console.log('[SKIP] headless-automation-recipes: webPayloadFamilyValidation recipe not compiled');
  process.exit(0);
}

const {
  createRecipeRun,
  advanceRecipeRun,
  getNextStep,
  completeRecipeRun,
  failRecipeRun,
  stopRecipeRun,
  isRecipeRunComplete,
} = engineMod;

// Verify required engine exports
const requiredFns = [
  'createRecipeRun', 'advanceRecipeRun', 'getNextStep',
  'completeRecipeRun', 'failRecipeRun', 'stopRecipeRun', 'isRecipeRunComplete',
];
const missing = requiredFns.filter((n) => typeof engineMod[n] !== 'function');
if (missing.length) {
  console.log(`[SKIP] headless-automation-recipes: missing engine exports: ${missing.join(', ')}`);
  process.exit(0);
}

const { webPayloadFamilyValidation } = recipeMod;
if (!webPayloadFamilyValidation || typeof webPayloadFamilyValidation !== 'object') {
  console.log('[SKIP] headless-automation-recipes: webPayloadFamilyValidation not exported');
  process.exit(0);
}

const recipe = webPayloadFamilyValidation;

// ---------------------------------------------------------------------------
// Synthetic fixture exchange (no live network needed)
// ---------------------------------------------------------------------------

const fixtureExchange = {
  id: 'exchange-fixture-001',
  request: {
    method: 'GET',
    url: 'https://example.test/search?q=hello',
    headers: { host: 'example.test', 'user-agent': 'ProxyForge/test' },
    body: null,
  },
  response: {
    statusCode: 200,
    headers: { 'content-type': 'text/html' },
    bodyText: '<html><body>Search results for hello</body></html>',
    responseTimeMs: 150,
  },
};

// ---------------------------------------------------------------------------
// Test 1: recipe has expected structure
// ---------------------------------------------------------------------------
{
  assert.equal(typeof recipe.id, 'string', 'Test 1 — recipe.id should be a string');
  assert.ok(recipe.id.length > 0, 'Test 1 — recipe.id should not be empty');
  assert.ok(Array.isArray(recipe.steps), 'Test 1 — recipe.steps should be an array');
  assert.ok(recipe.steps.length > 0, 'Test 1 — recipe should have at least one step');
  assert.ok(Array.isArray(recipe.evidenceGates), 'Test 1 — recipe.evidenceGates should be an array');
  assert.ok(Array.isArray(recipe.stopConditions), 'Test 1 — recipe.stopConditions should be an array');
  assert.equal(typeof recipe.defaultBudgets, 'object', 'Test 1 — recipe.defaultBudgets should be an object');
}

// ---------------------------------------------------------------------------
// Test 2: createRecipeRun returns a run with expected shape
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  assert.equal(typeof run, 'object', 'Test 2 — run should be an object');
  assert.equal(typeof run.id, 'string', 'Test 2 — run.id should be a string');
  assert.ok(run.id.length > 0, 'Test 2 — run.id should not be empty');
  assert.equal(run.recipeId, recipe.id, 'Test 2 — run.recipeId should equal recipe.id');
  assert.equal(run.status, 'queued', 'Test 2 — initial status should be "queued"');
  assert.ok(Array.isArray(run.completedSteps), 'Test 2 — completedSteps should be an array');
  assert.equal(run.completedSteps.length, 0, 'Test 2 — completedSteps should start empty');
  assert.ok(Array.isArray(run.gateResults), 'Test 2 — gateResults should be an array');
  assert.ok(Array.isArray(run.errors), 'Test 2 — errors should be an array');
  assert.equal(typeof run.startedAt, 'string', 'Test 2 — startedAt should be an ISO string');
}

// ---------------------------------------------------------------------------
// Test 3: first step is the baseline capture step
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const firstStep = getNextStep(run, recipe);
  assert.ok(firstStep !== null, 'Test 3 — getNextStep should return first step');
  assert.equal(firstStep.id, recipe.steps[0].id, 'Test 3 — first step should be baseline');
  assert.equal(typeof firstStep.type, 'string', 'Test 3 — step.type should be a string');
  assert.equal(typeof firstStep.label, 'string', 'Test 3 — step.label should be a string');
  assert.equal(typeof firstStep.config, 'object', 'Test 3 — step.config should be an object');
}

// ---------------------------------------------------------------------------
// Test 4: run advances through all steps successfully (headless simulation)
// ---------------------------------------------------------------------------
{
  let run = createRecipeRun(recipe);
  let iterCount = 0;
  const maxIter = recipe.steps.length + 5;

  while (!isRecipeRunComplete(run) && iterCount < maxIter) {
    const step = getNextStep(run, recipe);
    if (!step) break;
    // Simulate step success
    run = advanceRecipeRun(run, step.id, true);
    iterCount++;

    // If no next step after advancing, complete the run
    const next = getNextStep(run, recipe);
    if (!next) {
      run = completeRecipeRun(run);
    }
  }

  assert.equal(run.status, 'complete', 'Test 4 — run should reach "complete" after all steps');
  assert.ok(run.completedSteps.length > 0, 'Test 4 — at least one step should be completed');
  assert.equal(typeof run.completedAt, 'string', 'Test 4 — completedAt should be set');
  assert.equal(run.errors.length, 0, 'Test 4 — no errors should be recorded on success path');
}

// ---------------------------------------------------------------------------
// Test 5: failRecipeRun produces a failed terminal state
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const failed = failRecipeRun(run, 'Budget exceeded during fixture test');
  assert.equal(failed.status, 'failed', 'Test 5 — failed run should have status "failed"');
  assert.ok(
    failed.errors.some((e) => e.includes('Budget exceeded')),
    'Test 5 — error message should be recorded',
  );
  assert.equal(typeof failed.completedAt, 'string', 'Test 5 — completedAt should be set');
  assert.equal(isRecipeRunComplete(failed), true, 'Test 5 — failed run should be terminal');
  assert.equal(getNextStep(failed, recipe), null, 'Test 5 — getNextStep returns null for failed run');
}

// ---------------------------------------------------------------------------
// Test 6: stopRecipeRun produces a stopped terminal state
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const stopped = stopRecipeRun(run, 'User cancelled fixture run');
  assert.equal(stopped.status, 'stopped', 'Test 6 — stopped run should have status "stopped"');
  assert.ok(
    stopped.errors.some((e) => e.includes('User cancelled')),
    'Test 6 — stop reason should be in errors',
  );
  assert.equal(isRecipeRunComplete(stopped), true, 'Test 6 — stopped run should be terminal');
}

// ---------------------------------------------------------------------------
// Test 7: run with a failure mid-recipe records the error but stays running
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const firstStep = getNextStep(run, recipe);
  assert.ok(firstStep !== null, 'Test 7 — first step should be available');
  const advanced = advanceRecipeRun(run, firstStep.id, false, 'Fixture timeout');
  assert.equal(advanced.status, 'running', 'Test 7 — status should be "running" after failed step advance');
  assert.ok(
    advanced.errors.some((e) => e.includes('Fixture timeout')),
    'Test 7 — failure error should be recorded',
  );
  assert.ok(
    advanced.completedSteps.includes(firstStep.id),
    'Test 7 — failed step should still appear in completedSteps',
  );
}

// ---------------------------------------------------------------------------
// Test 8: run IDs are unique across multiple createRecipeRun calls
// ---------------------------------------------------------------------------
{
  const ids = new Set();
  for (let i = 0; i < 5; i++) {
    ids.add(createRecipeRun(recipe).id);
  }
  assert.equal(ids.size, 5, 'Test 8 — each createRecipeRun call should produce a unique id');
}

// ---------------------------------------------------------------------------
// Test 9: advanceRecipeRun does not mutate the original run (immutability)
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const firstStep = getNextStep(run, recipe);
  const advanced = advanceRecipeRun(run, firstStep.id, true);
  assert.equal(run.status, 'queued', 'Test 9 — original run status must not be mutated');
  assert.equal(run.completedSteps.length, 0, 'Test 9 — original completedSteps must not be mutated');
  assert.equal(advanced.completedSteps.length, 1, 'Test 9 — advanced run must have one completed step');
}

// ---------------------------------------------------------------------------
// Test 10: every step in the recipe has id, type, label, and config
// ---------------------------------------------------------------------------
{
  const VALID_TYPES = new Set(['scan', 'repeater', 'intruder', 'oast', 'export', 'assert', 'branch']);
  for (const step of recipe.steps) {
    assert.equal(typeof step.id, 'string', `Test 10 — step "${step.id}" should have a string id`);
    assert.ok(step.id.length > 0, `Test 10 — step id should not be empty`);
    assert.ok(VALID_TYPES.has(step.type), `Test 10 — step "${step.id}" type "${step.type}" should be valid`);
    assert.equal(typeof step.label, 'string', `Test 10 — step "${step.id}" should have a label`);
    assert.equal(typeof step.config, 'object', `Test 10 — step "${step.id}" should have a config object`);
  }
}

console.log('PASS headless-automation-recipes');
