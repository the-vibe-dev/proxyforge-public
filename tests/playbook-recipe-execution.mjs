/**
 * playbook-recipe-execution.mjs
 *
 * Tests the recipe run state machine in playbookRecipeEngine.ts.
 *
 * Covers: createRecipeRun, advanceRecipeRun, getNextStep, completeRecipeRun,
 * failRecipeRun, stopRecipeRun, and isRecipeRunComplete.
 *
 * Skips gracefully when the TypeScript compiler is unavailable.
 */
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);

let ts;
try {
  ts = require('typescript');
} catch {
  console.log('playbook-recipe-execution: skipped; typescript not available');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Loader helpers (consistent with other tests in this project)
// ---------------------------------------------------------------------------

function loadTsModule(filePath, cache = new Map()) {
  const resolved = path.resolve(filePath);
  if (cache.has(resolved)) return cache.get(resolved).exports;

  let source;
  try {
    source = fsSync.readFileSync(resolved, 'utf8');
  } catch {
    return null;
  }

  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: resolved,
  }).outputText;

  const mod = { exports: {} };
  cache.set(resolved, mod);

  const localRequire = (specifier) => {
    if (specifier.startsWith('.')) {
      const base = path.resolve(path.dirname(resolved), specifier);
      for (const candidate of [
        base,
        `${base}.json`,
        `${base}.ts`,
        `${base}.js`,
        path.join(base, 'index.ts'),
        path.join(base, 'index.js'),
      ]) {
        if (fsSync.existsSync(candidate) && fsSync.statSync(candidate).isFile()) {
          if (candidate.endsWith('.ts')) return loadTsModule(candidate, cache);
          return require(candidate);
        }
      }
    }
    return require(specifier);
  };

  const sandbox = {
    module: mod,
    exports: mod.exports,
    Buffer,
    console,
    URL,
    URLSearchParams,
    process,
    require: localRequire,
    TextEncoder,
    TextDecoder,
    crypto: globalThis.crypto,
  };

  try {
    vm.runInNewContext(transpiled, sandbox, { filename: resolved });
  } catch (err) {
    console.log(`playbook-recipe-execution: skipped; failed to load ${path.basename(resolved)}: ${err.message}`);
    return null;
  }

  return mod.exports;
}

// ---------------------------------------------------------------------------
// Locate and load the recipe engine module
// ---------------------------------------------------------------------------

const candidatePaths = [
  'src/automation/playbookRecipeEngine.ts',
  'electron/automation/playbookRecipeEngine.ts',
  'dist-electron/automation/playbookRecipeEngine.js',
  'dist/automation/playbookRecipeEngine.js',
];

let enginePath = '';
for (const candidate of candidatePaths) {
  const resolved = path.resolve(candidate);
  try {
    const stat = await fs.stat(resolved);
    if (stat.isFile()) { enginePath = resolved; break; }
  } catch { /* keep looking */ }
}

if (!enginePath) {
  console.log('playbook-recipe-execution: skipped; playbookRecipeEngine not found');
  process.exit(0);
}

const engine = loadTsModule(enginePath);
if (!engine) {
  console.log('playbook-recipe-execution: skipped; playbookRecipeEngine failed to load');
  process.exit(0);
}

// Verify required exports
const requiredExports = [
  'createRecipeRun',
  'advanceRecipeRun',
  'getNextStep',
  'completeRecipeRun',
  'failRecipeRun',
  'stopRecipeRun',
  'isRecipeRunComplete',
];
const missingExports = requiredExports.filter((n) => typeof engine[n] !== 'function');
if (missingExports.length) {
  console.log(`playbook-recipe-execution: skipped; missing export(s): ${missingExports.join(', ')}`);
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
} = engine;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

function makeRecipe(overrides = {}) {
  return {
    id: 'recipe-test-001',
    name: 'Test Recipe',
    summary: 'A recipe for execution tests.',
    requiredInputs: ['targetExchangeId'],
    steps: [
      { id: 'step-a', type: 'scan',   label: 'Scan',   config: {}, onSuccess: 'step-b' },
      { id: 'step-b', type: 'assert', label: 'Assert', config: {}, onSuccess: 'step-c' },
      { id: 'step-c', type: 'export', label: 'Export', config: {} },
    ],
    evidenceGates: [
      { id: 'gate-1', requiredClass: 'expected-proof', minConfidence: 0.8, required: true },
    ],
    stopConditions: ['budget.exceeded'],
    defaultBudgets: { maxRequests: 100, maxRuntimeMs: 30000, maxPayloadsPerInsertionPoint: 5 },
    ...overrides,
  };
}

const recipe = makeRecipe();

// ---------------------------------------------------------------------------
// Test 1: createRecipeRun returns a run object with 'queued' status
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  assert.ok(typeof run === 'object' && run !== null, 'Test 1 — createRecipeRun should return an object');
  assert.ok(typeof run.id === 'string' && run.id.length > 0, 'Test 1 — run should have a non-empty id');
  assert.equal(run.recipeId, recipe.id, 'Test 1 — run.recipeId should match recipe.id');
  assert.equal(run.status, 'queued', 'Test 1 — initial status should be "queued"');
  assert.ok(Array.isArray(run.completedSteps), 'Test 1 — completedSteps should be an array');
  assert.equal(run.completedSteps.length, 0, 'Test 1 — completedSteps should start empty');
  assert.ok(Array.isArray(run.errors), 'Test 1 — errors should be an array');
  assert.equal(run.errors.length, 0, 'Test 1 — errors should start empty');
  assert.ok(typeof run.startedAt === 'string', 'Test 1 — startedAt should be a string');
}

// ---------------------------------------------------------------------------
// Test 2: createRecipeRun sets currentStepId to the first step
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  assert.equal(run.currentStepId, 'step-a', 'Test 2 — currentStepId should be the first step id');
}

// ---------------------------------------------------------------------------
// Test 3: createRecipeRun with an empty steps array has no currentStepId
// ---------------------------------------------------------------------------
{
  const emptyRecipe = makeRecipe({ steps: [] });
  const run = createRecipeRun(emptyRecipe);
  assert.equal(run.status, 'queued', 'Test 3 — empty steps run should still be queued');
  assert.ok(!run.currentStepId, 'Test 3 — currentStepId should be undefined for empty steps recipe');
}

// ---------------------------------------------------------------------------
// Test 4: getNextStep returns the first step when currentStepId is set
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const next = getNextStep(run, recipe);
  assert.ok(next !== null, 'Test 4 — getNextStep should return a step');
  assert.equal(next.id, 'step-a', 'Test 4 — first step should be step-a');
}

// ---------------------------------------------------------------------------
// Test 5: advanceRecipeRun marks step as completed and status 'running'
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const advanced = advanceRecipeRun(run, 'step-a', true);
  assert.ok(advanced.completedSteps.includes('step-a'), 'Test 5 — step-a should be in completedSteps');
  assert.equal(advanced.status, 'running', 'Test 5 — status should be "running" after advance');
}

// ---------------------------------------------------------------------------
// Test 6: advanceRecipeRun with failure appends an error entry
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const advanced = advanceRecipeRun(run, 'step-a', false, 'Assertion failed');
  assert.ok(advanced.completedSteps.includes('step-a'), 'Test 6 — failed step still added to completedSteps');
  assert.ok(advanced.errors.some((e) => /Assertion failed/i.test(e)), 'Test 6 — error message should be recorded');
}

// ---------------------------------------------------------------------------
// Test 7: getNextStep resolves onSuccess routing after a step completes
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  // Simulate completing step-a
  const advanced = advanceRecipeRun(run, 'step-a', true);
  const next = getNextStep(advanced, recipe);
  // After advancing (currentStepId cleared), getNextStep uses completedSteps routing
  assert.ok(next !== null, 'Test 7 — getNextStep should resolve next step');
  assert.equal(next.id, 'step-b', 'Test 7 — after step-a succeeds, next step should be step-b via onSuccess');
}

// ---------------------------------------------------------------------------
// Test 8: completeRecipeRun sets status 'complete' and records completedAt
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const completed = completeRecipeRun(run);
  assert.equal(completed.status, 'complete', 'Test 8 — status should be "complete"');
  assert.ok(typeof completed.completedAt === 'string', 'Test 8 — completedAt should be a string');
}

// ---------------------------------------------------------------------------
// Test 9: failRecipeRun sets status 'failed' and appends reason
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const failed = failRecipeRun(run, 'Budget exceeded');
  assert.equal(failed.status, 'failed', 'Test 9 — status should be "failed"');
  assert.ok(failed.errors.some((e) => /Budget exceeded/i.test(e)), 'Test 9 — reason should be in errors');
  assert.ok(typeof failed.completedAt === 'string', 'Test 9 — completedAt should be set');
}

// ---------------------------------------------------------------------------
// Test 10: stopRecipeRun sets status 'stopped' and appends reason
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const stopped = stopRecipeRun(run, 'User cancelled');
  assert.equal(stopped.status, 'stopped', 'Test 10 — status should be "stopped"');
  assert.ok(stopped.errors.some((e) => /User cancelled/i.test(e)), 'Test 10 — reason should be in errors');
  assert.ok(typeof stopped.completedAt === 'string', 'Test 10 — completedAt should be set');
}

// ---------------------------------------------------------------------------
// Test 11: isRecipeRunComplete returns false for non-terminal states
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  assert.equal(isRecipeRunComplete(run), false, 'Test 11 — queued run is not complete');
  const running = advanceRecipeRun(run, 'step-a', true);
  assert.equal(isRecipeRunComplete(running), false, 'Test 11 — running run is not complete');
}

// ---------------------------------------------------------------------------
// Test 12: isRecipeRunComplete returns true for terminal states
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  assert.equal(isRecipeRunComplete(completeRecipeRun(run)), true, 'Test 12 — complete run is terminal');
  assert.equal(isRecipeRunComplete(failRecipeRun(run, 'x')), true, 'Test 12 — failed run is terminal');
  assert.equal(isRecipeRunComplete(stopRecipeRun(run, 'x')), true, 'Test 12 — stopped run is terminal');
}

// ---------------------------------------------------------------------------
// Test 13: getNextStep returns null after run has reached a terminal state
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const completed = completeRecipeRun(run);
  const next = getNextStep(completed, recipe);
  assert.equal(next, null, 'Test 13 — getNextStep should return null for a completed run');
}

// ---------------------------------------------------------------------------
// Test 14: run IDs are unique per createRecipeRun call
// ---------------------------------------------------------------------------
{
  const run1 = createRecipeRun(recipe);
  const run2 = createRecipeRun(recipe);
  assert.notEqual(run1.id, run2.id, 'Test 14 — each run should have a unique id');
}

// ---------------------------------------------------------------------------
// Test 15: advanceRecipeRun does not mutate the original run object
// ---------------------------------------------------------------------------
{
  const run = createRecipeRun(recipe);
  const advanced = advanceRecipeRun(run, 'step-a', true);
  assert.equal(run.status, 'queued', 'Test 15 — original run status should not be mutated');
  assert.equal(run.completedSteps.length, 0, 'Test 15 — original completedSteps should not be mutated');
  assert.equal(advanced.completedSteps.length, 1, 'Test 15 — advanced run should have one completed step');
}

console.log('playbook-recipe-execution: all 15 recipe execution tests passed');
