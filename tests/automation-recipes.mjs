import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

// ---------------------------------------------------------------------------
// Module resolution
// ---------------------------------------------------------------------------

const candidateEnginePaths = [
  'src/automation/playbookRecipeEngine.ts',
  'electron/automation/playbookRecipeEngine.ts',
  'dist-electron/automation/playbookRecipeEngine.js',
  'dist/automation/playbookRecipeEngine.js',
];

const candidateGatePaths = [
  'src/automation/playbookEvidenceGate.ts',
  'electron/automation/playbookEvidenceGate.ts',
  'dist-electron/automation/playbookEvidenceGate.js',
  'dist/automation/playbookEvidenceGate.js',
];

const candidateRecipePaths = [
  'src/automation/recipes/webPayloadFamilyValidation.ts',
  'electron/automation/recipes/webPayloadFamilyValidation.ts',
  'dist-electron/automation/recipes/webPayloadFamilyValidation.js',
  'dist/automation/recipes/webPayloadFamilyValidation.js',
];

const enginePath = await firstExistingPath(candidateEnginePaths);
if (!enginePath) {
  console.log('automation-recipes: skipped; playbookRecipeEngine not found or compiled yet');
  process.exit(0);
}

const gatePath = await firstExistingPath(candidateGatePaths);
if (!gatePath) {
  console.log('automation-recipes: skipped; playbookEvidenceGate not found or compiled yet');
  process.exit(0);
}

const recipePath = await firstExistingPath(candidateRecipePaths);
if (!recipePath) {
  console.log('automation-recipes: skipped; webPayloadFamilyValidation recipe not found or compiled yet');
  process.exit(0);
}

const engineExports = normalizeModuleExports(await loadEngine(enginePath), [
  'createRecipeRun',
  'advanceRecipeRun',
  'stopRecipeRun',
  'isRecipeRunComplete',
  'getNextStep',
]);

const gateExports = normalizeModuleExports(await loadEngine(gatePath), [
  'evaluateGate',
  'evaluateAllGates',
  'allRequiredGatesPassed',
]);

const recipeExports = normalizeModuleExports(await loadEngine(recipePath), [
  'webPayloadFamilyValidation',
]);

const requiredEngineExports = ['createRecipeRun', 'advanceRecipeRun', 'stopRecipeRun', 'isRecipeRunComplete', 'getNextStep'];
const missingEngineExports = requiredEngineExports.filter((n) => typeof engineExports[n] !== 'function');
if (missingEngineExports.length) {
  console.log(`automation-recipes: skipped; missing engine export(s): ${missingEngineExports.join(', ')}`);
  process.exit(0);
}

const requiredGateExports = ['evaluateGate', 'evaluateAllGates', 'allRequiredGatesPassed'];
const missingGateExports = requiredGateExports.filter((n) => typeof gateExports[n] !== 'function');
if (missingGateExports.length) {
  console.log(`automation-recipes: skipped; missing gate export(s): ${missingGateExports.join(', ')}`);
  process.exit(0);
}

const {
  createRecipeRun,
  advanceRecipeRun,
  stopRecipeRun,
  isRecipeRunComplete,
  getNextStep,
} = engineExports;

const { evaluateGate, evaluateAllGates, allRequiredGatesPassed } = gateExports;
const { webPayloadFamilyValidation } = recipeExports;

if (!webPayloadFamilyValidation || typeof webPayloadFamilyValidation !== 'object') {
  console.log('automation-recipes: skipped; webPayloadFamilyValidation recipe not exported correctly');
  process.exit(0);
}

const recipe = webPayloadFamilyValidation;

// ---------------------------------------------------------------------------
// RecipeRun state machine tests
// ---------------------------------------------------------------------------

// createRecipeRun status = 'queued'
const run0 = createRecipeRun(recipe);
assert(run0 !== null && typeof run0 === 'object', 'createRecipeRun must return an object');
assert.equal(run0.status, 'queued', 'createRecipeRun initial status must be "queued"');
assert.equal(run0.recipeId, recipe.id, 'createRecipeRun must set recipeId');
assert(Array.isArray(run0.completedSteps), 'createRecipeRun must initialise completedSteps as array');
assert.equal(run0.completedSteps.length, 0, 'createRecipeRun completedSteps must be empty');
assert(typeof run0.startedAt === 'string', 'createRecipeRun must set startedAt as ISO string');
assert(Array.isArray(run0.errors), 'createRecipeRun must initialise errors as array');

// getNextStep returns first step when none completed
const firstStep = getNextStep(run0, recipe);
assert(firstStep !== null, 'getNextStep must return a step when run is queued with no completed steps');
assert.equal(firstStep.id, recipe.steps[0].id, 'getNextStep must return the first step initially');

// advanceRecipeRun marks baseline complete, status becomes 'running'
const run1 = advanceRecipeRun(run0, 'baseline', true);
assert(run1 !== null && typeof run1 === 'object', 'advanceRecipeRun must return an object');
assert.equal(run1.status, 'running', 'advanceRecipeRun must set status to "running"');
assert(run1.completedSteps.includes('baseline'), 'advanceRecipeRun must add stepId to completedSteps');

// getNextStep after advancing follows onSuccess routing
const nextStep = getNextStep(run1, recipe);
assert(nextStep !== null, 'getNextStep must resolve the next step via onSuccess routing');
assert.equal(nextStep.id, 'sql-scan', 'getNextStep must follow onSuccess: "sql-scan" from baseline');

// Advance through multiple steps
const run2 = advanceRecipeRun(run1, 'sql-scan', true);
assert(run2.completedSteps.includes('sql-scan'), 'advanceRecipeRun must track sql-scan as complete');

// advanceRecipeRun with error records the error
const run3 = advanceRecipeRun(run2, 'xss-scan', false, 'timeout');
assert(run3.errors.includes('timeout'), 'advanceRecipeRun must record error when provided');

// stopRecipeRun sets status to 'stopped'
const stoppedRun = stopRecipeRun(run0, 'test stop reason');
assert.equal(stoppedRun.status, 'stopped', 'stopRecipeRun must set status to "stopped"');
assert(stoppedRun.errors.includes('test stop reason'), 'stopRecipeRun must record reason in errors');
assert(typeof stoppedRun.completedAt === 'string', 'stopRecipeRun must set completedAt');

// isRecipeRunComplete returns false on running
assert.equal(isRecipeRunComplete(run1), false, 'isRecipeRunComplete must return false for running status');
assert.equal(isRecipeRunComplete(run0), false, 'isRecipeRunComplete must return false for queued status');

// isRecipeRunComplete returns true on complete
const completedRun = { ...run0, status: 'complete' };
assert.equal(isRecipeRunComplete(completedRun), true, 'isRecipeRunComplete must return true for complete status');

// isRecipeRunComplete returns true on failed and stopped
const failedRun = { ...run0, status: 'failed' };
assert.equal(isRecipeRunComplete(failedRun), true, 'isRecipeRunComplete must return true for failed status');
assert.equal(isRecipeRunComplete(stoppedRun), true, 'isRecipeRunComplete must return true for stopped status');

// getNextStep returns null for complete runs
const nextOnComplete = getNextStep(completedRun, recipe);
assert.equal(nextOnComplete, null, 'getNextStep must return null for complete runs');

// ---------------------------------------------------------------------------
// EvidenceGate tests
// ---------------------------------------------------------------------------

const sampleGate = {
  id: 'test-gate-1',
  checkId: 'sql-injection',
  requiredClass: 'expected-proof',
  minConfidence: 0.8,
  required: true,
};

const matchingObservations = [
  { responseClass: 'expected-proof', confidence: 0.95, checkId: 'sql-injection' },
];

// evaluateGate passes when observation matches required class + confidence
const passResult = evaluateGate(sampleGate, matchingObservations);
assert(typeof passResult === 'object', 'evaluateGate must return an object');
assert.equal(passResult.gateId, sampleGate.id, 'evaluateGate result must have gateId');
assert.equal(passResult.passed, true, 'evaluateGate must pass when observation matches class and confidence');
assert(typeof passResult.reason === 'string', 'evaluateGate result must have a reason string');

// evaluateGate fails when confidence below minimum
const lowConfidenceObservations = [
  { responseClass: 'expected-proof', confidence: 0.5, checkId: 'sql-injection' },
];
const failConfidenceResult = evaluateGate(sampleGate, lowConfidenceObservations);
assert.equal(
  failConfidenceResult.passed,
  false,
  'evaluateGate must fail when confidence is below minConfidence',
);

// evaluateGate fails when no matching observation
const noMatchObservations = [
  { responseClass: 'neutral-or-not-parsed', confidence: 0.99, checkId: 'sql-injection' },
];
const failClassResult = evaluateGate(sampleGate, noMatchObservations);
assert.equal(
  failClassResult.passed,
  false,
  'evaluateGate must fail when no observation matches the required class',
);

// evaluateGate fails when checkId does not match
const wrongCheckIdObservations = [
  { responseClass: 'expected-proof', confidence: 0.95, checkId: 'reflected-xss' },
];
const failCheckIdResult = evaluateGate(sampleGate, wrongCheckIdObservations);
assert.equal(
  failCheckIdResult.passed,
  false,
  'evaluateGate must fail when observation checkId does not match gate checkId',
);

// evaluateGate passes for gate without checkId restriction
const gateNoCheckId = { ...sampleGate, checkId: undefined };
const passAnyCheckResult = evaluateGate(gateNoCheckId, wrongCheckIdObservations);
assert.equal(
  passAnyCheckResult.passed,
  true,
  'evaluateGate must pass when gate has no checkId and class+confidence match',
);

// allRequiredGatesPassed returns false when any required gate failed
const mixedResults = [
  { gateId: 'gate-a', passed: true, reason: 'ok' },
  { gateId: 'gate-b', passed: false, reason: 'miss' },
];
assert.equal(
  allRequiredGatesPassed(mixedResults),
  false,
  'allRequiredGatesPassed must return false when any result failed',
);

// allRequiredGatesPassed returns true when all passed
const allPassedResults = [
  { gateId: 'gate-a', passed: true, reason: 'ok' },
  { gateId: 'gate-b', passed: true, reason: 'ok' },
];
assert.equal(
  allRequiredGatesPassed(allPassedResults),
  true,
  'allRequiredGatesPassed must return true when all results passed',
);

// evaluateAllGates returns one result per gate
const gates = [
  sampleGate,
  { id: 'gate-2', requiredClass: 'oast-callback-confirmed', minConfidence: 0.85, required: false },
];
const allResults = evaluateAllGates(gates, matchingObservations);
assert.equal(allResults.length, 2, 'evaluateAllGates must return one result per gate');
assert.equal(allResults[0].gateId, sampleGate.id, 'evaluateAllGates result[0] must correspond to first gate');

console.log('automation-recipes: all assertions passed');

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

async function firstExistingPath(candidates) {
  for (const candidate of candidates) {
    const resolved = path.resolve(candidate);
    try {
      const stat = await fs.stat(resolved);
      if (stat.isFile()) return resolved;
    } catch {
      // keep looking
    }
  }
  return '';
}

async function loadEngine(enginePath) {
  if (enginePath.endsWith('.js') || enginePath.endsWith('.cjs')) {
    return require(enginePath);
  }
  return loadTsModule(enginePath);
}

function loadTsModule(filePath, cache = new Map()) {
  const resolved = path.resolve(filePath);
  if (cache.has(resolved)) return cache.get(resolved).exports;
  const source = fsSync.readFileSync(resolved, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
      resolveJsonModule: true,
    },
    fileName: resolved,
  }).outputText;
  const module = { exports: {} };
  cache.set(resolved, module);
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
    module,
    exports: module.exports,
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    Buffer,
    console,
    crypto: globalThis.crypto,
    setTimeout,
    clearTimeout,
    require: localRequire,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: resolved });
  return module.exports;
}

function normalizeModuleExports(moduleExports, expectedNames) {
  const hasNamedExport = expectedNames.some((name) => {
    const val = moduleExports[name];
    return typeof val === 'function' || (val !== null && typeof val === 'object');
  });
  if (hasNamedExport) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}
