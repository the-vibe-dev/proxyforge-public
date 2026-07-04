import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const candidateSchemaPaths = [
  'src/automation/playbookSchema.ts',
  'electron/automation/playbookSchema.ts',
  'dist-electron/automation/playbookSchema.js',
  'dist/automation/playbookSchema.js',
];

const schemaPath = await firstExistingPath(candidateSchemaPaths);
if (!schemaPath) {
  console.log('playbook-recipe-parser: skipped; playbookSchema not found or compiled yet');
  process.exit(0);
}

const schemaExports = normalizeModuleExports(await loadEngine(schemaPath), [
  'validateRecipe',
  'parseRecipeJson',
  'serializeRecipe',
]);

const expectedSchemaExports = ['validateRecipe', 'parseRecipeJson', 'serializeRecipe'];
const missingSchemaExports = expectedSchemaExports.filter(
  (n) => typeof schemaExports[n] !== 'function',
);
if (missingSchemaExports.length) {
  console.log(`playbook-recipe-parser: skipped; missing export(s): ${missingSchemaExports.join(', ')}`);
  process.exit(0);
}

const { validateRecipe, parseRecipeJson, serializeRecipe } = schemaExports;

// ---------------------------------------------------------------------------
// Well-formed recipe fixture
// ---------------------------------------------------------------------------

const wellFormedRecipe = {
  id: 'test-recipe-001',
  name: 'Test Recipe',
  summary: 'A well-formed recipe for parser tests.',
  requiredInputs: ['targetExchangeId'],
  steps: [
    {
      id: 'step-one',
      type: 'scan',
      label: 'Run first scan',
      config: { checkIds: ['sql-injection'] },
      onSuccess: 'step-two',
    },
    {
      id: 'step-two',
      type: 'export',
      label: 'Export results',
      config: { format: 'bundle' },
    },
  ],
  evidenceGates: [
    {
      id: 'gate-one',
      requiredClass: 'expected-proof',
      minConfidence: 0.8,
      required: true,
    },
  ],
  stopConditions: ['budget.exceeded'],
  defaultBudgets: {
    maxRequests: 200,
    maxRuntimeMs: 60000,
    maxPayloadsPerInsertionPoint: 10,
  },
};

// ---------------------------------------------------------------------------
// validateRecipe tests
// ---------------------------------------------------------------------------

// validateRecipe returns valid: true for a well-formed recipe object
const wellFormedResult = validateRecipe(wellFormedRecipe);
assert(typeof wellFormedResult === 'object', 'validateRecipe must return an object');
assert(typeof wellFormedResult.valid === 'boolean', 'validateRecipe result must have a boolean "valid" field');
assert(Array.isArray(wellFormedResult.errors), 'validateRecipe result must have an "errors" array');
assert.equal(
  wellFormedResult.valid,
  true,
  `validateRecipe must return valid:true for a well-formed recipe, errors: ${JSON.stringify(wellFormedResult.errors)}`,
);
assert.equal(
  wellFormedResult.errors.length,
  0,
  `validateRecipe must return empty errors for a well-formed recipe, got: ${JSON.stringify(wellFormedResult.errors)}`,
);

// validateRecipe returns errors for missing id
const missingIdResult = validateRecipe({ ...wellFormedRecipe, id: '' });
assert.equal(missingIdResult.valid, false, 'validateRecipe must return valid:false when id is empty');
assert(missingIdResult.errors.length > 0, 'validateRecipe must return errors when id is empty');
assert(
  missingIdResult.errors.some((e) => /\bid\b/i.test(e)),
  `validateRecipe errors should mention "id", got: ${JSON.stringify(missingIdResult.errors)}`,
);

// validateRecipe returns errors for missing name
const missingNameResult = validateRecipe({ ...wellFormedRecipe, name: '' });
assert.equal(missingNameResult.valid, false, 'validateRecipe must return valid:false when name is empty');
assert(
  missingNameResult.errors.some((e) => /\bname\b/i.test(e)),
  `validateRecipe errors should mention "name", got: ${JSON.stringify(missingNameResult.errors)}`,
);

// validateRecipe returns errors for missing steps
const missingStepsResult = validateRecipe({ ...wellFormedRecipe, steps: [] });
assert.equal(missingStepsResult.valid, false, 'validateRecipe must return valid:false when steps is empty');
assert(
  missingStepsResult.errors.some((e) => /step/i.test(e)),
  `validateRecipe errors should mention "steps", got: ${JSON.stringify(missingStepsResult.errors)}`,
);

// validateRecipe returns errors for non-array steps
const nonArrayStepsResult = validateRecipe({ ...wellFormedRecipe, steps: 'not-an-array' });
assert.equal(nonArrayStepsResult.valid, false, 'validateRecipe must reject non-array steps');

// validateRecipe returns errors for invalid step type
const badStepTypeResult = validateRecipe({
  ...wellFormedRecipe,
  steps: [{ ...wellFormedRecipe.steps[0], type: 'invalid-type' }],
});
assert.equal(badStepTypeResult.valid, false, 'validateRecipe must reject invalid step type');

// validateRecipe returns errors for null input
const nullResult = validateRecipe(null);
assert.equal(nullResult.valid, false, 'validateRecipe must return valid:false for null input');

// validateRecipe returns errors for missing defaultBudgets
const missingBudgetsResult = validateRecipe({ ...wellFormedRecipe, defaultBudgets: undefined });
assert.equal(missingBudgetsResult.valid, false, 'validateRecipe must return valid:false when defaultBudgets is missing');

// ---------------------------------------------------------------------------
// parseRecipeJson / serializeRecipe round-trip tests
// ---------------------------------------------------------------------------

// parseRecipeJson round-trips through serializeRecipe
const serialized = serializeRecipe(wellFormedRecipe);
assert(typeof serialized === 'string', 'serializeRecipe must return a string');
const parsed = parseRecipeJson(serialized);
assert(typeof parsed === 'object' && parsed !== null, 'parseRecipeJson must return an object');
assert.equal(parsed.id, wellFormedRecipe.id, 'Round-tripped recipe id must match');
assert.equal(parsed.name, wellFormedRecipe.name, 'Round-tripped recipe name must match');
assert.equal(parsed.steps.length, wellFormedRecipe.steps.length, 'Round-tripped recipe steps length must match');
assert.equal(
  parsed.steps[0].id,
  wellFormedRecipe.steps[0].id,
  'Round-tripped recipe step[0].id must match',
);

// Re-serializing the parsed result produces identical JSON
const reSerialized = serializeRecipe(parsed);
assert.equal(reSerialized, serialized, 'serializeRecipe output must be stable across round-trips');

// parseRecipeJson throws on invalid JSON
{
  let threw = false;
  let thrownMsg = '';
  try {
    parseRecipeJson('not valid json {{{{');
  } catch (err) {
    threw = true;
    thrownMsg = err && err.message ? String(err.message) : String(err);
  }
  assert.equal(threw, true, 'parseRecipeJson must throw on invalid JSON input');
  assert(
    /JSON|json|parse/i.test(thrownMsg),
    `parseRecipeJson error message must mention JSON, got: ${thrownMsg}`,
  );
}

// parseRecipeJson throws on valid JSON that fails validation
{
  let threw = false;
  try {
    parseRecipeJson(JSON.stringify({ id: '', steps: [] }));
  } catch {
    threw = true;
  }
  assert.equal(threw, true, 'parseRecipeJson must throw when the parsed object fails validateRecipe');
}

// serializeRecipe produces valid JSON
const jsonString = serializeRecipe(wellFormedRecipe);
let parsedJson;
try {
  parsedJson = JSON.parse(jsonString);
} catch {
  assert.fail('serializeRecipe must produce valid JSON');
}
assert.equal(parsedJson.id, wellFormedRecipe.id, 'serializeRecipe JSON must contain the correct id');

console.log('playbook-recipe-parser: all assertions passed');

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
  const hasNamedExport = expectedNames.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedExport) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}
