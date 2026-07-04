import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import fsSync from 'node:fs';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const candidateMapperPaths = [
  'src/scanner/skillletMapper.ts',
  'electron/scanner/skillletMapper.ts',
  'dist-electron/src/scanner/skillletMapper.js',
  'dist/scanner/skillletMapper.js',
];

const mapperPath = await firstExistingPath(candidateMapperPaths);
if (!mapperPath) {
  console.log('scanner-skilllet-metadata: skipped; src/scanner/skillletMapper.ts not found or compiled yet');
  process.exit(0);
}

const importedMapper = await loadEngine(mapperPath);
const mapper = normalizeModuleExports(importedMapper, [
  'loadSkilllets',
  'getSkilllet',
  'getSkillletsByFamily',
  'getAllCheckIds',
  'validateSkillletCompleteness',
]);

const expectedExports = [
  'loadSkilllets',
  'getSkilllet',
  'getSkillletsByFamily',
  'getAllCheckIds',
  'validateSkillletCompleteness',
];
const missingExports = expectedExports.filter((name) => typeof mapper[name] !== 'function');
if (missingExports.length) {
  console.log(`scanner-skilllet-metadata: skipped; missing export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

// --- Tests ---

// loadSkilllets() returns >= 15 entries
const skilllets = mapper.loadSkilllets();
assert(Array.isArray(skilllets), 'loadSkilllets() must return an array');
assert(
  skilllets.length >= 15,
  `loadSkilllets() must return at least 15 entries, got ${skilllets.length}`,
);

// getSkilllet('sql-injection') returns correct metadata
const sqlSkilllet = mapper.getSkilllet('sql-injection');
assert(sqlSkilllet !== null, 'getSkilllet("sql-injection") must return a skilllet');
assert.equal(sqlSkilllet.id, 'sql-injection', 'sql-injection skilllet id should be "sql-injection"');
assert.equal(
  sqlSkilllet.family,
  'sql-injection',
  'sql-injection skilllet family should be "sql-injection"',
);
assert(
  sqlSkilllet.surfaceTypes.includes('query'),
  'sql-injection skilllet should include "query" in surfaceTypes',
);
assert(
  sqlSkilllet.surfaceTypes.includes('body'),
  'sql-injection skilllet should include "body" in surfaceTypes',
);

// Every skilllet has non-empty expectedProof array
for (const s of skilllets) {
  assert(
    Array.isArray(s.expectedProof) && s.expectedProof.length > 0,
    `Skilllet "${s.id}" must have a non-empty expectedProof array`,
  );
}

// Every skilllet has non-empty operatorGuidance array
for (const s of skilllets) {
  assert(
    Array.isArray(s.operatorGuidance) && s.operatorGuidance.length > 0,
    `Skilllet "${s.id}" must have a non-empty operatorGuidance array`,
  );
}

// getSkillletsByFamily('sql-injection') returns the SQL entry
const sqlFamily = mapper.getSkillletsByFamily('sql-injection');
assert(Array.isArray(sqlFamily), 'getSkillletsByFamily must return an array');
assert(sqlFamily.length >= 1, 'getSkillletsByFamily("sql-injection") must return at least one entry');
assert(
  sqlFamily.some((s) => s.id === 'sql-injection'),
  'getSkillletsByFamily("sql-injection") must include the sql-injection skilllet',
);

// getAllCheckIds() returns string array with expected IDs
const allIds = mapper.getAllCheckIds();
assert(Array.isArray(allIds), 'getAllCheckIds() must return an array');
assert(allIds.length >= 15, `getAllCheckIds() must return at least 15 IDs, got ${allIds.length}`);
assert(allIds.includes('sql-injection'), 'getAllCheckIds() must include "sql-injection"');
assert(allIds.includes('reflected-xss'), 'getAllCheckIds() must include "reflected-xss"');
assert(allIds.includes('ssrf'), 'getAllCheckIds() must include "ssrf"');

// validateSkillletCompleteness returns [] for a valid skilllet
const validSkilllet = {
  id: 'test-check',
  checkIds: ['test-check'],
  family: 'sql-injection',
  surfaceTypes: ['query'],
  triggerFacts: ['Error observed'],
  summary: 'A test skilllet.',
  operatorGuidance: ['Do thing one', 'Do thing two'],
  allowedFollowups: [],
  forbiddenBranches: [],
  expectedProof: ['Error in response'],
  defaultRisk: 'low',
};
const validErrors = mapper.validateSkillletCompleteness(validSkilllet);
assert(Array.isArray(validErrors), 'validateSkillletCompleteness must return an array');
assert.equal(
  validErrors.length,
  0,
  `validateSkillletCompleteness should return no errors for a valid skilllet, got: ${JSON.stringify(validErrors)}`,
);

// validateSkillletCompleteness returns errors for skilllet missing expectedProof
const invalidSkilllet = {
  ...validSkilllet,
  expectedProof: [],
};
const invalidErrors = mapper.validateSkillletCompleteness(invalidSkilllet);
assert(Array.isArray(invalidErrors), 'validateSkillletCompleteness must return an array');
assert(
  invalidErrors.length > 0,
  'validateSkillletCompleteness should return errors for a skilllet with empty expectedProof',
);
assert(
  invalidErrors.some((e) => /expectedProof/i.test(e)),
  `validateSkillletCompleteness errors should mention expectedProof, got: ${JSON.stringify(invalidErrors)}`,
);

// validateSkillletCompleteness returns errors for skilllet missing id
const missingIdSkilllet = {
  ...validSkilllet,
  id: '',
};
const missingIdErrors = mapper.validateSkillletCompleteness(missingIdSkilllet);
assert(
  missingIdErrors.length > 0,
  'validateSkillletCompleteness should return errors for a skilllet with empty id',
);

console.log(
  `scanner-skilllet-metadata: all assertions passed (${skilllets.length} skilllets loaded)`,
);

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
      // Try .json extension first for data imports
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
