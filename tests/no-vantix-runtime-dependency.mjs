// Phase 0.3 — CI guard: zero runtime imports of vendored source material.
import { strict as assert } from 'node:assert';
import { execSync } from 'node:child_process';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');

// Search for any import/require of source-reference paths in runtime code.
let output = '';
try {
  output = execSync(
    `grep -rn "source-reference/vantix" "${root}/src" "${root}/electron" "${root}/scripts" "${root}/package.json" "${root}/package-lock.json"`,
    { encoding: 'utf8' },
  );
} catch (err) {
  // grep exits 1 when no matches found — that is the success case.
  output = (err && typeof err === 'object' && 'stdout' in err) ? String(err.stdout) : '';
}

// Strip provenance comment lines (// Adapted from source-reference/vantix/...)
const runtimeMatches = output
  .split('\n')
  .filter((line) => line.trim())
  .filter((line) => !/^\s*(\/\/|#)\s*Adapted from source-reference/.test(line.split(':').slice(2).join(':')));

assert.equal(
  runtimeMatches.length,
  0,
  `Runtime code must not import vendored source material. Found ${runtimeMatches.length} match(es):\n${runtimeMatches.join('\n')}`,
);

console.log('PASS no-vantix-runtime-dependency — zero runtime source-reference matches');
