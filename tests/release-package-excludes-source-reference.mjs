// Phase 0.4 — Confirms package.json build.files allowlist does not ship source-reference/.
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const pkg = JSON.parse(readFileSync(path.resolve(import.meta.dirname, '../package.json'), 'utf8'));

const buildFiles = pkg?.build?.files ?? [];
const includesSourceRef = buildFiles.some(
  (entry) => typeof entry === 'string' && (
    entry.includes('source-reference') && !entry.startsWith('!')
  ),
);

assert.equal(
  includesSourceRef,
  false,
  `package.json#build.files must not positively include source-reference/. Current files: ${JSON.stringify(buildFiles)}`,
);

// Verify there is either an explicit exclusion or the directory is simply absent from the list.
const hasExclusion = buildFiles.some(
  (entry) => typeof entry === 'string' && entry.startsWith('!') && entry.includes('source-reference'),
);
const hasImplicitExclusion = !buildFiles.some(
  (entry) => typeof entry === 'string' && entry === '**/*',
);

assert.ok(
  hasExclusion || hasImplicitExclusion || buildFiles.length === 0,
  `Expected explicit exclusion or absence of source-reference from build.files. files: ${JSON.stringify(buildFiles)}`,
);

console.log('PASS release-package-excludes-source-reference — build.files does not ship vendored source');
