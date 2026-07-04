/**
 * Phase 18.11 — Feature Matrix lint
 *
 * Validates the FEATURE_MATRIX.md document for structural consistency:
 *   1. Every table row has exactly 3 columns (Feature | Status | Test).
 *   2. Status values are one of the known set.
 *   3. Non-empty test references start with "tests/".
 *   4. The document has at least 5 phase sections.
 *   5. The document has a Gates Status section.
 */
import { strict as assert } from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';

const matrixPath = path.resolve('docs/FEATURE_MATRIX.md');

let content;
try {
  content = await fs.readFile(matrixPath, 'utf8');
} catch (err) {
  console.error(`Could not read ${matrixPath}: ${err.message}`);
  process.exit(1);
}

const VALID_STATUSES = new Set([
  'Backend',
  'GUI-integrated',
  'E2E-tested',
  'Beta',
  'Production',
  // Gates Status table uses different terms — allow those too
  'In progress',
  'Not started',
  'Complete',
  'Done',
]);

const lines = content.split('\n');

// ---------------------------------------------------------------------------
// Collect all Markdown table rows (lines that start and end with |)
// Skip separator lines (e.g., |---|---|---|)
// ---------------------------------------------------------------------------
const tableRows = [];
for (let i = 0; i < lines.length; i++) {
  const line = lines[i].trim();
  if (!line.startsWith('|') || !line.endsWith('|')) continue;
  // Skip separator rows
  if (/^\|[-|: ]+\|$/.test(line)) continue;
  // Skip header rows (lines that define column names)
  if (/\|\s*(Feature|Gate)\s*\|/.test(line)) continue;
  tableRows.push({ lineNumber: i + 1, line });
}

// ---------------------------------------------------------------------------
// Check 1: Every table row has exactly 3 columns
// ---------------------------------------------------------------------------
const columnErrors = [];
for (const { lineNumber, line } of tableRows) {
  // Split by | and filter empty strings from leading/trailing pipes
  const cells = line.split('|').map((c) => c.trim()).filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
  if (cells.length !== 3) {
    columnErrors.push(`Line ${lineNumber}: expected 3 columns, got ${cells.length}: ${line}`);
  }
}
assert.equal(columnErrors.length, 0, `Table rows with wrong column count:\n${columnErrors.join('\n')}`);
console.log(`  Column count OK on ${tableRows.length} table rows`);

// ---------------------------------------------------------------------------
// Check 2: Status values are from the known set (skip Gates table rows with Criteria column)
// ---------------------------------------------------------------------------
const statusErrors = [];
for (const { lineNumber, line } of tableRows) {
  const cells = line.split('|').map((c) => c.trim()).filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
  if (cells.length !== 3) continue; // already caught above
  const status = cells[1];
  // Skip the Gates Status table — it uses "Status" differently (e.g., "In progress")
  // and Criteria column as third column. Allow known statuses + gate statuses.
  if (!VALID_STATUSES.has(status)) {
    statusErrors.push(`Line ${lineNumber}: unknown Status "${status}" in: ${line}`);
  }
}
assert.equal(statusErrors.length, 0, `Rows with invalid Status values:\n${statusErrors.join('\n')}`);
console.log(`  Status values OK`);

// ---------------------------------------------------------------------------
// Check 3: Test references (3rd column) look like valid paths or are "—"
// ---------------------------------------------------------------------------
const testRefErrors = [];
for (const { lineNumber, line } of tableRows) {
  const cells = line.split('|').map((c) => c.trim()).filter((_, idx, arr) => idx > 0 && idx < arr.length - 1);
  if (cells.length !== 3) continue;
  const testCol = cells[2];
  // Skip dash placeholder and Gates Status criteria column
  if (testCol === '—' || testCol === '-' || testCol === '') continue;
  // Skip criteria text (Gates rows) — criteria don't start with "tests/"
  // but they also don't contain comma-separated test paths
  // Split by comma to handle multiple test references on one row
  const refs = testCol.split(',').map((r) => r.trim()).filter(Boolean);
  for (const ref of refs) {
    if (!ref.startsWith('tests/')) {
      // Allow criteria-like text (gates rows contain plain text descriptions)
      // Only flag if it looks like it should be a test path (contains .mjs)
      if (ref.includes('.mjs') && !ref.startsWith('tests/')) {
        testRefErrors.push(`Line ${lineNumber}: test reference "${ref}" should start with "tests/"`);
      }
    }
  }
}
assert.equal(testRefErrors.length, 0, `Invalid test references:\n${testRefErrors.join('\n')}`);
console.log(`  Test references OK`);

// ---------------------------------------------------------------------------
// Check 4: Document has at least 5 phase sections
// ---------------------------------------------------------------------------
const phaseSections = lines.filter((line) => /^## Phase \d+/.test(line.trim()));
assert.ok(
  phaseSections.length >= 5,
  `Expected at least 5 phase sections, found ${phaseSections.length}: ${phaseSections.join(', ')}`,
);
console.log(`  Phase sections OK: ${phaseSections.length} phase(s) found`);

// ---------------------------------------------------------------------------
// Check 5: Document has a Gates Status section
// ---------------------------------------------------------------------------
const hasGatesSection = lines.some((line) => /gates?\s+status/i.test(line));
assert.ok(hasGatesSection, 'Document should contain a "Gates Status" section');
console.log(`  Gates Status section found`);

const staleGateRows = tableRows
  .map(({ line }) => line)
  .filter((line) => /^\|\s*G\d+\s+/.test(line))
  .filter((line) => /\|\s*(In progress|Not started)\s*\|/i.test(line));
assert.deepEqual(staleGateRows, [], `Gate rows must not remain stale:\n${staleGateRows.join('\n')}`);
console.log('  Gate completion statuses OK');

console.log('PASS feature-matrix-lint');
