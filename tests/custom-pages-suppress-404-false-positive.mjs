// Tests: a custom 'not-found' page declaration suppresses passive false positives.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let customPagesModule;
try {
  customPagesModule = require('../dist-electron/customPages.js');
} catch {
  console.log('custom-pages-suppress-404-false-positive: skipped — customPages not compiled yet');
  process.exit(0);
}

const { addCustomPage, getCustomPageClass, suppressFalsePositive, removeCustomPage } =
  customPagesModule;

if (typeof addCustomPage !== 'function') {
  console.log('custom-pages-suppress-404-false-positive: skipped — missing exports');
  process.exit(0);
}

const CONTEXT_ID = 'ctx-test-001';

// ---------------------------------------------------------------------------
// Test 1: addCustomPage creates a record with an id
// ---------------------------------------------------------------------------
{
  const pages = [];
  const page = addCustomPage(
    { contextId: CONTEXT_ID, pattern: 'https://app.example.com/missing*', class: 'not-found' },
    pages,
  );

  assert.ok(typeof page.id === 'string' && page.id.length > 0, 'page must have an id');
  assert.strictEqual(page.contextId, CONTEXT_ID);
  assert.strictEqual(page.class, 'not-found');
  assert.strictEqual(pages.length, 1, 'page must be added to the collection');
  console.log('PASS: addCustomPage creates a record and appends to collection');
}

// ---------------------------------------------------------------------------
// Test 2: getCustomPageClass returns 'not-found' for matching URL
// ---------------------------------------------------------------------------
{
  const pages = [];
  addCustomPage(
    { contextId: CONTEXT_ID, pattern: 'https://app.example.com/missing*', class: 'not-found' },
    pages,
  );

  const cls = getCustomPageClass('https://app.example.com/missing/page', CONTEXT_ID, pages);
  assert.strictEqual(cls, 'not-found');
  console.log('PASS: getCustomPageClass returns correct class for matching URL');
}

// ---------------------------------------------------------------------------
// Test 3: getCustomPageClass returns null for non-matching URL
// ---------------------------------------------------------------------------
{
  const pages = [];
  addCustomPage(
    { contextId: CONTEXT_ID, pattern: 'https://app.example.com/missing*', class: 'not-found' },
    pages,
  );

  const cls = getCustomPageClass('https://app.example.com/home', CONTEXT_ID, pages);
  assert.strictEqual(cls, null);
  console.log('PASS: getCustomPageClass returns null for non-matching URL');
}

// ---------------------------------------------------------------------------
// Test 4: getCustomPageClass is context-scoped (wrong context → null)
// ---------------------------------------------------------------------------
{
  const pages = [];
  addCustomPage(
    { contextId: 'other-context', pattern: 'https://app.example.com/missing*', class: 'not-found' },
    pages,
  );

  const cls = getCustomPageClass('https://app.example.com/missing/page', CONTEXT_ID, pages);
  assert.strictEqual(cls, null, 'must not match pages from a different context');
  console.log('PASS: getCustomPageClass is scoped to the correct context');
}

// ---------------------------------------------------------------------------
// Test 5: suppressFalsePositive — not-found page + HTTP 200 → true
// ---------------------------------------------------------------------------
{
  const pages = [];
  addCustomPage(
    { contextId: CONTEXT_ID, pattern: 'https://app.example.com/missing*', class: 'not-found' },
    pages,
  );

  // A custom 404 that the app serves as HTTP 200 — classic false positive
  const suppressed = suppressFalsePositive(
    'https://app.example.com/missing/anything',
    CONTEXT_ID,
    200,
    pages,
  );
  assert.strictEqual(suppressed, true, 'not-found page + 200 must be suppressed');
  console.log('PASS: suppressFalsePositive suppresses not-found page returning HTTP 200');
}

// ---------------------------------------------------------------------------
// Test 6: suppressFalsePositive — not-found page + HTTP 404 → also suppressed
// ---------------------------------------------------------------------------
{
  const pages = [];
  addCustomPage(
    { contextId: CONTEXT_ID, pattern: 'https://app.example.com/missing*', class: 'not-found' },
    pages,
  );

  const suppressed = suppressFalsePositive(
    'https://app.example.com/missing/x',
    CONTEXT_ID,
    404,
    pages,
  );
  assert.strictEqual(suppressed, true, 'not-found page + 404 must be suppressed');
  console.log('PASS: suppressFalsePositive suppresses not-found page with HTTP 404');
}

// ---------------------------------------------------------------------------
// Test 7: suppressFalsePositive — auth-required page + HTTP 200 → suppressed
// ---------------------------------------------------------------------------
{
  const pages = [];
  addCustomPage(
    { contextId: CONTEXT_ID, pattern: 'https://app.example.com/login*', class: 'auth-required' },
    pages,
  );

  const suppressed = suppressFalsePositive(
    'https://app.example.com/login',
    CONTEXT_ID,
    200,
    pages,
  );
  assert.strictEqual(suppressed, true, 'auth-required page + 200 must be suppressed');
  console.log('PASS: suppressFalsePositive suppresses auth-required page returning HTTP 200');
}

// ---------------------------------------------------------------------------
// Test 8: suppressFalsePositive — ok page → never suppressed
// ---------------------------------------------------------------------------
{
  const pages = [];
  addCustomPage(
    { contextId: CONTEXT_ID, pattern: 'https://app.example.com/home', class: 'ok' },
    pages,
  );

  const suppressed = suppressFalsePositive(
    'https://app.example.com/home',
    CONTEXT_ID,
    200,
    pages,
  );
  assert.strictEqual(suppressed, false, 'ok pages are never suppressed');
  console.log('PASS: suppressFalsePositive does not suppress ok pages');
}

// ---------------------------------------------------------------------------
// Test 9: suppressFalsePositive — no matching page → false
// ---------------------------------------------------------------------------
{
  const pages = [];
  const suppressed = suppressFalsePositive(
    'https://app.example.com/any',
    CONTEXT_ID,
    200,
    pages,
  );
  assert.strictEqual(suppressed, false, 'no custom page → no suppression');
  console.log('PASS: suppressFalsePositive returns false when no custom page matches');
}

// ---------------------------------------------------------------------------
// Test 10: removeCustomPage removes the page
// ---------------------------------------------------------------------------
{
  const pages = [];
  const page = addCustomPage(
    { contextId: CONTEXT_ID, pattern: 'https://app.example.com/gone*', class: 'not-found' },
    pages,
  );

  const removed = removeCustomPage(page.id, pages);
  assert.strictEqual(removed, true);
  assert.strictEqual(pages.length, 0, 'pages must be empty after removal');
  console.log('PASS: removeCustomPage removes the target page');
}

console.log('\nAll custom-pages-suppress-404-false-positive tests passed.');
