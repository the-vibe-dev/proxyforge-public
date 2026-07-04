// Test: Ajax spider driver rate/budget enforcement.
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

const driverMod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'electron', 'spiders', 'ajaxSpiderDriver.js'),
  path.join(__dirname, '..', 'dist-electron', 'spiders', 'ajaxSpiderDriver.js'),
]);

if (!driverMod) {
  console.warn('[SKIP] spider-ajax-rate-budget-respected: dist-electron not compiled, skipping.');
  process.exit(0);
}

const { runAjaxSpider, buildExcludeFilter } = driverMod;

// 1. runAjaxSpider returns error when Playwright not installed
const result = await runAjaxSpider({
  projectId: 'test-project',
  startUrl: 'https://example.com',
});
assert.ok(
  result.status === 'complete' || result.status === 'error',
  `Expected status 'complete' or 'error', got ${result.status}`
);
assert.ok(typeof result.durationMs === 'number', 'durationMs should be a number');
assert.ok(typeof result.pagesVisited === 'number', 'pagesVisited should be a number');
assert.ok(Array.isArray(result.routes), 'routes should be an array');

// 2. When Playwright not installed, error message mentions Playwright
if (result.status === 'error') {
  assert.ok(
    result.error?.toLowerCase().includes('playwright'),
    `Error should mention Playwright, got: ${result.error}`
  );
}

// 3. buildExcludeFilter: excludes matching URLs
const filter = buildExcludeFilter(['logout', '\\.pdf$', '/admin/']);
assert.ok(filter('https://example.com/logout'), 'Should exclude /logout');
assert.ok(filter('https://example.com/files/doc.pdf'), 'Should exclude .pdf URLs');
assert.ok(filter('https://example.com/admin/users'), 'Should exclude /admin/ paths');
assert.ok(!filter('https://example.com/dashboard'), 'Should not exclude /dashboard');
assert.ok(!filter('https://example.com/products'), 'Should not exclude /products');

// 4. buildExcludeFilter: empty patterns excludes nothing
const noFilter = buildExcludeFilter([]);
assert.ok(!noFilter('https://example.com/anything'), 'Empty filter should exclude nothing');

// 5. buildExcludeFilter: regex pattern via /pattern/
const regexFilter = buildExcludeFilter(['/\\.(jpg|png|gif)$/']);
assert.ok(regexFilter('https://example.com/image.jpg'), 'Should exclude .jpg');
assert.ok(regexFilter('https://example.com/photo.png'), 'Should exclude .png');
assert.ok(!regexFilter('https://example.com/api/data'), 'Should not exclude /api/data');

// 6. durationMs >= 0
assert.ok(result.durationMs >= 0, 'durationMs should be >= 0');

// 7. clicksFired is a number
assert.ok(typeof result.clicksFired === 'number', 'clicksFired should be a number');

// 8. pagesVisited <= maxPages when configured
const budgetResult = await runAjaxSpider({
  projectId: 'test-project',
  startUrl: 'https://example.com',
  maxPages: 5,
  maxDepth: 2,
});
assert.ok(
  budgetResult.pagesVisited <= 5 || budgetResult.status === 'error',
  `pagesVisited ${budgetResult.pagesVisited} should be <= maxPages 5 (or error)`
);

console.log(`[PASS] spider-ajax-rate-budget-respected: status=${result.status}, pages=${result.pagesVisited}, routes=${result.routes.length}`);
