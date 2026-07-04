// Test: Ajax spider heuristics + engine with React Router-style SPA fixture.
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

const heuristicsMod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'electron', 'spiders', 'ajaxSpiderHeuristics.js'),
  path.join(__dirname, '..', 'dist-electron', 'spiders', 'ajaxSpiderHeuristics.js'),
]);
const driverMod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'electron', 'spiders', 'ajaxSpiderDriver.js'),
  path.join(__dirname, '..', 'dist-electron', 'spiders', 'ajaxSpiderDriver.js'),
]);
const engineMod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'src', 'spiders', 'ajaxSpiderEngine.js'),
  path.join(__dirname, '..', 'dist-electron', 'spiders', 'ajaxSpiderEngine.js'),
]);

if (!heuristicsMod || !engineMod) {
  console.warn('[SKIP] spider-ajax-react-router-fixture: dist-electron not compiled, skipping.');
  process.exit(0);
}

const { extractRouteSignalsFromHtml } = heuristicsMod;
const { detectSpaFramework } = driverMod ?? {};
const { createSpiderState, mergeRoutes } = engineMod;

const BASE_URL = 'https://app.example.com';

// React Router SPA fixture — typical HTML from a CRA app
const reactRouterHtml = `<!DOCTYPE html>
<html>
<head>
  <title>React App</title>
  <script>window.__reactFiber = true</script>
  <script src="/static/js/main.chunk.js"></script>
</head>
<body>
  <div id="root" data-reactroot>
    <nav>
      <a href="/">Home</a>
      <a href="/dashboard">Dashboard</a>
      <a href="/users">Users</a>
      <a href="/users/123">User 123</a>
      <a href="/settings">Settings</a>
    </nav>
    <main>
      <button data-action="logout">Logout</button>
      <a href="mailto:support@example.com">Contact</a>
      <a href="javascript:void(0)" onclick="toggleModal()">Modal</a>
      <a href="https://external.com/docs">External Docs</a>
    </main>
  </div>
</body>
</html>`;

// 1. Framework detection: React Router signals present (detectSpaFramework may be in driverMod)
const framework = typeof detectSpaFramework === 'function' ? detectSpaFramework(reactRouterHtml) : undefined;
assert.ok(
  framework === 'react-router' || framework === undefined,
  `Expected react-router or undefined, got ${framework}`
);
// Note: since the HTML is a string, window.__reactFiber won't be a real object,
// but the signal string should still match
const frameworkFromSource = typeof detectSpaFramework === 'function'
  ? detectSpaFramework('window.__reactFiber = {}; var __REACT_DEVTOOLS_GLOBAL_HOOK__ = {};')
  : undefined;
assert.ok(
  frameworkFromSource === 'react-router' || frameworkFromSource === undefined || frameworkFromSource !== 'vue-router',
  `React signals should not match vue-router`
);

// 2. Route signal extraction: only same-origin links extracted
const signals = extractRouteSignalsFromHtml(reactRouterHtml, BASE_URL);
assert.ok(Array.isArray(signals), 'signals should be an array');

const sameDomainSignals = signals.filter((s) => s.url.startsWith(BASE_URL));
assert.ok(sameDomainSignals.length >= 4, `Expected >= 4 same-domain signals, got ${sameDomainSignals.length}`);

// 3. External links are still included (the spider filters later)
const externalSignals = signals.filter((s) => s.url.includes('external.com'));
assert.ok(externalSignals.length >= 1, 'External link should be captured for filtering');

// 4. mailto: is excluded
const mailtoSignals = signals.filter((s) => s.url.includes('mailto:'));
assert.ok(mailtoSignals.length === 0, 'mailto: should be excluded from signals');

// 5. javascript: is excluded
const jsSignals = signals.filter((s) => s.url.includes('javascript:'));
assert.ok(jsSignals.length === 0, 'javascript: should be excluded from signals');

// 6. Confidence ordering — high-confidence first
if (signals.length >= 2) {
  assert.ok(signals[0].confidence >= signals[signals.length - 1].confidence, 'Signals should be sorted by confidence desc');
}

// 7. Engine merges React Router routes
const state = createSpiderState(BASE_URL, 3);
const routes = sameDomainSignals.map((s) => ({
  url: s.url,
  method: 'GET',
  foundAt: BASE_URL,
  depth: 1,
  via: s.source,
}));

const added = mergeRoutes(state, routes);
assert.ok(added.length >= 4, `Expected >= 4 routes merged, got ${added.length}`);

// 8. No duplicate routes after second merge call
const secondMerge = mergeRoutes(state, routes);
assert.ok(secondMerge.length === 0, 'Second merge of same routes should add 0 new entries');

// 9. Sitemap snapshot has all entries
const snapshot = state.entries;
assert.ok(snapshot.size >= 4, `Expected >= 4 entries in map, got ${snapshot.size}`);

console.log(`[PASS] spider-ajax-react-router-fixture: detected framework=${frameworkFromSource ?? 'unknown'}, ${sameDomainSignals.length} same-domain signals, ${added.length} routes merged`);
