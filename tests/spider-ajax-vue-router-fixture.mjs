// Test: Ajax spider with Vue Router-style SPA fixture.
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

if (!heuristicsMod) {
  console.warn('[SKIP] spider-ajax-vue-router-fixture: dist-electron not compiled, skipping.');
  process.exit(0);
}

const { extractRouteSignalsFromHtml, scoreClickCandidate } = heuristicsMod;
const detectSpaFramework = driverMod?.detectSpaFramework;

const BASE_URL = 'https://vue-app.example.com';

// Vue Router SPA HTML — uses `to` attributes on router-link components
const vueRouterHtml = `<!DOCTYPE html>
<html>
<head>
  <script>window.__VUE__ = true; window.__VUE_HMR_RUNTIME__ = {};</script>
</head>
<body>
  <div id="app">
    <nav>
      <router-link to="/">Home</router-link>
      <router-link to="/about">About</router-link>
      <router-link to="/products">Products</router-link>
      <router-link to="/products/42">Product 42</router-link>
      <router-link to="/cart">Cart</router-link>
    </nav>
    <a href="/checkout">Checkout</a>
    <a href="/profile/me">Profile</a>
    <router-view></router-view>
  </div>
</body>
</html>`;

// 1. Framework detection: Vue Router signals (detectSpaFramework is from driverMod)
const framework = typeof detectSpaFramework === 'function' ? detectSpaFramework(vueRouterHtml) : undefined;
// Note: string-based signal detection — will match if the signal text is in the HTML
const vueFramework = typeof detectSpaFramework === 'function'
  ? detectSpaFramework('window.__VUE__ = true; window.__vue_router__ = {};')
  : undefined;
assert.ok(
  vueFramework === 'vue-router' || vueFramework === undefined || vueFramework !== 'react-router',
  `Vue signals should not match react-router, got ${vueFramework}`
);

// 2. Extract `to="..."` attributes as router-attr signals
const signals = extractRouteSignalsFromHtml(vueRouterHtml, BASE_URL);
assert.ok(Array.isArray(signals), 'signals should be an array');

const toSignals = signals.filter((s) => s.source === 'router-attr');
assert.ok(
  toSignals.length >= 3,
  `Expected >= 3 router-attr signals from to="...", got ${toSignals.length}`
);

// 3. href links also captured
const hrefSignals = signals.filter((s) => s.source === 'href');
assert.ok(hrefSignals.length >= 2, `Expected >= 2 href signals, got ${hrefSignals.length}`);

// 4. router-attr confidence is >= 0.7
if (toSignals.length > 0) {
  assert.ok(toSignals[0].confidence >= 0.7, `router-attr confidence should be >= 0.7, got ${toSignals[0].confidence}`);
}

// 5. href confidence >= 0.8
if (hrefSignals.length > 0) {
  assert.ok(hrefSignals[0].confidence >= 0.8, `href confidence should be >= 0.8, got ${hrefSignals[0].confidence}`);
}

// 6. Scoring: router-link with 'to' attribute
const candidate = scoreClickCandidate('a', { to: '/products', role: 'link' }, 'Products');
assert.ok(candidate.score > 10, `Expected score > 10 for router-link, got ${candidate.score}`);
assert.ok(candidate.navigationLikelihood === 'high', `Expected high nav likelihood, got ${candidate.navigationLikelihood}`);

// 7. Scoring: plain div with no attributes is low
const divCandidate = scoreClickCandidate('div', {}, 'Content block');
assert.ok(divCandidate.score === 0 || divCandidate.score < 5, `Expected low score for plain div, got ${divCandidate.score}`);

// 8. Total unique signal count
const allUrls = new Set(signals.map((s) => s.url));
assert.ok(allUrls.size >= 5, `Expected >= 5 unique route URLs, got ${allUrls.size}`);

console.log(`[PASS] spider-ajax-vue-router-fixture: ${toSignals.length} router-attr signals, ${hrefSignals.length} href signals, framework=${vueFramework ?? 'unknown'}`);
