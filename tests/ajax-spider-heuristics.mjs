// Tests for electron/spiders/ajaxSpiderHeuristics.ts + ajaxSpiderDriver.ts (detectSpaFramework)
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let heuristics, driver;
try {
  heuristics = require('../dist-electron/spiders/ajaxSpiderHeuristics.js');
} catch {
  console.log('SKIP ajax-spider-heuristics (module not compiled)');
  process.exit(0);
}
try {
  driver = require('../dist-electron/spiders/ajaxSpiderDriver.js');
} catch {
  // detectSpaFramework tests will be skipped if driver not compiled
  driver = null;
}

const { scoreClickCandidate, extractRouteSignalsFromHtml, rankCandidates } = heuristics;

// 1. scoreClickCandidate('a', {href: '/dashboard'}, 'Dashboard') has score > 0 and navigationLikelihood: 'high'
const anchorWithPath = scoreClickCandidate('a', { href: '/dashboard' }, 'Dashboard');
assert.ok(anchorWithPath.score > 0, `anchor with /dashboard href should have score > 0 (got ${anchorWithPath.score})`);
assert.equal(anchorWithPath.navigationLikelihood, 'high', 'anchor with path href has navigationLikelihood: high');
console.log('  [1] anchor with /dashboard href: score > 0 and navigationLikelihood high: PASS');

// 2. scoreClickCandidate('a', {href: 'javascript:void(0)'}, 'Noop') has score <= 0
const noop = scoreClickCandidate('a', { href: 'javascript:void(0)' }, 'Noop');
assert.ok(noop.score <= 0, `javascript:void(0) href should have score <= 0 (got ${noop.score})`);
console.log('  [2] javascript:void(0) href has score <= 0: PASS');

// 3. scoreClickCandidate('button', {role: 'link'}, 'Go') has navigationLikelihood: 'high'
const buttonWithRoleLink = scoreClickCandidate('button', { role: 'link' }, 'Go');
assert.equal(buttonWithRoleLink.navigationLikelihood, 'high', 'button with role=link has navigationLikelihood: high');
assert.ok(buttonWithRoleLink.score > 0, `button with role=link should have score > 0 (got ${buttonWithRoleLink.score})`);
console.log('  [3] button with role=link has navigationLikelihood high: PASS');

// 4. scoreClickCandidate('div', {}, 'Text') has score = 0 (no nav signals)
const plainDiv = scoreClickCandidate('div', {}, 'Text');
assert.ok(plainDiv.score === 0, `plain div with no attrs should have score 0 (got ${plainDiv.score})`);
console.log('  [4] plain div with no attributes has score 0: PASS');

// 5. extractRouteSignalsFromHtml extracts href links and resolves against baseUrl
const baseUrl = 'https://app.example.com';
const htmlWithHrefs = `
  <nav>
    <a href="/about">About</a>
    <a href="/contact">Contact</a>
    <a href="https://external.example.com/page">External</a>
  </nav>
`;
const signals = extractRouteSignalsFromHtml(htmlWithHrefs, baseUrl);
assert.ok(Array.isArray(signals), 'extractRouteSignalsFromHtml returns array');
assert.ok(signals.length >= 3, `should extract at least 3 href signals (got ${signals.length})`);
const signalUrls = signals.map((s) => s.url);
assert.ok(signalUrls.some((u) => u === 'https://app.example.com/about'), '/about resolved against baseUrl');
assert.ok(signalUrls.some((u) => u === 'https://app.example.com/contact'), '/contact resolved against baseUrl');
assert.ok(signalUrls.some((u) => u === 'https://external.example.com/page'), 'absolute URL preserved');
console.log('  [5] extractRouteSignalsFromHtml extracts href links and resolves them: PASS');

// 6. extractRouteSignalsFromHtml extracts `to="..."` router attribute links
const htmlWithRouterAttrs = `
  <nav>
    <a to="/dashboard">Dashboard</a>
    <router-link to="/profile">Profile</router-link>
    <a to="/settings">Settings</a>
  </nav>
`;
const routerSignals = extractRouteSignalsFromHtml(htmlWithRouterAttrs, baseUrl);
const routerSignalUrls = routerSignals.map((s) => s.url);
assert.ok(routerSignalUrls.some((u) => u.includes('/dashboard')), 'to="/dashboard" extracted as router-attr signal');
assert.ok(routerSignalUrls.some((u) => u.includes('/profile')), 'to="/profile" extracted');
const routerAttrSignals = routerSignals.filter((s) => s.source === 'router-attr');
assert.ok(routerAttrSignals.length >= 1, 'at least one signal with source router-attr');
console.log('  [6] extractRouteSignalsFromHtml extracts to="..." router attributes: PASS');

// 7. extractRouteSignalsFromHtml ignores mailto: and tel: hrefs
const htmlWithMailtoTel = `
  <a href="mailto:admin@example.com">Email</a>
  <a href="tel:+15551234567">Call</a>
  <a href="/real-page">Real Page</a>
`;
const filteredSignals = extractRouteSignalsFromHtml(htmlWithMailtoTel, baseUrl);
const filteredUrls = filteredSignals.map((s) => s.url);
assert.ok(!filteredUrls.some((u) => u.startsWith('mailto:')), 'mailto: href is ignored');
assert.ok(!filteredUrls.some((u) => u.startsWith('tel:')), 'tel: href is ignored');
assert.ok(filteredUrls.some((u) => u.includes('/real-page')), 'valid href is still included');
console.log('  [7] extractRouteSignalsFromHtml ignores mailto: and tel: hrefs: PASS');

// 8. rankCandidates returns candidates sorted by score descending
const candidates = [
  scoreClickCandidate('a', { href: '/home' }, 'Home'),
  scoreClickCandidate('div', {}, 'Content'),
  scoreClickCandidate('button', { role: 'link' }, 'Go'),
  scoreClickCandidate('a', { href: '/profile' }, 'Profile'),
];
const ranked = rankCandidates(candidates);
assert.ok(Array.isArray(ranked), 'rankCandidates returns array');
assert.equal(ranked.length, candidates.length, 'ranked has same number of candidates');
for (let i = 0; i < ranked.length - 1; i++) {
  assert.ok(ranked[i].score >= ranked[i + 1].score, `ranked[${i}].score (${ranked[i].score}) >= ranked[${i + 1}].score (${ranked[i + 1].score})`);
}
console.log('  [8] rankCandidates returns candidates sorted by score descending: PASS');

// 9. detectSpaFramework matches React Router signal (__reactFiber)
if (!driver) {
  console.log('  [9] SKIP detectSpaFramework React Router (ajaxSpiderDriver not compiled)');
  console.log('  [10] SKIP detectSpaFramework Vue Router (ajaxSpiderDriver not compiled)');
} else {
  const { detectSpaFramework } = driver;

  const reactPageSource = '<div id="app" __reactFiber="xyz">...</div>';
  const reactFramework = detectSpaFramework(reactPageSource);
  assert.ok(reactFramework, 'detectSpaFramework returns a result for React signals');
  assert.equal(reactFramework, 'react-router', `detected framework should be react-router (got ${reactFramework})`);
  console.log('  [9] detectSpaFramework matches React Router signal (__reactFiber): PASS');

  // 10. detectSpaFramework matches Vue Router signal (__VUE__)
  const vuePageSource = '<div id="app" class="vue-app"><!-- __VUE__ --></div>';
  const vueFramework = detectSpaFramework(vuePageSource);
  assert.ok(vueFramework, 'detectSpaFramework returns a result for Vue signals');
  assert.equal(vueFramework, 'vue-router', `detected framework should be vue-router (got ${vueFramework})`);
  console.log('  [10] detectSpaFramework matches Vue Router signal (__VUE__): PASS');
}

console.log('PASS ajax-spider-heuristics');
