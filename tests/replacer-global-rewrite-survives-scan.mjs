// Test: replacer engine — rule creation, application, and enabled-rule filtering.
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

const mod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'src', 'replacer', 'index.js'),
  path.join(__dirname, '..', 'dist-electron', 'replacer', 'index.js'),
]);

if (!mod) {
  console.log('SKIP: replacer-global-rewrite-survives-scan — dist-electron/src/replacer/index.js not compiled, run tsc first.');
  process.exit(0);
}

const {
  createReplacerRule,
  applyReplacerRules,
  applyReplacerRulesToResponse,
} = mod;

// ── Rule creation ─────────────────────────────────────────────────────────────

assert.ok(typeof createReplacerRule === 'function', 'createReplacerRule must be a function');

// A User-Agent rewrite rule (plain string match)
const uaRule = createReplacerRule({
  name: 'Spoof User-Agent',
  scope: 'request',
  matchPattern: 'Mozilla/5.0',
  replaceWith: 'ProxyForge/1.0',
});
assert.ok(uaRule !== null && typeof uaRule === 'object', 'createReplacerRule should return an object');
assert.ok(typeof uaRule.id === 'string' && uaRule.id.length > 0, 'rule.id should be a non-empty string');
assert.equal(uaRule.name, 'Spoof User-Agent', 'rule.name should match');
assert.equal(uaRule.scope, 'request', 'rule.scope should match');
assert.equal(uaRule.matchPattern, 'Mozilla/5.0', 'rule.matchPattern should match');
assert.equal(uaRule.replaceWith, 'ProxyForge/1.0', 'rule.replaceWith should match');
assert.equal(uaRule.enabled, true, 'rule should be enabled by default');

// ── applyReplacerRules — replaces User-Agent ──────────────────────────────────

assert.ok(typeof applyReplacerRules === 'function', 'applyReplacerRules must be a function');

// NOTE: The function signature is applyReplacerRules(rawRequest, rules)
const rawRequest = [
  'GET /api/data HTTP/1.1',
  'Host: example.com',
  'User-Agent: Mozilla/5.0 (compatible; scanner)',
  'Accept: application/json',
  '',
  '',
].join('\n');

const rewritten = applyReplacerRules(rawRequest, [uaRule]);
assert.ok(typeof rewritten === 'string', 'applyReplacerRules should return a string');
assert.ok(
  rewritten.includes('ProxyForge/1.0'),
  `Rewritten request should contain "ProxyForge/1.0", got:\n${rewritten}`,
);
assert.ok(
  !rewritten.includes('Mozilla/5.0'),
  `Rewritten request should not contain original value "Mozilla/5.0", got:\n${rewritten}`,
);

// ── Disabled rules are skipped ────────────────────────────────────────────────

const disabledRule = createReplacerRule({
  name: 'Disabled rule',
  enabled: false,
  scope: 'request',
  matchPattern: 'application/json',
  replaceWith: 'application/xml',
});
assert.equal(disabledRule.enabled, false, 'disabled rule should have enabled=false');

// When only a disabled rule is present, output should be unchanged
const withDisabled = applyReplacerRules(rawRequest, [disabledRule]);
assert.equal(withDisabled, rawRequest, 'Disabled rule should not modify the request');

// When mixing enabled + disabled rules, only enabled rules fire
const mixed = applyReplacerRules(rawRequest, [disabledRule, uaRule]);
assert.ok(mixed.includes('ProxyForge/1.0'), 'enabled rule should still fire in mixed list');
assert.ok(mixed.includes('application/json'), 'disabled rule should NOT rewrite Accept header');

// ── getEnabledRules helper (if exported) ──────────────────────────────────────

// The source doesn't export getEnabledRules — that's a filter in the caller.
// We verify the contract: applyReplacerRules internally skips disabled rules.
// Two enabled rules with different patterns both fire.
const hostRule = createReplacerRule({
  name: 'Add Debug Header',
  scope: 'request',
  matchPattern: 'example.com',
  replaceWith: 'target.internal',
});
const doubleRewritten = applyReplacerRules(rawRequest, [uaRule, hostRule]);
assert.ok(doubleRewritten.includes('ProxyForge/1.0'), 'first rule should fire');
assert.ok(doubleRewritten.includes('target.internal'), 'second rule should fire');

// ── Response rules are not applied to requests ────────────────────────────────

const responseOnlyRule = createReplacerRule({
  name: 'Add X-Frame-Options',
  scope: 'response',
  matchPattern: 'application/json',
  replaceWith: 'text/html',
});
// Applying to a request should leave it unchanged
const requestAfterResponseRule = applyReplacerRules(rawRequest, [responseOnlyRule]);
assert.ok(requestAfterResponseRule.includes('application/json'), 'response-only rule should not affect request');

// ── applyReplacerRulesToResponse (if exported) ────────────────────────────────

if (typeof applyReplacerRulesToResponse === 'function') {
  const rawResponse = [
    'HTTP/1.1 200 OK',
    'Content-Type: application/json',
    '',
    '{"ok":true}',
  ].join('\n');
  const rewrittenResp = applyReplacerRulesToResponse(rawResponse, [responseOnlyRule]);
  assert.ok(typeof rewrittenResp === 'string', 'applyReplacerRulesToResponse should return a string');
  assert.ok(rewrittenResp.includes('text/html'), 'response rule should rewrite Content-Type');
}

// ── Regex pattern matching ────────────────────────────────────────────────────

const regexRule = createReplacerRule({
  name: 'Strip session cookie',
  scope: 'request',
  matchPattern: '/sessionid=[^;]+/',
  replaceWith: 'sessionid=REDACTED',
});
const cookieRequest = 'GET / HTTP/1.1\nHost: app.com\nCookie: sessionid=abc123; csrftoken=xyz\n\n';
const scrubbed = applyReplacerRules(cookieRequest, [regexRule]);
assert.ok(scrubbed.includes('sessionid=REDACTED'), 'regex rule should replace matched session id');
assert.ok(!scrubbed.includes('abc123'), 'original session id should be gone');
assert.ok(scrubbed.includes('csrftoken=xyz'), 'unrelated cookie part should remain');

console.log('PASS replacer-global-rewrite-survives-scan: rule creation, application, scoping, and regex patterns verified.');
