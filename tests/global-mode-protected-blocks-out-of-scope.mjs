// Phase 3b — Modes: protected mode blocks out-of-scope active probes.
// Tests setGlobalMode, isActiveProbeAllowed with protected and safe modes.
// The exported function is isActiveProbeAllowed (not isActiveScanAllowed).
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let modesMod;
try {
  modesMod = require('../dist-electron/src/modes/index.js');
} catch {
  console.log('SKIP: modes/index.js not compiled — run tsc first.');
  process.exit(0);
}

const { setGlobalMode, getGlobalMode, isActiveProbeAllowed, isSafeMode } = modesMod;

if (typeof setGlobalMode !== 'function' || typeof isActiveProbeAllowed !== 'function') {
  console.log('SKIP: required exports not present in modes/index.js');
  process.exit(0);
}

const IN_SCOPE_PATTERNS = ['https://in-scope.example.com'];
const IN_SCOPE_URL = 'https://in-scope.example.com/api/login';
const OUT_OF_SCOPE_URL = 'https://out-of-scope.evil.com/steal';

// ---------------------------------------------------------------------------
// Test 1: setGlobalMode('protected') is accepted
// ---------------------------------------------------------------------------
{
  setGlobalMode('protected');
  assert.strictEqual(getGlobalMode(), 'protected',
    'getGlobalMode() must return "protected" after setGlobalMode("protected")');

  console.log('PASS: setGlobalMode("protected") is accepted');
}

// ---------------------------------------------------------------------------
// Test 2: protected mode blocks out-of-scope URLs
// ---------------------------------------------------------------------------
{
  setGlobalMode('protected');

  const allowed = isActiveProbeAllowed(OUT_OF_SCOPE_URL, IN_SCOPE_PATTERNS);
  assert.strictEqual(allowed, false,
    'protected mode must block probes to out-of-scope URLs');

  console.log('PASS: protected mode blocks out-of-scope URL');
}

// ---------------------------------------------------------------------------
// Test 3: protected mode allows in-scope URLs
// ---------------------------------------------------------------------------
{
  setGlobalMode('protected');

  const allowed = isActiveProbeAllowed(IN_SCOPE_URL, IN_SCOPE_PATTERNS);
  assert.strictEqual(allowed, true,
    'protected mode must allow probes to in-scope URLs');

  console.log('PASS: protected mode allows in-scope URL');
}

// ---------------------------------------------------------------------------
// Test 4: protected mode blocks when scope list is empty
// ---------------------------------------------------------------------------
{
  setGlobalMode('protected');

  assert.strictEqual(isActiveProbeAllowed(IN_SCOPE_URL, []), false,
    'protected mode must block all probes when scope list is empty');
  assert.strictEqual(isActiveProbeAllowed(OUT_OF_SCOPE_URL, []), false,
    'protected mode must block out-of-scope probes when scope list is empty');

  console.log('PASS: protected mode blocks all probes when scope list is empty');
}

// ---------------------------------------------------------------------------
// Test 5: safe mode blocks all probes, regardless of scope
// ---------------------------------------------------------------------------
{
  setGlobalMode('safe');
  assert.strictEqual(getGlobalMode(), 'safe');
  assert.strictEqual(isSafeMode(), true);

  assert.strictEqual(isActiveProbeAllowed(IN_SCOPE_URL, IN_SCOPE_PATTERNS), false,
    'safe mode must block in-scope probes');
  assert.strictEqual(isActiveProbeAllowed(OUT_OF_SCOPE_URL, IN_SCOPE_PATTERNS), false,
    'safe mode must block out-of-scope probes');
  assert.strictEqual(isActiveProbeAllowed(IN_SCOPE_URL, []), false,
    'safe mode must block probes with empty scope list');

  console.log('PASS: setGlobalMode("safe") blocks all active probes');
}

// ---------------------------------------------------------------------------
// Test 6: mode override parameter works without mutating global state
// ---------------------------------------------------------------------------
{
  // Set global to protected first
  setGlobalMode('protected');

  // Explicitly pass 'safe' as override — should block even in-scope URL
  const safeOverride = isActiveProbeAllowed(IN_SCOPE_URL, IN_SCOPE_PATTERNS, 'safe');
  assert.strictEqual(safeOverride, false,
    'mode override "safe" must block in-scope URL regardless of global mode');

  // Global mode should still be 'protected'
  assert.strictEqual(getGlobalMode(), 'protected',
    'global mode must not change when using mode override');

  console.log('PASS: mode override parameter does not mutate global state');
}

// ---------------------------------------------------------------------------
// Test 7: wildcard scope pattern works in protected mode
// ---------------------------------------------------------------------------
{
  setGlobalMode('protected');

  const wildcardScope = ['https://in-scope.example.com/*'];
  const deepUrl = 'https://in-scope.example.com/api/v2/users/42';

  assert.strictEqual(isActiveProbeAllowed(deepUrl, wildcardScope), true,
    'wildcard scope must match deep paths in protected mode');
  assert.strictEqual(isActiveProbeAllowed(OUT_OF_SCOPE_URL, wildcardScope), false,
    'wildcard scope must still block out-of-scope URLs in protected mode');

  console.log('PASS: wildcard scope patterns work in protected mode');
}

// ---------------------------------------------------------------------------
// Clean up: restore to standard mode
// ---------------------------------------------------------------------------
setGlobalMode('standard');

console.log('\nAll global-mode-protected-blocks-out-of-scope tests passed.');
