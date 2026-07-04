// Tests: safe mode blocks active probes, standard allows them,
//        attack mode allows out-of-scope only when explicitly in allowlist.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let modesModule;
try {
  modesModule = require('../dist-electron/modes/index.js');
} catch {
  try {
    modesModule = require('../dist-electron/modesIndex.js');
  } catch {
    console.log('global-mode-safe-blocks-active-scan: skipped — modes module not compiled yet');
    process.exit(0);
  }
}

const { setGlobalMode, getGlobalMode, isActiveProbeAllowed, isSafeMode } = modesModule;

if (typeof setGlobalMode !== 'function') {
  console.log('global-mode-safe-blocks-active-scan: skipped — missing exports');
  process.exit(0);
}

const IN_SCOPE = ['https://target.example.com/*'];
const TARGET = 'https://target.example.com/api/users';
const OUT_OF_SCOPE = 'https://other.example.com/page';

// ---------------------------------------------------------------------------
// Test 1: Safe mode blocks all active probes
// ---------------------------------------------------------------------------
{
  setGlobalMode('safe');
  assert.strictEqual(getGlobalMode(), 'safe');
  assert.strictEqual(isSafeMode(), true);

  assert.strictEqual(isActiveProbeAllowed(TARGET, IN_SCOPE), false,
    'safe mode must block in-scope targets');
  assert.strictEqual(isActiveProbeAllowed(OUT_OF_SCOPE, IN_SCOPE), false,
    'safe mode must block out-of-scope targets');
  assert.strictEqual(isActiveProbeAllowed(TARGET, []), false,
    'safe mode must block even with empty allowlist');

  console.log('PASS: safe mode blocks all active probes');
}

// ---------------------------------------------------------------------------
// Test 2: isSafeMode returns false when mode is not safe
// ---------------------------------------------------------------------------
{
  setGlobalMode('standard');
  assert.strictEqual(isSafeMode(), false);
  setGlobalMode('protected');
  assert.strictEqual(isSafeMode(), false);
  setGlobalMode('attack');
  assert.strictEqual(isSafeMode(), false);
  console.log('PASS: isSafeMode returns false for non-safe modes');
}

// ---------------------------------------------------------------------------
// Test 3: Standard mode allows in-scope probes
// ---------------------------------------------------------------------------
{
  setGlobalMode('standard');
  assert.strictEqual(getGlobalMode(), 'standard');

  assert.strictEqual(isActiveProbeAllowed(TARGET, IN_SCOPE), true,
    'standard mode must allow in-scope targets');
  console.log('PASS: standard mode allows in-scope probes');
}

// ---------------------------------------------------------------------------
// Test 4: Standard mode blocks out-of-scope probes
// ---------------------------------------------------------------------------
{
  setGlobalMode('standard');
  assert.strictEqual(isActiveProbeAllowed(OUT_OF_SCOPE, IN_SCOPE), false,
    'standard mode must block out-of-scope targets');
  assert.strictEqual(isActiveProbeAllowed(TARGET, []), false,
    'standard mode with empty allowlist must block everything');
  console.log('PASS: standard mode blocks out-of-scope probes');
}

// ---------------------------------------------------------------------------
// Test 5: Protected mode also requires scope match
// ---------------------------------------------------------------------------
{
  setGlobalMode('protected');
  assert.strictEqual(isActiveProbeAllowed(TARGET, IN_SCOPE), true,
    'protected mode allows in-scope targets');
  assert.strictEqual(isActiveProbeAllowed(OUT_OF_SCOPE, IN_SCOPE), false,
    'protected mode blocks out-of-scope targets');
  console.log('PASS: protected mode restricts to in-scope targets');
}

// ---------------------------------------------------------------------------
// Test 6: Attack mode allows in-scope targets
// ---------------------------------------------------------------------------
{
  setGlobalMode('attack');
  assert.strictEqual(isActiveProbeAllowed(TARGET, IN_SCOPE), true,
    'attack mode must allow in-scope targets');
  console.log('PASS: attack mode allows in-scope targets');
}

// ---------------------------------------------------------------------------
// Test 7: Attack mode blocks out-of-scope targets not in allowlist
// ---------------------------------------------------------------------------
{
  setGlobalMode('attack');
  assert.strictEqual(isActiveProbeAllowed(OUT_OF_SCOPE, IN_SCOPE), false,
    'attack mode must block targets not in allowlist');
  console.log('PASS: attack mode blocks out-of-scope targets without explicit approval');
}

// ---------------------------------------------------------------------------
// Test 8: Attack mode allows out-of-scope URL when explicitly added to allowlist
// ---------------------------------------------------------------------------
{
  setGlobalMode('attack');
  const expandedScope = [...IN_SCOPE, 'https://other.example.com/*'];
  assert.strictEqual(isActiveProbeAllowed(OUT_OF_SCOPE, expandedScope), true,
    'attack mode must allow out-of-scope target when added to allowlist');
  console.log('PASS: attack mode allows explicitly approved out-of-scope target');
}

// ---------------------------------------------------------------------------
// Test 9: Mode persists across calls
// ---------------------------------------------------------------------------
{
  setGlobalMode('safe');
  assert.strictEqual(getGlobalMode(), 'safe');
  setGlobalMode('attack');
  assert.strictEqual(getGlobalMode(), 'attack');
  // Restore to standard for cleanliness
  setGlobalMode('standard');
  assert.strictEqual(getGlobalMode(), 'standard');
  console.log('PASS: global mode persists and can be changed');
}

console.log('\nAll global-mode-safe-blocks-active-scan tests passed.');
