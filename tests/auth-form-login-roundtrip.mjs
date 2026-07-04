// Phase 3b — Auth Methods: form-based login roundtrip.
// Tests isFormAuth type-guard and performFormAuth offline behaviour.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let indexMod;
let formMod;
try {
  indexMod = require('../dist-electron/src/authMethods/index.js');
} catch {
  console.log('SKIP: authMethods/index.js not compiled — run tsc first.');
  process.exit(0);
}
try {
  formMod = require('../dist-electron/src/authMethods/formAuth.js');
} catch {
  console.log('SKIP: authMethods/formAuth.js not compiled — run tsc first.');
  process.exit(0);
}

const { isFormAuth } = indexMod;
const { performFormAuth } = formMod;

// ---------------------------------------------------------------------------
// Test 1: isFormAuth type-guard
// ---------------------------------------------------------------------------
{
  const method = { type: 'form', id: 'x', name: 'x', config: {} };
  assert.strictEqual(isFormAuth(method), true, 'isFormAuth should return true for type=form');

  const notForm = { type: 'json', id: 'y', name: 'y', config: {} };
  assert.strictEqual(isFormAuth(notForm), false, 'isFormAuth should return false for type=json');

  console.log('PASS: isFormAuth type-guard');
}

// ---------------------------------------------------------------------------
// Test 2: performFormAuth is exported as a function
// ---------------------------------------------------------------------------
{
  assert.strictEqual(typeof performFormAuth, 'function', 'performFormAuth must be a function');
  console.log('PASS: performFormAuth is a function');
}

// ---------------------------------------------------------------------------
// Test 3: offline call returns { success: false } on connection refused
// ---------------------------------------------------------------------------
{
  const result = await performFormAuth(
    {
      loginUrl: 'http://localhost:19999/invalid',
      usernameField: 'user',
      passwordField: 'pass',
    },
    { username: 'a', password: 'b' },
  );

  assert.strictEqual(result.success, false, 'offline call must return success=false');
  // error may be an empty string depending on the Node.js version and platform;
  // the invariant is that success=false and error is a string (not undefined).
  assert.ok(typeof result.error === 'string',
    `offline call must set error to a string, got: ${JSON.stringify(result.error)}`);

  console.log('PASS: performFormAuth returns { success: false } on connection refused');
}

// ---------------------------------------------------------------------------
// Test 4: isFormAuth returns false for unrecognised type
// ---------------------------------------------------------------------------
{
  const method = { type: 'manual', id: 'z', name: 'z', config: {} };
  assert.strictEqual(isFormAuth(method), false, 'isFormAuth should return false for type=manual');
  console.log('PASS: isFormAuth rejects non-form type');
}

console.log('\nAll auth-form-login-roundtrip tests passed.');
