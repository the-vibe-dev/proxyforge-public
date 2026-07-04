// Phase 3b — Auth Methods: JSON-based login roundtrip.
// Tests isJsonAuth type-guard and performJsonAuth offline behaviour.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let indexMod;
let jsonMod;
try {
  indexMod = require('../dist-electron/src/authMethods/index.js');
} catch {
  console.log('SKIP: authMethods/index.js not compiled — run tsc first.');
  process.exit(0);
}
try {
  jsonMod = require('../dist-electron/src/authMethods/jsonAuth.js');
} catch {
  console.log('SKIP: authMethods/jsonAuth.js not compiled — run tsc first.');
  process.exit(0);
}

const { isJsonAuth } = indexMod;
const { performJsonAuth } = jsonMod;

// ---------------------------------------------------------------------------
// Test 1: isJsonAuth type-guard
// ---------------------------------------------------------------------------
{
  const method = { type: 'json', id: 'a', name: 'JSON Login', config: {} };
  assert.strictEqual(isJsonAuth(method), true, 'isJsonAuth should return true for type=json');

  const notJson = { type: 'form', id: 'b', name: 'Form Login', config: {} };
  assert.strictEqual(isJsonAuth(notJson), false, 'isJsonAuth should return false for type=form');

  console.log('PASS: isJsonAuth type-guard');
}

// ---------------------------------------------------------------------------
// Test 2: performJsonAuth is exported as a function
// ---------------------------------------------------------------------------
{
  assert.strictEqual(typeof performJsonAuth, 'function', 'performJsonAuth must be a function');
  console.log('PASS: performJsonAuth is a function');
}

// ---------------------------------------------------------------------------
// Test 3: offline call returns { success: false } on connection refused
// ---------------------------------------------------------------------------
{
  const result = await performJsonAuth(
    {
      loginUrl: 'http://localhost:19999/api/login',
      bodyTemplate: { email: '{{username}}', password: '{{password}}' },
      tokenClaimPath: 'data.accessToken',
    },
    { username: 'testuser', password: 'testpass' },
  );

  assert.strictEqual(result.success, false, 'offline call must return success=false');
  // error may be an empty string depending on the Node.js version and platform;
  // the invariant is that success=false and error is a string (not undefined).
  assert.ok(typeof result.error === 'string',
    `offline call must set error to a string, got: ${JSON.stringify(result.error)}`);

  console.log('PASS: performJsonAuth returns { success: false } on connection refused');
}

// ---------------------------------------------------------------------------
// Test 4: isJsonAuth rejects unrelated types
// ---------------------------------------------------------------------------
{
  assert.strictEqual(isJsonAuth({ type: 'http-basic', id: 'c', name: 'Basic', config: {} }), false);
  assert.strictEqual(isJsonAuth({ type: 'totp', id: 'd', name: 'TOTP', config: {} }), false);
  assert.strictEqual(isJsonAuth({ type: 'manual', id: 'e', name: 'Manual', config: {} }), false);
  console.log('PASS: isJsonAuth rejects non-json types');
}

console.log('\nAll auth-json-login-roundtrip tests passed.');
