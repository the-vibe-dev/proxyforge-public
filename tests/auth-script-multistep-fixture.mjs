// Phase 3b — Auth Methods: script-based multi-step auth fixture.
// Tests performScriptAuth with success, syntax error, and missing-run scenarios.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let scriptMod;
try {
  scriptMod = require('../dist-electron/src/authMethods/scriptAuth.js');
} catch {
  console.log('SKIP: authMethods/scriptAuth.js not compiled — run tsc first.');
  process.exit(0);
}

const { performScriptAuth } = scriptMod;

// ---------------------------------------------------------------------------
// Test 1: performScriptAuth is a function
// ---------------------------------------------------------------------------
{
  assert.strictEqual(typeof performScriptAuth, 'function', 'performScriptAuth must be a function');
  console.log('PASS: performScriptAuth is a function');
}

// ---------------------------------------------------------------------------
// Test 2: valid script returning success with sessionData
// ---------------------------------------------------------------------------
{
  const result = await performScriptAuth(
    {
      scriptSource: `
        async function run(ctx) {
          return { success: true, sessionData: { token: 'abc' } };
        }
      `,
      targetUrl: 'https://example.com',
    },
    { credentials: { username: 'alice', password: 'secret' } },
  );

  assert.strictEqual(result.success, true, 'valid script must return success=true');
  assert.deepEqual(result.sessionData, { token: 'abc' },
    'valid script must propagate sessionData');

  console.log('PASS: valid script returns { success: true, sessionData: { token: "abc" } }');
}

// ---------------------------------------------------------------------------
// Test 3: script with syntax error returns { success: false, error: /parse error/i }
// ---------------------------------------------------------------------------
{
  const result = await performScriptAuth(
    {
      scriptSource: 'this is not valid javascript }{{{',
      targetUrl: 'https://example.com',
    },
    { credentials: {} },
  );

  assert.strictEqual(result.success, false, 'syntax-error script must return success=false');
  assert.ok(typeof result.error === 'string', 'syntax-error script must return a string error');
  assert.match(result.error, /parse error/i,
    `error message should mention "parse error", got: "${result.error}"`);

  console.log('PASS: syntax-error script returns { success: false, error: /parse error/i }');
}

// ---------------------------------------------------------------------------
// Test 4: script without a `run` function returns { success: false, error: /must define/i }
// ---------------------------------------------------------------------------
{
  const result = await performScriptAuth(
    {
      scriptSource: `
        // no run function defined here
        const x = 42;
      `,
      targetUrl: 'https://example.com',
    },
    { credentials: {} },
  );

  assert.strictEqual(result.success, false, 'missing-run script must return success=false');
  assert.ok(typeof result.error === 'string', 'missing-run script must return a string error');
  assert.match(result.error, /must define/i,
    `error message should mention "must define", got: "${result.error}"`);

  console.log('PASS: missing run function returns { success: false, error: /must define/i }');
}

// ---------------------------------------------------------------------------
// Test 5: script that throws inside run returns { success: false }
// ---------------------------------------------------------------------------
{
  const result = await performScriptAuth(
    {
      scriptSource: `
        async function run(ctx) {
          throw new Error('deliberate runtime failure');
        }
      `,
      targetUrl: 'https://example.com',
    },
    { credentials: {} },
  );

  assert.strictEqual(result.success, false, 'throwing script must return success=false');
  assert.ok(typeof result.error === 'string' && result.error.length > 0,
    'throwing script must produce a non-empty error string');

  console.log('PASS: script that throws returns { success: false }');
}

// ---------------------------------------------------------------------------
// Test 6: script has access to credentials via ctx
// ---------------------------------------------------------------------------
{
  const result = await performScriptAuth(
    {
      scriptSource: `
        async function run(ctx) {
          if (ctx.credentials.username !== 'bob') {
            return { success: false, error: 'wrong user' };
          }
          return { success: true, sessionData: { user: ctx.credentials.username } };
        }
      `,
      targetUrl: 'https://example.com',
    },
    { credentials: { username: 'bob', password: 'hunter2' } },
  );

  assert.strictEqual(result.success, true);
  assert.deepEqual(result.sessionData, { user: 'bob' });

  console.log('PASS: script receives credentials in ctx');
}

console.log('\nAll auth-script-multistep-fixture tests passed.');
