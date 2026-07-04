// Tests: stickyCookie.ts + stickyAuth.ts
// stickyCookie: applyStickycookie pins Cookie header
// stickyAuth:   applyStickyAuth pins Authorization header
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

function tryLoad(newPath, oldPath) {
  try { return require(newPath); } catch {}
  try { return require(oldPath); } catch {}
  return null;
}

const cookieMod = tryLoad(
  '../dist-electron/electron/traffic/rules/stickyCookie.js',
  '../dist-electron/traffic/rules/stickyCookie.js',
);
const authMod = tryLoad(
  '../dist-electron/electron/traffic/rules/stickyAuth.js',
  '../dist-electron/traffic/rules/stickyAuth.js',
);

if (!cookieMod && !authMod) {
  console.log('SKIP: traffic/rules/stickyCookie and stickyAuth not compiled');
  process.exit(0);
}

try {
  // ── stickyCookie ──────────────────────────────────────────────────────────
  if (cookieMod) {
    const { applyStickycookie } = cookieMod;

    // Pins the Cookie header with the given value
    const headers = { Host: 'example.com', Accept: '*/*' };
    const result = applyStickycookie(headers, 'session=abc123; csrf=xyz');

    assert.ok(result, 'applyStickycookie must return an object');
    assert.equal(result.Cookie, 'session=abc123; csrf=xyz', 'Cookie header must be set to given value');
    // Original headers preserved
    assert.equal(result.Host, 'example.com', 'Other headers must be preserved');
    assert.equal(result.Accept, '*/*', 'Accept header must be preserved');
    // Original object not mutated
    assert.equal(headers.Cookie, undefined, 'applyStickycookie must not mutate input headers');

    // Overwrites any existing Cookie header
    const withExisting = { Cookie: 'old=value' };
    const replaced = applyStickycookie(withExisting, 'session=new');
    assert.equal(replaced.Cookie, 'session=new', 'applyStickycookie must overwrite existing Cookie');

    console.log('  stickyCookie: OK');
  } else {
    console.log('  stickyCookie: SKIP (not compiled)');
  }

  // ── stickyAuth ────────────────────────────────────────────────────────────
  if (authMod) {
    const { applyStickyAuth } = authMod;

    const headers = { Host: 'api.example.com' };
    const authValue = 'Bearer eyJhbGciOiJIUzI1NiJ9.test.sig';
    const result = applyStickyAuth(headers, authValue);

    assert.ok(result, 'applyStickyAuth must return an object');
    assert.equal(result.Authorization, authValue, 'Authorization header must be set to given value');
    assert.equal(result.Host, 'api.example.com', 'Other headers must be preserved');
    // Original object not mutated
    assert.equal(headers.Authorization, undefined, 'applyStickyAuth must not mutate input headers');

    // Works with Basic auth too
    const basicResult = applyStickyAuth({}, 'Basic dXNlcjpwYXNz');
    assert.ok(basicResult.Authorization.startsWith('Basic '), 'Basic auth value must be set');

    console.log('  stickyAuth: OK');
  } else {
    console.log('  stickyAuth: SKIP (not compiled)');
  }

  console.log('PASS traffic-rules-sticky');
} catch (err) {
  console.error('FAIL traffic-rules-sticky:', err.message);
  process.exit(1);
}
