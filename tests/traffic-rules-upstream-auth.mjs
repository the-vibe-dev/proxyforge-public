// Tests: upstreamAuth.ts — applyUpstreamAuth injects Proxy-Authorization for upstream proxy chains.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

function tryLoad(newPath, oldPath) {
  try { return require(newPath); } catch {}
  try { return require(oldPath); } catch {}
  return null;
}

const mod = tryLoad(
  '../dist-electron/electron/traffic/rules/upstreamAuth.js',
  '../dist-electron/traffic/rules/upstreamAuth.js',
);

if (!mod) {
  console.log('SKIP: traffic/rules/upstreamAuth not compiled');
  process.exit(0);
}

try {
  const { applyUpstreamAuth } = mod;

  // ── Basic credentials are base64-encoded into Proxy-Authorization ────────
  const headers = { Host: 'proxy.example.com' };
  const result = applyUpstreamAuth(headers, 'user:pass');

  assert.ok(result, 'applyUpstreamAuth must return an object');
  assert.ok(result['Proxy-Authorization'], 'applyUpstreamAuth must add Proxy-Authorization header');
  assert.ok(
    result['Proxy-Authorization'].startsWith('Basic '),
    `Proxy-Authorization must start with 'Basic '. Got: ${result['Proxy-Authorization']}`,
  );

  // Verify the base64 payload decodes correctly
  const encoded = result['Proxy-Authorization'].slice('Basic '.length);
  const decoded = Buffer.from(encoded, 'base64').toString('utf8');
  assert.equal(decoded, 'user:pass', `Decoded credentials must be 'user:pass'. Got: ${decoded}`);

  // ── Original headers are preserved ────────────────────────────────────────
  assert.equal(result.Host, 'proxy.example.com', 'applyUpstreamAuth must preserve other headers');

  // ── Original object not mutated ────────────────────────────────────────────
  assert.equal(headers['Proxy-Authorization'], undefined, 'applyUpstreamAuth must not mutate input headers');

  // ── Works with empty initial headers ─────────────────────────────────────
  const emptyResult = applyUpstreamAuth({}, 'admin:secret');
  assert.ok(emptyResult['Proxy-Authorization'], 'Must add Proxy-Authorization to empty headers');
  const emptyDecoded = Buffer.from(emptyResult['Proxy-Authorization'].slice(6), 'base64').toString('utf8');
  assert.equal(emptyDecoded, 'admin:secret', 'Decoded credentials must match');

  // ── Credentials with colon in password ────────────────────────────────────
  const colonResult = applyUpstreamAuth({}, 'user:p:a:s:s');
  const colonDecoded = Buffer.from(colonResult['Proxy-Authorization'].slice(6), 'base64').toString('utf8');
  assert.equal(colonDecoded, 'user:p:a:s:s', 'Must handle passwords containing colons');

  // ── createUpstreamAuthRule / applyUpstreamAuthRule (if exported) ──────────
  if (typeof mod.createUpstreamAuthRule === 'function' && typeof mod.applyUpstreamAuthRule === 'function') {
    const { createUpstreamAuthRule, applyUpstreamAuthRule } = mod;

    // Basic rule
    const basicRule = createUpstreamAuthRule({ type: 'basic', username: 'user', password: 'pass' });
    assert.ok(basicRule, 'createUpstreamAuthRule must return a rule');

    const basicHeaders = {};
    const appliedBasic = applyUpstreamAuthRule(basicRule, basicHeaders);
    assert.ok(
      appliedBasic['Authorization'] || appliedBasic['Proxy-Authorization'],
      'applyUpstreamAuthRule must add an auth header',
    );
    const basicAuthHeader = appliedBasic['Authorization'] ?? appliedBasic['Proxy-Authorization'];
    assert.ok(
      basicAuthHeader.startsWith('Basic '),
      `Basic rule must produce a 'Basic ...' header. Got: ${basicAuthHeader}`,
    );

    // Bearer rule
    const bearerRule = createUpstreamAuthRule({ type: 'bearer', token: 'mytoken' });
    assert.ok(bearerRule, 'createUpstreamAuthRule (bearer) must return a rule');

    const bearerHeaders = {};
    const appliedBearer = applyUpstreamAuthRule(bearerRule, bearerHeaders);
    const bearerAuthHeader = appliedBearer['Authorization'] ?? appliedBearer['Proxy-Authorization'];
    assert.ok(
      bearerAuthHeader && bearerAuthHeader.includes('mytoken'),
      `Bearer rule must include token in auth header. Got: ${bearerAuthHeader}`,
    );
  }

  console.log('PASS traffic-rules-upstream-auth');
} catch (err) {
  console.error('FAIL traffic-rules-upstream-auth:', err.message);
  process.exit(1);
}
