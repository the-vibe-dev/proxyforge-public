// Tests: proxyAuth.ts — validateProxyAuth checks Proxy-Authorization headers.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

function tryLoad(newPath, oldPath) {
  try { return require(newPath); } catch {}
  try { return require(oldPath); } catch {}
  return null;
}

const mod = tryLoad(
  '../dist-electron/electron/traffic/rules/proxyAuth.js',
  '../dist-electron/traffic/rules/proxyAuth.js',
);

if (!mod) {
  console.log('SKIP: traffic/rules/proxyAuth not compiled');
  process.exit(0);
}

try {
  const { validateProxyAuth } = mod;

  // Helper: build a Basic auth header value from user:pass
  function buildBasicHeader(username, password) {
    const encoded = Buffer.from(`${username}:${password}`).toString('base64');
    return `Basic ${encoded}`;
  }

  // ── Valid credentials are accepted ────────────────────────────────────────
  const header = buildBasicHeader('user', 'pass');
  assert.equal(
    validateProxyAuth(header, 'user:pass'),
    true,
    'validateProxyAuth must return true for correct credentials',
  );

  // ── Wrong password is rejected ────────────────────────────────────────────
  const wrongHeader = buildBasicHeader('user', 'wrong');
  assert.equal(
    validateProxyAuth(wrongHeader, 'user:pass'),
    false,
    'validateProxyAuth must return false for wrong password',
  );

  // ── Missing header is rejected ────────────────────────────────────────────
  assert.equal(
    validateProxyAuth(undefined, 'user:pass'),
    false,
    'validateProxyAuth must return false when header is undefined',
  );
  assert.equal(
    validateProxyAuth('', 'user:pass'),
    false,
    'validateProxyAuth must return false for empty header',
  );

  // ── Non-Basic scheme is rejected ───────────────────────────────────────────
  assert.equal(
    validateProxyAuth('Bearer sometoken', 'user:pass'),
    false,
    'validateProxyAuth must return false for Bearer scheme',
  );

  // ── Case-insensitive Basic match ──────────────────────────────────────────
  const lowerBasicHeader = `basic ${Buffer.from('user:pass').toString('base64')}`;
  assert.equal(
    validateProxyAuth(lowerBasicHeader, 'user:pass'),
    true,
    'validateProxyAuth must accept lowercase "basic" scheme',
  );

  // ── Credentials with colon in password work ────────────────────────────────
  const colonPassHeader = buildBasicHeader('admin', 'p:a:s:s');
  assert.equal(
    validateProxyAuth(colonPassHeader, 'admin:p:a:s:s'),
    true,
    'validateProxyAuth must handle passwords containing colons',
  );

  // ── buildProxyAuthHeader helper (if exported) ─────────────────────────────
  if (typeof mod.buildProxyAuthHeader === 'function') {
    const builtHeader = mod.buildProxyAuthHeader({ username: 'user', password: 'pass' });
    assert.ok(
      typeof builtHeader === 'string' && builtHeader.startsWith('Basic '),
      `buildProxyAuthHeader must return a string starting with 'Basic '. Got: ${builtHeader}`,
    );
  }

  console.log('PASS traffic-rules-proxyauth');
} catch (err) {
  console.error('FAIL traffic-rules-proxyauth:', err.message);
  process.exit(1);
}
