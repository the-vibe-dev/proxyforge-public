// Tests: mapLocal.ts — resolveMapLocal matches URL patterns and returns file content (or null).
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import { writeFileSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const require = createRequire(import.meta.url);

function tryLoad(newPath, oldPath) {
  try { return require(newPath); } catch {}
  try { return require(oldPath); } catch {}
  return null;
}

const mod = tryLoad(
  '../dist-electron/electron/traffic/rules/mapLocal.js',
  '../dist-electron/traffic/rules/mapLocal.js',
);

if (!mod) {
  console.log('SKIP: traffic/rules/mapLocal not compiled');
  process.exit(0);
}

try {
  const { resolveMapLocal } = mod;

  // Create a temporary fixture file
  const fixturePath = join(tmpdir(), 'pf-test-maplocal-fixture.json');
  const fixtureContent = JSON.stringify({ users: [{ id: 1, name: 'Alice' }] });
  writeFileSync(fixturePath, fixtureContent, 'utf8');

  try {
    // ── Matching rule returns file content ─────────────────────────────────
    const rules = [
      {
        id: 'ml-1',
        urlPattern: '/api/v1/',
        localPath: fixturePath,
        enabled: true,
      },
    ];

    const matched = resolveMapLocal('https://app.example.com/api/v1/users', rules);
    assert.ok(matched !== null, 'resolveMapLocal must return content for matching URL');
    assert.ok(Buffer.isBuffer(matched), 'resolveMapLocal must return a Buffer');
    assert.equal(matched.toString('utf8'), fixtureContent, 'Buffer content must match fixture file');

    // ── Non-matching URL returns null ──────────────────────────────────────
    const noMatch = resolveMapLocal('https://app.example.com/other/path', rules);
    assert.equal(noMatch, null, 'resolveMapLocal must return null for non-matching URL');

    // ── Disabled rule is skipped ───────────────────────────────────────────
    const disabledRules = [
      { id: 'ml-2', urlPattern: '/api/v1/', localPath: fixturePath, enabled: false },
    ];
    const skipped = resolveMapLocal('https://app.example.com/api/v1/users', disabledRules);
    assert.equal(skipped, null, 'Disabled rule must be skipped (return null)');

    // ── Multiple rules — first match wins ─────────────────────────────────
    const fixture2Path = join(tmpdir(), 'pf-test-maplocal-fixture2.json');
    writeFileSync(fixture2Path, '{"second":true}', 'utf8');
    try {
      const multiRules = [
        { id: 'ml-3a', urlPattern: '/api/v1/', localPath: fixturePath, enabled: true },
        { id: 'ml-3b', urlPattern: '/api/',    localPath: fixture2Path, enabled: true },
      ];
      const firstMatch = resolveMapLocal('https://app.example.com/api/v1/users', multiRules);
      assert.equal(firstMatch?.toString('utf8'), fixtureContent, 'First matching rule must win');
    } finally {
      try { unlinkSync(fixture2Path); } catch {}
    }

    // ── RegExp pattern also matches ────────────────────────────────────────
    const regexpRules = [
      { id: 'ml-4', urlPattern: /\/api\/v\d+\//, localPath: fixturePath, enabled: true },
    ];
    const regexpMatch = resolveMapLocal('https://app.example.com/api/v2/products', regexpRules);
    assert.ok(regexpMatch !== null, 'RegExp urlPattern must match');

    // ── Missing local file returns null (not a throw) ──────────────────────
    const missingRules = [
      { id: 'ml-5', urlPattern: '/api/', localPath: '/nonexistent/path/fixture.json', enabled: true },
    ];
    const missing = resolveMapLocal('https://app.example.com/api/data', missingRules);
    assert.equal(missing, null, 'Missing local file must return null');

  } finally {
    try { unlinkSync(fixturePath); } catch {}
  }

  console.log('PASS traffic-rules-maplocal');
} catch (err) {
  console.error('FAIL traffic-rules-maplocal:', err.message);
  process.exit(1);
}
