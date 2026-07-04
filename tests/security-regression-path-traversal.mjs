// Phase 18 — Security regression: path traversal prevention
// Tests that Proxy Forge's IPC path validation blocks directory traversal attacks.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function tryLoad(candidates) {
  for (const c of candidates) {
    try { return require(c); } catch { }
  }
  return null;
}

const mod = tryLoad([
  '../dist-electron/ipcContracts.js',
  '../dist-electron/electron/ipcContracts.js',
]);

assert.ok(mod, 'ipcContracts module must be loadable');

const { ipcContracts, IpcValidationError } = mod;
assert.ok(ipcContracts, 'ipcContracts export must exist');
assert.ok(IpcValidationError, 'IpcValidationError export must exist');

// ── Helper: call the projectOpen validator ─────────────────────────────────
function validatePath(rootDir) {
  return ipcContracts.projectOpen.validate({ rootDir });
}

// ── Test 1: Unix forward-slash traversal ──────────────────────────────────
{
  const payload = '/safe/dir/../../etc/passwd.proxyforge';
  let threw = false;
  try {
    validatePath(payload);
  } catch (err) {
    threw = true;
    assert.ok(
      err instanceof IpcValidationError,
      'Should throw IpcValidationError for ../ traversal',
    );
    assert.match(
      err.message,
      /path traversal/i,
      'Error message must mention path traversal',
    );
  }
  assert.ok(threw, 'Must reject path containing ../');
}

// ── Test 2: Windows backslash traversal ───────────────────────────────────
{
  const payload = 'C:\\safe\\dir\\..\\..\\Windows\\system32.proxyforge';
  let threw = false;
  try {
    validatePath(payload);
  } catch (err) {
    threw = true;
    assert.ok(err instanceof IpcValidationError, 'Should throw for ..\\ traversal');
    assert.match(err.message, /path traversal/i);
  }
  assert.ok(threw, 'Must reject path containing ..\\');
}

// ── Test 3: NUL byte injection ─────────────────────────────────────────────
{
  const payload = '/safe/project\x00/../../etc/passwd.proxyforge';
  let threw = false;
  try {
    validatePath(payload);
  } catch (err) {
    threw = true;
    assert.ok(err instanceof IpcValidationError, 'Should throw for NUL byte');
    assert.match(err.message, /NUL/i, 'Error message must mention NUL');
  }
  assert.ok(threw, 'Must reject path containing NUL byte');
}

// ── Test 4: Double-encoded %2e%2e%2f (URL decode not applied, but raw dots) ─
{
  // The validator operates on the raw string value received over IPC.
  // A path like "%2e%2e%2fmalicious" doesn't contain literal ".." segments,
  // but we verify that a decoded form would also be caught.
  const decoded = '/safe/' + decodeURIComponent('%2e%2e%2f') + 'malicious.proxyforge';
  // decoded === '/safe/../../malicious.proxyforge'
  let threw = false;
  try {
    validatePath(decoded);
  } catch (err) {
    threw = true;
    assert.ok(err instanceof IpcValidationError, 'Should throw for decoded %2e%2e%2f');
    assert.match(err.message, /path traversal/i);
  }
  assert.ok(threw, 'Must reject URL-decoded traversal path');
}

// ── Test 5: node:path join cannot escape safe base ────────────────────────
// Demonstrates that even if path.join is used naively, the validator
// would catch the input before path.join is called.
{
  const safeBase = '/home/user/projects';
  const userInput = '../../etc/passwd';
  const joined = path.join(safeBase, userInput);
  // joined === '/home/etc/passwd' — traversal succeeded at the path level.
  // Proxy Forge prevents this by rejecting inputs with '..' before path.join.
  assert.ok(
    joined !== path.join(safeBase, 'safe.proxyforge'),
    'path.join alone does not protect against traversal',
  );
  // The IPC validator would reject '../../etc/passwd' before it ever reaches path.join.
  let threw = false;
  try {
    validatePath(userInput);
  } catch (err) {
    threw = true;
    assert.ok(err instanceof IpcValidationError);
  }
  assert.ok(threw, 'IPC validator blocks the input before path.join can be called');
}

// ── Test 6: Valid project path passes ─────────────────────────────────────
{
  const valid = '/home/user/projects/myengagement.proxyforge';
  let result;
  try {
    result = validatePath(valid);
  } catch (err) {
    assert.fail(`Valid path should not throw: ${err.message}`);
  }
  assert.ok(result, 'Valid path must return a result');
  assert.equal(result.rootDir, valid, 'rootDir must be preserved on valid input');
}

console.log('PASS security-regression-path-traversal');
