import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);

let mod;
try {
  mod = require('../dist-electron/electron/openProjectFolder.js');
} catch {
  console.log('SKIP: openProjectFolder not compiled — run tsc first.');
  process.exit(0);
}

const { validateProjectFolderPath } = mod;

// 1. /etc/passwd is outside the allowed root — blocked
{
  const result = validateProjectFolderPath('/etc/passwd', '/home/user/.proxyforge');
  assert.strictEqual(result.allowed, false,
    '/etc/passwd should be blocked (outside allowed root)');
}

// 2. Path inside allowed root — allowed if it exists, blocked with "does not exist" if not
{
  const allowedRoot = '/home/user/.proxyforge';
  const targetPath = '/home/user/.proxyforge/project1';
  const result = validateProjectFolderPath(targetPath, allowedRoot);
  if (fs.existsSync(targetPath)) {
    assert.strictEqual(result.allowed, true,
      'existing path inside allowed root should be allowed');
  } else {
    assert.strictEqual(result.allowed, false,
      'non-existent path inside allowed root should be blocked');
    assert.ok(result.reason && /does not exist/i.test(result.reason),
      `reason should mention "does not exist", got: "${result.reason}"`);
  }
}

// 3. Path traversal attack — blocked (resolves outside allowed root)
{
  const result = validateProjectFolderPath(
    '/home/user/.proxyforge/../../../etc',
    '/home/user/.proxyforge',
  );
  assert.strictEqual(result.allowed, false,
    'path traversal (/../../../etc) should be blocked');
}

// 4. Happy path using os.tmpdir() as allowed root with a real temp directory
{
  const tmpRoot = os.tmpdir();
  const tempDir = fs.mkdtempSync(path.join(tmpRoot, 'pf-whitelist-test-'));
  try {
    const result = validateProjectFolderPath(tempDir, tmpRoot);
    assert.strictEqual(result.allowed, true,
      'existing temp dir inside os.tmpdir() should be allowed');
    assert.strictEqual(result.resolvedPath, path.resolve(tempDir),
      'resolvedPath should equal the resolved temp dir');
  } finally {
    fs.rmdirSync(tempDir);
  }
}

console.log('open-project-folder-whitelist-guard: all tests passed');
