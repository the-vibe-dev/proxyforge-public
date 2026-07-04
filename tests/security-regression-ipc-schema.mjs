// Phase 18 — Security regression: IPC parameter validation
// Tests that ipcContracts.validate() rejects malformed payloads and accepts
// valid ones, covering multiple channels.
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

const { ipcContracts, IpcValidationError, IPC_LIMITS } = mod;

// ── Helpers ────────────────────────────────────────────────────────────────
function mustThrow(contract, payload, description) {
  let threw = false;
  try {
    contract.validate(payload);
  } catch (err) {
    threw = true;
    assert.ok(
      err instanceof IpcValidationError,
      `${description}: error should be IpcValidationError, got ${err.constructor.name}: ${err.message}`,
    );
  }
  assert.ok(threw, `${description}: should have thrown IpcValidationError`);
}

function mustPass(contract, payload, description) {
  try {
    return contract.validate(payload);
  } catch (err) {
    assert.fail(`${description}: unexpected rejection — ${err.message}`);
  }
}

// ── project:open ──────────────────────────────────────────────────────────
{
  const c = ipcContracts.projectOpen;

  // Missing rootDir
  mustThrow(c, {}, 'project:open — missing rootDir');

  // Path traversal in rootDir
  mustThrow(c, { rootDir: '../../etc/shadow.proxyforge' }, 'project:open — traversal in rootDir');

  // NUL byte in rootDir
  mustThrow(c, { rootDir: '/projects/ok\x00bad.proxyforge' }, 'project:open — NUL in rootDir');

  // Wrong suffix
  mustThrow(c, { rootDir: '/projects/myproject.txt' }, 'project:open — bad suffix');

  // Extra / unknown keys
  mustThrow(c, { rootDir: '/proj/ok.proxyforge', __proto__: null, sqlInjection: "'; DROP TABLE--" }, 'project:open — extra keys rejected');

  // Valid payload
  mustPass(c, { rootDir: '/home/user/projects/myproject.proxyforge' }, 'project:open — valid');
}

// ── project:create ────────────────────────────────────────────────────────
{
  const c = ipcContracts.projectCreate;

  // Extra unknown key with injection content
  mustThrow(
    c,
    { projectName: 'Test', extraKey: 'ignored; SELECT * FROM users;--' },
    'project:create — unknown keys rejected',
  );

  // Valid minimal payload (all optional)
  mustPass(c, {}, 'project:create — empty payload (all optional)');

  // rootDir with traversal
  mustThrow(
    c,
    { rootDir: '../../etc/passwd.proxyforge' },
    'project:create — traversal in rootDir',
  );
}

// ── ai:run ────────────────────────────────────────────────────────────────
{
  const c = ipcContracts.aiRun;

  // Missing required fields
  mustThrow(c, {}, 'ai:run — empty payload');
  mustThrow(c, { providerId: 'codex' }, 'ai:run — missing task/prompt/context');

  // Invalid providerId enum
  mustThrow(
    c,
    {
      providerId: 'malicious-provider',
      task: 'triage',
      prompt: 'hello',
      context: {
        projectName: 'Test',
        scopeAllowlist: ['https://example.com'],
        taskHint: 'triage traffic',
        exchanges: [],
        issues: [],
      },
    },
    'ai:run — invalid providerId enum',
  );

  // Invalid task enum
  mustThrow(
    c,
    {
      providerId: 'codex',
      task: 'drop-database',
      prompt: 'pwn everything',
      context: {
        projectName: 'Test',
        scopeAllowlist: ['https://example.com'],
        taskHint: 'triage traffic',
        exchanges: [],
        issues: [],
      },
    },
    'ai:run — invalid task enum',
  );

  // Prompt exceeding rawTextBytes limit
  const bigPrompt = 'A'.repeat(IPC_LIMITS.rawTextBytes + 1);
  mustThrow(
    c,
    {
      providerId: 'codex',
      task: 'triage',
      prompt: bigPrompt,
      context: {
        projectName: 'Test',
        scopeAllowlist: ['https://example.com'],
        taskHint: 'hint',
        exchanges: [],
        issues: [],
      },
    },
    'ai:run — oversized prompt rejected',
  );

  // Extra unknown key in context
  mustThrow(
    c,
    {
      providerId: 'codex',
      task: 'triage',
      prompt: 'safe prompt',
      context: {
        projectName: 'Test',
        scopeAllowlist: ['https://example.com'],
        taskHint: 'hint',
        exchanges: [],
        issues: [],
        __extra__: "'; DROP TABLE exchanges;--",
      },
    },
    'ai:run — unknown key in context rejected',
  );

  // Valid ai:run request
  const valid = mustPass(
    c,
    {
      providerId: 'claude',
      task: 'report-draft',
      prompt: 'Draft a finding narrative for the XSS in /search.',
      context: {
        projectName: 'MyEngagement',
        scopeAllowlist: ['https://target.example.com'],
        taskHint: 'report-draft',
        exchanges: [],
        issues: [],
      },
    },
    'ai:run — valid payload',
  );
  assert.equal(valid.providerId, 'claude', 'providerId preserved');
  assert.equal(valid.task, 'report-draft', 'task preserved');
}

// ── repeater:send ─────────────────────────────────────────────────────────
{
  const c = ipcContracts.repeaterSend;

  // Missing rawRequest
  mustThrow(c, { targetUrl: 'https://example.com', scopeAllowlist: [] }, 'repeater:send — missing rawRequest');

  // Non-HTTP targetUrl
  mustThrow(
    c,
    {
      rawRequest: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
      targetUrl: 'ftp://evil.com',
      scopeAllowlist: ['https://example.com'],
      settings: { redirectMode: 'manual', maxRedirects: 5, connectionMode: 'default', timeoutMs: 5000 },
    },
    'repeater:send — ftp:// targetUrl rejected',
  );

  // Extra injection field
  mustThrow(
    c,
    {
      rawRequest: 'GET / HTTP/1.1\r\nHost: example.com\r\n\r\n',
      targetUrl: 'https://example.com',
      scopeAllowlist: ['https://example.com'],
      settings: { redirectMode: 'manual', maxRedirects: 5, connectionMode: 'default', timeoutMs: 5000 },
      __sql__: 'DROP TABLE--',
    },
    'repeater:send — extra unknown field rejected',
  );
}

// ── scanner:run-active ────────────────────────────────────────────────────
{
  const c = ipcContracts.scannerRunActive;

  // Empty payload
  mustThrow(c, {}, 'scanner:run-active — empty payload');

  // Unknown check IDs
  mustThrow(
    c,
    {
      checkIds: ['../../../etc/malicious'],
      exchanges: [],
      scopeAllowlist: [],
      insertionPoints: [],
    },
    'scanner:run-active — unknown check IDs rejected',
  );
}

console.log('PASS security-regression-ipc-schema');
