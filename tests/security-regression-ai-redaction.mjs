// Phase 18 — Security regression: AI handoff boundary redaction
// Tests that sensitive values (authorization headers, bearer tokens, cookies,
// API keys, AWS keys) are detected and blocked from AI export, using the
// redactionInvariantTemplate and the underlying PII-pattern engine.
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

// ── Load the redaction invariant verifier ────────────────────────────────
const redactionMod = tryLoad([
  '../dist-electron/src/exploitTemplates/redactionInvariant.js',
]);
assert.ok(redactionMod, 'redactionInvariant module must be loadable');

const { redactionInvariantTemplate } = redactionMod;
assert.ok(redactionInvariantTemplate, 'redactionInvariantTemplate must be exported');
assert.ok(typeof redactionInvariantTemplate.validate === 'function', 'validate must be a function');

// ── Helper: run the invariant check ──────────────────────────────────────
function check(exportedContent, sensitiveValues = [], expectedRedactionMarkers = []) {
  return redactionInvariantTemplate.validate(
    {
      evidence: {
        exportedContent,
        sensitiveValues,
        expectedRedactionMarkers,
        exportFormat: 'json',
      },
    },
    { exchangeId: 'ex-test' },
  );
}

// ── Test 1: Bearer token leaks are detected ──────────────────────────────
{
  const content = JSON.stringify({
    request: 'GET /api/user HTTP/1.1',
    headers: { authorization: 'Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature' },
  });
  const result = check(content, [], []);
  assert.ok(
    result.valid === false,
    'Bearer token in export must be flagged as a redaction violation',
  );
  assert.ok(
    result.evidence.some((line) => /bearer token/i.test(line)),
    'Evidence must mention "bearer token"',
  );
}

// ── Test 2: Authorization header verbatim value is blocked ────────────────
{
  const SECRET_VALUE = 'Basic dXNlcjpwYXNzd29yZA=='; // base64(user:password)
  const content = `Authorization: ${SECRET_VALUE}\r\nContent-Type: application/json`;
  const result = check(content, [SECRET_VALUE], ['[REDACTED]']);
  assert.ok(
    result.valid === false,
    'Verbatim sensitive value in export must fail the invariant',
  );
  assert.ok(
    result.evidence.some((line) => /LEAK/i.test(line)),
    'Evidence must contain a LEAK entry for the verbatim sensitive value',
  );
}

// ── Test 3: AWS access key is flagged ─────────────────────────────────────
{
  const content = 'Found credential: AKIAIOSFODNN7EXAMPLE in response body';
  const result = check(content);
  assert.ok(
    result.valid === false,
    'AWS access key in export must fail the redaction invariant',
  );
  assert.ok(
    result.evidence.some((line) => /AWS access key/i.test(line)),
    'Evidence must mention "AWS access key"',
  );
}

// ── Test 4: Cookie header with session token is blocked ───────────────────
{
  const SESSION = 'session_token_super_secret_abc123def456';
  const content = `Set-Cookie: session=${SESSION}; HttpOnly; Secure`;
  // The cookie value itself is a verbatim sensitive value
  const result = check(content, [SESSION], []);
  assert.ok(
    result.valid === false,
    'Verbatim session cookie in export must fail the invariant',
  );
}

// ── Test 5: API key pattern is detected ───────────────────────────────────
{
  const content = 'config: { api_key: abc123xyz987, endpoint: "https://api.example.com" }';
  const result = check(content);
  assert.ok(
    result.valid === false,
    'API key pattern in export must fail the redaction invariant',
  );
  assert.ok(
    result.evidence.some((line) => /API key/i.test(line)),
    'Evidence must mention "API key"',
  );
}

// ── Test 6: GitHub token is detected ─────────────────────────────────────
{
  const ghToken = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ab';
  const content = `Authorization: token ${ghToken}`;
  const result = check(content);
  assert.ok(
    result.valid === false,
    'GitHub token in export must fail the redaction invariant',
  );
  assert.ok(
    result.evidence.some((line) => /GitHub token/i.test(line)),
    'Evidence must mention "GitHub token"',
  );
}

// ── Test 7: Properly redacted content passes ──────────────────────────────
{
  const redactedContent = JSON.stringify({
    request: 'GET /api/user HTTP/1.1',
    headers: { authorization: '[REDACTED]', cookie: '[REDACTED]' },
    body: 'No sensitive data here',
  });
  const result = check(redactedContent, [], ['[REDACTED]']);
  assert.ok(
    result.valid === true,
    'Content with redaction markers and no PII must pass the invariant (got violations: ' +
      result.evidence.filter((l) => /LEAK|PII/.test(l)).join('; ') + ')',
  );
  assert.ok(
    result.evidence.some((line) => /Redaction markers present/i.test(line)),
    'Evidence must confirm redaction markers were found',
  );
}

// ── Test 8: Clean content with no sensitive data passes ──────────────────
{
  const safeContent = JSON.stringify({
    method: 'GET',
    path: '/api/public/status',
    status: 200,
    body: '{"status":"ok"}',
  });
  const result = check(safeContent, [], []);
  assert.ok(
    result.valid === true,
    'Content with no PII and no registered sensitive values must pass (violations: ' +
      result.evidence.filter((l) => /LEAK|PII|NO REDACTION/.test(l)).join('; ') + ')',
  );
}

// ── Test 9: Private key header is detected ────────────────────────────────
{
  const content = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...';
  const result = check(content);
  assert.ok(
    result.valid === false,
    'Private key header in export must fail the redaction invariant',
  );
  assert.ok(
    result.evidence.some((line) => /private key/i.test(line)),
    'Evidence must mention "private key"',
  );
}

// ── Test 10: IPC boundary — ai:run context is size-capped ─────────────────
// The IPC layer enforces that AI context exchanges are capped at aiContextExchanges (12)
// and raw request/response at rawTextBytes (10 MB), preventing credential-stuffed
// 100-exchange dumps from reaching the AI provider.
{
  const ipcMod = tryLoad([
    '../dist-electron/ipcContracts.js',
    '../dist-electron/electron/ipcContracts.js',
  ]);
  assert.ok(ipcMod, 'ipcContracts must be loadable for boundary test');

  const { ipcContracts, IpcValidationError, IPC_LIMITS } = ipcMod;

  // Build 13 exchanges (over the 12-exchange AI context limit)
  const exchange = {
    method: 'GET',
    host: 'example.com',
    path: '/api/secret',
    status: 200,
    risk: 'low',
    notes: '',
    requestRaw: 'GET /api/secret HTTP/1.1\r\nAuthorization: Bearer secret-token\r\n\r\n',
    responseRaw: 'HTTP/1.1 200 OK\r\n\r\n{"data":"ok"}',
    tags: [],
  };

  let threw = false;
  try {
    ipcContracts.aiRun.validate({
      providerId: 'codex',
      task: 'triage',
      prompt: 'Analyze this traffic',
      context: {
        projectName: 'Test',
        scopeAllowlist: ['https://example.com'],
        taskHint: 'triage',
        exchanges: Array(IPC_LIMITS.aiContextExchanges + 1).fill(exchange),
        issues: [],
      },
    });
  } catch (err) {
    threw = true;
    assert.ok(
      err instanceof IpcValidationError,
      'Oversized exchange list must throw IpcValidationError',
    );
  }
  assert.ok(threw, `AI context must cap at ${IPC_LIMITS.aiContextExchanges} exchanges`);
}

console.log('PASS security-regression-ai-redaction');
