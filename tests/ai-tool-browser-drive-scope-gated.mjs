import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let mod;
try {
  mod = require('../dist-electron/src/aiTools/managedBrowserDrive.js');
} catch {
  console.log('SKIP: managedBrowserDrive not compiled — run tsc first.');
  process.exit(0);
}

const { validateBrowserAction, executeBrowserAction } = mod;

const IN_SCOPE = 'https://in-scope.example.com';
const IN_SCOPE_URLS = ['https://in-scope.example.com'];

// 1. Navigate to out-of-scope URL — blocked
{
  const result = validateBrowserAction(
    { type: 'navigate', url: 'https://evil.com/page' },
    IN_SCOPE,
    IN_SCOPE_URLS,
    'standard',
  );
  assert.ok(result !== null && typeof result === 'string',
    'navigate to out-of-scope URL should return non-null refusal');
}

// 2. Click on in-scope page — allowed
{
  const result = validateBrowserAction(
    { type: 'click', selector: '#btn' },
    `${IN_SCOPE}/page`,
    IN_SCOPE_URLS,
    'standard',
  );
  assert.strictEqual(result, null, 'click on in-scope page should be allowed (null)');
}

// 3. Safe evaluate expression (document.title) — allowed
{
  const result = validateBrowserAction(
    { type: 'evaluate', expression: 'document.title' },
    IN_SCOPE,
    IN_SCOPE_URLS,
    'standard',
  );
  assert.strictEqual(result, null, 'evaluate document.title should be allowed (null)');
}

// 4. executeBrowserAction resolves to { allowed: true, actionType: string }
{
  const request = {
    projectId: 'proj-1',
    sessionId: 'sess-1',
    action: { type: 'click', selector: '#submit' },
    currentUrl: IN_SCOPE,
    inScopeUrls: IN_SCOPE_URLS,
  };
  const result = await executeBrowserAction(request, 'standard');
  assert.strictEqual(result.allowed, true, 'executeBrowserAction should return allowed: true');
  assert.strictEqual(typeof result.actionType, 'string', 'executeBrowserAction result.actionType should be a string');
}

console.log('ai-tool-browser-drive-scope-gated: all tests passed');
