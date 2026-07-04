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

const { validateBrowserAction } = mod;

const IN_SCOPE = 'https://in-scope.example.com';
const IN_SCOPE_URLS = ['https://in-scope.example.com'];

// 1. Any action in safe mode — blocked with message mentioning safe mode
{
  const result = validateBrowserAction(
    { type: 'click', selector: '#btn' },
    IN_SCOPE,
    IN_SCOPE_URLS,
    'safe',
  );
  assert.ok(result !== null && typeof result === 'string',
    'click in safe mode should return non-null refusal string');
  assert.ok(
    result.toLowerCase().includes('safe'),
    `safe-mode refusal should mention 'Safe' (case-insensitive), got: "${result}"`,
  );
}

// 2. evaluate with process.env — blocked (dangerous expression)
{
  const result = validateBrowserAction(
    { type: 'evaluate', expression: 'process.env.SECRET' },
    IN_SCOPE,
    IN_SCOPE_URLS,
    'standard',
  );
  assert.ok(result !== null && typeof result === 'string',
    'evaluate process.env should return non-null refusal');
}

// 3. evaluate with require() — blocked (dangerous expression)
{
  const result = validateBrowserAction(
    { type: 'evaluate', expression: 'require("fs")' },
    IN_SCOPE,
    IN_SCOPE_URLS,
    'standard',
  );
  assert.ok(result !== null && typeof result === 'string',
    'evaluate require("fs") should return non-null refusal');
}

console.log('ai-tool-browser-drive-mode-safe-blocks: all tests passed');
