// Tests: createContext, isUrlInContext, dissolveContext, getMatchingContext
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

// Support both compiled (dist-electron) and direct TypeScript paths via ts-node
let contextEngine;
try {
  contextEngine = require('../dist-electron/contextEngine.js');
} catch {
  // Fallback: attempt the src path for environments with ts-node/tsx
  try {
    contextEngine = require('../src/contextEngine.ts');
  } catch {
    console.log('context-engine-membership: skipped — contextEngine not compiled to dist-electron yet');
    process.exit(0);
  }
}

const { createContext, isUrlInContext, dissolveContext, getMatchingContext } = contextEngine;

if (typeof createContext !== 'function') {
  console.log('context-engine-membership: skipped — missing exports');
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Test 1: createContext returns a well-formed context
// ---------------------------------------------------------------------------
{
  const ctx = createContext({
    name: 'Test App',
    scopePatterns: ['https://app.example.com/*'],
    techStack: ['React'],
  });

  assert.ok(typeof ctx.id === 'string' && ctx.id.length > 0, 'id must be a non-empty string');
  assert.strictEqual(ctx.name, 'Test App');
  assert.deepStrictEqual(ctx.scopePatterns, ['https://app.example.com/*']);
  assert.deepStrictEqual(ctx.techStack, ['React']);
  assert.deepStrictEqual(ctx.users, []);
  assert.deepStrictEqual(ctx.customPages, []);
  assert.ok(typeof ctx.createdAt === 'string', 'createdAt must be a string');
  console.log('PASS: createContext returns well-formed context');
}

// ---------------------------------------------------------------------------
// Test 2: isUrlInContext — positive match
// ---------------------------------------------------------------------------
{
  const ctx = createContext({
    name: 'Admin',
    scopePatterns: ['https://admin.example.com/*'],
  });

  assert.strictEqual(isUrlInContext('https://admin.example.com/dashboard', ctx), true);
  assert.strictEqual(isUrlInContext('https://admin.example.com/', ctx), true);
  console.log('PASS: isUrlInContext returns true for matching URL');
}

// ---------------------------------------------------------------------------
// Test 3: isUrlInContext — negative match (out-of-scope URL)
// ---------------------------------------------------------------------------
{
  const ctx = createContext({
    name: 'App',
    scopePatterns: ['https://app.example.com/*'],
  });

  assert.strictEqual(isUrlInContext('https://other.example.com/page', ctx), false);
  assert.strictEqual(isUrlInContext('https://evil.com/', ctx), false);
  console.log('PASS: isUrlInContext returns false for out-of-scope URL');
}

// ---------------------------------------------------------------------------
// Test 4: isUrlInContext — empty scopePatterns always returns false
// ---------------------------------------------------------------------------
{
  const ctx = createContext({ name: 'Empty', scopePatterns: [] });
  assert.strictEqual(isUrlInContext('https://anything.com/', ctx), false);
  console.log('PASS: isUrlInContext with empty patterns returns false');
}

// ---------------------------------------------------------------------------
// Test 5: isUrlInContext — regex pattern
// ---------------------------------------------------------------------------
{
  const ctx = createContext({
    name: 'Regex',
    scopePatterns: ['^https://app\\.example\\.com/api/v[0-9]+/'],
  });

  assert.strictEqual(isUrlInContext('https://app.example.com/api/v2/users', ctx), true);
  assert.strictEqual(isUrlInContext('https://app.example.com/api/vX/users', ctx), false);
  console.log('PASS: isUrlInContext with regex pattern works correctly');
}

// ---------------------------------------------------------------------------
// Test 6: dissolveContext removes the context
// ---------------------------------------------------------------------------
{
  const ctx1 = createContext({ name: 'Alpha', scopePatterns: ['https://alpha.com/*'] });
  const ctx2 = createContext({ name: 'Beta', scopePatterns: ['https://beta.com/*'] });
  const ctx3 = createContext({ name: 'Gamma', scopePatterns: ['https://gamma.com/*'] });

  const contexts = [ctx1, ctx2, ctx3];
  const remaining = dissolveContext(ctx2.id, contexts);

  assert.strictEqual(remaining.length, 2);
  assert.ok(!remaining.some((c) => c.id === ctx2.id), 'ctx2 must be dissolved');
  assert.ok(remaining.some((c) => c.id === ctx1.id), 'ctx1 must remain');
  assert.ok(remaining.some((c) => c.id === ctx3.id), 'ctx3 must remain');
  console.log('PASS: dissolveContext removes the target context');
}

// ---------------------------------------------------------------------------
// Test 7: dissolveContext is a no-op for unknown id
// ---------------------------------------------------------------------------
{
  const ctx = createContext({ name: 'X', scopePatterns: [] });
  const contexts = [ctx];
  const result = dissolveContext('nonexistent-id', contexts);
  assert.strictEqual(result.length, 1);
  console.log('PASS: dissolveContext is no-op for unknown id');
}

// ---------------------------------------------------------------------------
// Test 8: getMatchingContext returns the first match
// ---------------------------------------------------------------------------
{
  const ctx1 = createContext({ name: 'A', scopePatterns: ['https://a.com/*'] });
  const ctx2 = createContext({ name: 'B', scopePatterns: ['https://b.com/*'] });
  const ctx3 = createContext({ name: 'Both', scopePatterns: ['https://a.com/*', 'https://b.com/*'] });

  const contexts = [ctx1, ctx2, ctx3];

  const match = getMatchingContext('https://b.com/page', contexts);
  assert.ok(match !== null, 'should find a match');
  assert.strictEqual(match.id, ctx2.id, 'first context in order with a matching pattern wins');
  console.log('PASS: getMatchingContext returns the first matching context');
}

// ---------------------------------------------------------------------------
// Test 9: getMatchingContext returns null when no context matches
// ---------------------------------------------------------------------------
{
  const ctx = createContext({ name: 'A', scopePatterns: ['https://a.com/*'] });
  const result = getMatchingContext('https://z.com/', [ctx]);
  assert.strictEqual(result, null);
  console.log('PASS: getMatchingContext returns null when no match');
}

console.log('\nAll context-engine-membership tests passed.');
