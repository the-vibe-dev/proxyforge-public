import { createRequire } from 'node:module';
import assert from 'node:assert/strict';

const require = createRequire(import.meta.url);

let sql;
try {
  sql = require('../dist-electron/src/aiTools/capturedTrafficSql.js');
} catch {
  console.log('SKIP: capturedTrafficSql not compiled — run tsc first.');
  process.exit(0);
}

let registry;
try {
  registry = require('../dist-electron/src/aiTools/index.js');
} catch {
  console.log('SKIP: aiTools/index not compiled — run tsc first.');
  process.exit(0);
}

const { validateTrafficSql, executeTrafficSql } = sql;
const { isToolAllowed } = registry;

// 1. SELECT * FROM exchanges LIMIT 10 — allowed
{
  const result = validateTrafficSql('SELECT * FROM exchanges LIMIT 10');
  assert.strictEqual(result, null, 'SELECT * FROM exchanges LIMIT 10 should be allowed (null)');
}

// 2. SELECT url FROM exchanges — allowed
{
  const result = validateTrafficSql('SELECT url FROM exchanges');
  assert.strictEqual(result, null, 'SELECT url FROM exchanges should be allowed (null)');
}

// 3. isToolAllowed standard mode + operator-enabled = true
{
  const allowed = isToolAllowed('captured-traffic-sql', 'standard', true);
  assert.strictEqual(allowed, true, 'captured-traffic-sql should be allowed in standard mode with operator enabled');
}

// 4. isToolAllowed safe mode = false regardless of operator flag
{
  const allowed = isToolAllowed('captured-traffic-sql', 'safe', true);
  assert.strictEqual(allowed, false, 'captured-traffic-sql should be blocked in safe mode');
}

// 5. executeTrafficSql resolves to { allowed: true, rows: Array, rowCount: number }
{
  const result = await executeTrafficSql({ sql: 'SELECT 1', rowLimit: 5 }, 'proj-1');
  assert.strictEqual(result.allowed, true, 'executeTrafficSql should return allowed: true for valid SELECT');
  assert.ok(Array.isArray(result.rows), 'executeTrafficSql result.rows should be an Array');
  assert.strictEqual(typeof result.rowCount, 'number', 'executeTrafficSql result.rowCount should be a number');
}

console.log('ai-tool-traffic-sql-readonly: all tests passed');
