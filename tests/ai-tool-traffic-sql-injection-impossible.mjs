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

const { validateTrafficSql } = sql;

// 1. INSERT — blocked
{
  const result = validateTrafficSql('INSERT INTO exchanges VALUES (1, "evil", "evil")');
  assert.ok(result !== null && typeof result === 'string',
    'INSERT should be blocked (non-null string refusal)');
}

// 2. DROP TABLE — blocked
{
  const result = validateTrafficSql('DROP TABLE exchanges');
  assert.ok(result !== null && typeof result === 'string',
    'DROP TABLE should be blocked (non-null string refusal)');
}

// 3. Blocked table: audit_log — blocked
{
  const result = validateTrafficSql('SELECT * FROM audit_log');
  assert.ok(result !== null && typeof result === 'string',
    'SELECT from audit_log should be blocked (non-null string refusal)');
}

// 4. Blocked table: secrets — blocked
{
  const result = validateTrafficSql('SELECT * FROM secrets');
  assert.ok(result !== null && typeof result === 'string',
    'SELECT from secrets should be blocked (non-null string refusal)');
}

// 5. UPDATE — blocked
{
  const result = validateTrafficSql('UPDATE exchanges SET url = "evil"');
  assert.ok(result !== null && typeof result === 'string',
    'UPDATE should be blocked (non-null string refusal)');
}

// 6. DELETE — blocked
{
  const result = validateTrafficSql('DELETE FROM exchanges');
  assert.ok(result !== null && typeof result === 'string',
    'DELETE should be blocked (non-null string refusal)');
}

console.log('ai-tool-traffic-sql-injection-impossible: all tests passed');
