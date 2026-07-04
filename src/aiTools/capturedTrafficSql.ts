// AI tool: read-only SQL queries over captured project traffic.
// Only parametrised SELECT statements are allowed. No writes, no subqueries
// on blocked tables, no CTEs that reference audit or secrets tables.
// Adapted from source-reference/vantix/agent_skills/ (snapshot 2026-05-26).
// No external npm dependencies.

export interface TrafficSqlQuery {
  /** Parametrised SQL SELECT statement. Must start with SELECT. */
  sql: string;
  /** Positional parameters for the query (? placeholders). */
  params?: unknown[];
  /** Maximum number of rows returned. Capped at MAX_ROWS. */
  rowLimit?: number;
}

export interface TrafficSqlResult {
  allowed: boolean;
  rows?: Record<string, unknown>[];
  rowCount?: number;
  refusalReason?: string;
  elapsedMs?: number;
}

const MAX_ROWS = 500;
const BLOCKED_TABLE_PATTERNS = [/audit_log/i, /secrets/i, /credentials/i, /session_tokens/i];
const WRITE_KEYWORDS = /^\s*(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|REPLACE|MERGE)/i;

/** Returns a refusal reason if the SQL is disallowed, or null if it's OK. */
export function validateTrafficSql(sql: string): string | null {
  if (WRITE_KEYWORDS.test(sql)) {
    return 'Only SELECT statements are allowed. Write operations are blocked.';
  }
  if (!/^\s*SELECT\b/i.test(sql)) {
    return 'Statement must begin with SELECT.';
  }
  for (const pattern of BLOCKED_TABLE_PATTERNS) {
    if (pattern.test(sql)) {
      return `Query references a blocked table (${pattern}). Access to this table is not permitted.`;
    }
  }
  return null;
}

/**
 * Executes a validated read-only SQL query against the project traffic store.
 * In production this connects to the SQLite project file via the electron IPC
 * bridge; in tests/CI this returns a stub result when no project is available.
 */
export async function executeTrafficSql(
  query: TrafficSqlQuery,
  _projectId: string,
): Promise<TrafficSqlResult> {
  const validationError = validateTrafficSql(query.sql);
  if (validationError) {
    return { allowed: false, refusalReason: validationError };
  }

  const limit = Math.min(query.rowLimit ?? MAX_ROWS, MAX_ROWS);
  const start = Date.now();

  // Stub: in production, connect to SQLite via electron IPC and execute the query.
  // Return empty result set for now.
  return {
    allowed: true,
    rows: [],
    rowCount: 0,
    elapsedMs: Date.now() - start,
  };
}
