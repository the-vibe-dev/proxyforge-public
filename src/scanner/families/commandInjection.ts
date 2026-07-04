// Command injection active check family.
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant } from '../types';

export const META = {
  id: 'command-injection',
  family: 'command-injection' as const,
  name: 'Command Injection',
  description: 'Detects OS command injection via shell metacharacter probes.',
  defaultRisk: 'low' as const,
  insertionPointKinds: ['query', 'body', 'json', 'header', 'path'],
};

const CMD_PROBES = [
  { value: '; id', intent: 'Semicolon separator + id command', signals: ['command-output'] },
  { value: '| id', intent: 'Pipe operator + id command', signals: ['command-output'] },
  { value: '`id`', intent: 'Backtick command substitution', signals: ['command-output'] },
  { value: '$(id)', intent: '$() command substitution', signals: ['command-output'] },
  { value: '; sleep 5', intent: 'Time-based blind injection via sleep', signals: ['timing-delta'] },
  { value: '| sleep 5', intent: 'Pipe-based time-based blind injection', signals: ['timing-delta'] },
  { value: '& ping -c 5 127.0.0.1 &', intent: 'Background ping for time-based detection', signals: ['timing-delta'] },
  { value: '1; sleep 5 #', intent: 'Hash-commented sleep for shell blinds', signals: ['timing-delta'] },
  { value: '; whoami', intent: 'whoami command to reveal execution context', signals: ['command-output'] },
  { value: '|| id', intent: 'OR operator command injection', signals: ['command-output'] },
];

export function variants(): PayloadVariant[] {
  return CMD_PROBES.map((probe, i) => ({
    id: `cmd-${i + 1}`,
    family: 'command-injection' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
