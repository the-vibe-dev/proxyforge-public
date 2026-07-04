// IDOR via predictable UUID active check family.
import type { PayloadVariant } from '../types';

export const META = {
  id: 'idor-uuid-predictable',
  family: 'idor' as const,
  name: 'IDOR (UUID / predictable ID)',
  description: 'Detects IDOR via UUID-format and sequential/predictable resource identifier substitution.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'path', 'json'],
};

const IDOR_UUID_PROBES = [
  { value: '00000000-0000-0000-0000-000000000001', intent: 'Nil UUID + 1 — minimal valid UUID', signals: ['idor-access'] },
  { value: '00000000-0000-0000-0000-000000000000', intent: 'Nil UUID — often used as system/admin account', signals: ['idor-access'] },
  { value: 'ffffffff-ffff-ffff-ffff-ffffffffffff', intent: 'Max UUID — boundary condition probe', signals: ['idor-access'] },
  { value: 'deadbeef-dead-beef-dead-beefdeadbeef', intent: 'Known-pattern UUID to detect insecure UUID generation', signals: ['idor-access'] },
  { value: '11111111-1111-1111-1111-111111111111', intent: 'Repeated-digit UUID — often test/admin account', signals: ['idor-access'] },
  { value: '00000001-0001-0001-0001-000000000001', intent: 'Sequential-style UUID for enumeration probe', signals: ['idor-access'] },
];

export function variants(): PayloadVariant[] {
  return IDOR_UUID_PROBES.map((p, i) => ({ id: `idor-uuid-${i+1}`, family: 'idor' as const, value: p.value, encoding: 'raw' as const, intent: p.intent, requiresOast: false, requiresBrowser: false, destructiveRisk: 'none' as const, expectedSignals: p.signals }));
}
