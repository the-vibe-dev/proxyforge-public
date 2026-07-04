import type { PayloadVariant } from '../types';

export const META = {
  id: 'trace-axd-exposure',
  family: 'lfi-traversal' as const,
  name: 'trace.axd Request Trace Exposure',
  description: 'Detects exposed ASP.NET trace.axd request tracing handler which reveals request details, session data, and server internals.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['path'],
};

const PROBES = [
  { value: '/trace.axd', intent: 'Probe ASP.NET trace.axd root — exposes request trace history', signals: ['error-log-exposed'] },
  { value: '/Trace.axd', intent: 'Mixed-case trace.axd probe — IIS is case-insensitive', signals: ['error-log-exposed'] },
  { value: '/TRACE.axd', intent: 'Uppercase probe for case-insensitive IIS servers', signals: ['error-log-exposed'] },
  { value: '/trace.axd?id=1', intent: 'trace.axd with request ID — fetches individual traced request details', signals: ['error-log-exposed'] },
  { value: '/admin/trace.axd', intent: 'trace.axd under /admin/ prefix — alternate installation path', signals: ['error-log-exposed'] },
  { value: '/trace.axd/clear', intent: 'trace.axd clear sub-path — confirms write access to trace handler', signals: ['error-log-exposed', 'write-access'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `trace-axd-${i + 1}`,
    family: 'lfi-traversal' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
