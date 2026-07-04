import type { PayloadVariant } from '../types';

export const META = {
  id: 'elmah-exposure',
  family: 'lfi-traversal' as const,
  name: 'ELMAH Error Log Exposure',
  description: 'Detects exposed ELMAH (Error Logging Modules and Handlers) error log endpoint at /elmah.axd.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['path'],
};

const PROBES = [
  { value: '/elmah.axd', intent: 'Probe ELMAH root handler — exposes full ASP.NET error log', signals: ['error-log-exposed'] },
  { value: '/elmah.axd/stylesheet', intent: 'ELMAH stylesheet sub-path — confirms handler is active and serving content', signals: ['error-log-exposed'] },
  { value: '/elmah.axd?404', intent: 'ELMAH filtered view — filter by error type to confirm handler access', signals: ['error-log-exposed'] },
  { value: '/admin/elmah.axd', intent: 'ELMAH under /admin/ prefix — common alternative installation path', signals: ['error-log-exposed'] },
  { value: '/errors/elmah.axd', intent: 'ELMAH under /errors/ prefix — alternate deployment path', signals: ['error-log-exposed'] },
  { value: '/log/elmah.axd', intent: 'ELMAH under /log/ prefix — alternate logging path', signals: ['error-log-exposed'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `elmah-${i + 1}`,
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
