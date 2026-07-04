import type { PayloadVariant } from '../types';

export const META = {
  id: 'http-parameter-override',
  family: 'mass-assignment' as const,
  name: 'HTTP Method/Parameter Override',
  description: 'Tests HTTP method override via _method parameter and X-HTTP-Method-Override / X-Method-Override headers.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['body', 'header', 'query'],
};

const PROBES = [
  { value: '_method=DELETE', intent: 'Body param override — Rails/Laravel _method=DELETE converts POST to DELETE', signals: ['method-override-accepted'] },
  { value: 'X-HTTP-Method-Override: DELETE', intent: 'Header override — Node/Express honor X-HTTP-Method-Override for DELETE', signals: ['method-override-accepted'] },
  { value: 'X-Method-Override: PUT', intent: 'Header override — alternate header name X-Method-Override for PUT', signals: ['method-override-accepted'] },
  { value: '_method=PUT', intent: 'Body param override converting POST to PUT for resource update', signals: ['method-override-accepted'] },
  { value: 'X-HTTP-Method-Override: PATCH', intent: 'Header override converting POST to PATCH', signals: ['method-override-accepted'] },
  { value: '_method=PATCH', intent: 'Body param override converting POST to PATCH', signals: ['method-override-accepted'] },
  { value: 'X-HTTP-Method: DELETE', intent: 'Alternate override header X-HTTP-Method for DELETE', signals: ['method-override-accepted'] },
  { value: '?_method=DELETE', intent: 'Query param _method=DELETE override — some frameworks accept via GET params', signals: ['method-override-accepted'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `http-override-${i + 1}`,
    family: 'mass-assignment' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
