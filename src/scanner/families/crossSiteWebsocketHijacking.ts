import type { PayloadVariant } from '../types';

export const META = {
  id: 'cross-site-websocket-hijacking',
  family: 'csrf-heuristic' as const,
  name: 'Cross-Site WebSocket Hijacking (CSWSH)',
  description: 'Detects WebSocket endpoints that accept cross-origin connections without SameSite or Origin validation.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['header'],
};

const PROBES = [
  { value: 'Origin: https://evil.example', intent: 'Cross-origin WebSocket handshake — server should reject non-allowlisted origins', signals: ['cswsh-accepted'] },
  { value: 'Origin: null', intent: 'Null origin WebSocket handshake — sent from sandboxed iframes; must be rejected', signals: ['cswsh-accepted'] },
  { value: 'Origin: https://trusted.example.evil.example', intent: 'Origin confusion via subdomain injection — tests prefix-only origin validation', signals: ['cswsh-accepted'] },
  { value: 'Origin: https://evil.example\r\nSec-WebSocket-Protocol: chat', intent: 'CRLF in Origin header during WebSocket upgrade — header injection attempt', signals: ['cswsh-accepted'] },
  { value: 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==', intent: 'Valid Upgrade key without SameSite cookie — tests session cookie forwarding to WS', signals: ['cswsh-accepted'] },
  { value: 'Origin: http://localhost', intent: 'Localhost origin — development allowlist bypass in production endpoints', signals: ['cswsh-accepted'] },
  { value: 'Origin: https://trusted.example', intent: 'Legitimate origin baseline — verify server properly allows expected origins', signals: ['cswsh-accepted'] },
];

export function variants(): PayloadVariant[] {
  return PROBES.map((p, i) => ({
    id: `cswsh-${i + 1}`,
    family: 'csrf-heuristic' as const,
    value: p.value,
    encoding: 'raw' as const,
    intent: p.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: p.signals,
  }));
}
