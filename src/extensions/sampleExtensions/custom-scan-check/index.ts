// Sample extension: custom scan check
// Demonstrates how to implement a custom active check via the SDK.
//
// Checks for common debug parameters (?debug=1, ?test=1, ?verbose=true) that
// may return extra information about the application when present in the URL.
// The check reports a finding when the payload is one of the known debug triggers.

import type {
  ProxyForgeExtension,
  ScanCheckPayload,
  ScanCheckResult,
} from '../../sdk';

/** Debug parameter values commonly accepted by misconfigured applications. */
const DEBUG_PAYLOADS = new Set([
  '1',
  'true',
  'yes',
  'on',
  'enable',
  'enabled',
]);

/** Known debug/verbose query-string parameter names. */
const DEBUG_PARAM_NAMES = ['debug', 'test', 'verbose', 'trace', 'dev', 'internal'];

export const extension: ProxyForgeExtension = {
  manifest: {
    id: 'custom-scan-check',
    name: 'Debug Parameter Probe',
    version: '1.0.0',
    description:
      'Custom scanner check that probes for debug query parameters (?debug=1, ?test=1, ?verbose=true) ' +
      'which may cause the server to expose extra diagnostic information.',
    author: 'ProxyForge',
    license: 'MIT',
    hooks: ['scan_check'],
    permissions: ['read:history', 'write:issues'],
  },

  async onScanCheck(payload: ScanCheckPayload): Promise<ScanCheckResult | void> {
    // payload.payload is the value injected at the insertion point.
    const injected = (payload.payload ?? '').toLowerCase().trim();

    // Only report when one of our debug payloads was injected AND the
    // insertion point ID suggests it targets a query-string parameter.
    const insertionPoint = (payload.insertionPointId ?? '').toLowerCase();
    const isDebugParam = DEBUG_PARAM_NAMES.some((name) => insertionPoint.includes(name));
    const isDebugValue = DEBUG_PAYLOADS.has(injected);

    if (!isDebugParam || !isDebugValue) {
      return; // Not our check's responsibility.
    }

    return {
      finding: {
        title: 'Debug parameter accepted by server',
        severity: 'low',
        confidence: 'tentative',
        detail:
          `Exchange ${payload.exchangeId}: the server accepted the insertion point ` +
          `"${payload.insertionPointId}" with value "${payload.payload}". ` +
          'Verify whether the response reveals diagnostic information that should not be exposed in production.',
      },
    };
  },
};
