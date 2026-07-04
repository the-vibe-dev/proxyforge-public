// Sample extension: header injector
// Injects a configurable set of custom headers into every outgoing request.
//
// Configuration:
//   PF_INJECT_HEADERS — JSON string mapping header names to values, e.g.
//     PF_INJECT_HEADERS='{"X-Debug":"1","X-Custom":"value"}'
//
// The extension always injects X-ProxyForge-Extension regardless of configuration.

import type { ProxyForgeExtension, RequestHookPayload, RequestHookResult } from '../../sdk';

function loadConfigHeaders(): Record<string, string> {
  const raw = process.env.PF_INJECT_HEADERS;
  if (!raw) return {};
  try {
    const parsed: unknown = JSON.parse(raw);
    if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) {
      const result: Record<string, string> = {};
      for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
        if (typeof value === 'string') {
          result[key] = value;
        }
      }
      return result;
    }
  } catch {
    // Malformed env var — ignore.
  }
  return {};
}

export const extension: ProxyForgeExtension = {
  manifest: {
    id: 'header-injector',
    name: 'Header Injector',
    version: '1.0.0',
    description:
      'Injects a configurable set of custom headers into every outgoing request. ' +
      'Supply PF_INJECT_HEADERS as a JSON object to add additional headers.',
    author: 'ProxyForge',
    license: 'MIT',
    hooks: ['request'],
    permissions: ['read:history', 'write:history'],
  },

  async onRequest(payload: RequestHookPayload): Promise<RequestHookResult | void> {
    const configHeaders = loadConfigHeaders();

    const injected: Record<string, string> = {
      // Built-in identification header
      'X-ProxyForge-Extension': 'header-injector/1.0',
      // Merge config-supplied headers
      ...configHeaders,
      // Preserve existing headers so we don't clobber them
      ...payload.headers,
    };

    return { headers: injected };
  },
};
