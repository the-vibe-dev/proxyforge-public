// Sample extension: base64 payload processor
// Transforms Intruder payloads by base64-encoding them.
//
// Useful when an insertion point expects base64-encoded values, e.g.
// a JSON body field that stores encoded user input.

import type {
  ProxyForgeExtension,
  IntruderPayloadProcessorPayload,
  IntruderPayloadResult,
} from '../../sdk';
import { base64Encode } from '../../sdkHelpers';

export const extension: ProxyForgeExtension = {
  manifest: {
    id: 'intruder-base64',
    name: 'Intruder Base64 Payload Processor',
    version: '1.0.0',
    description:
      'Transforms each Intruder payload by base64-encoding it before it is injected into the request.',
    author: 'ProxyForge',
    license: 'MIT',
    hooks: ['intruder_payload_processor'],
    permissions: ['read:history'],
  },

  async onIntruderPayload(
    payload: IntruderPayloadProcessorPayload,
  ): Promise<IntruderPayloadResult | void> {
    return { transformed: base64Encode(payload.original) };
  },
};
