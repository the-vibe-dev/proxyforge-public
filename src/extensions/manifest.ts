/**
 * Extension manifest validation, normalisation, and digest utilities.
 */
import { createHash } from 'node:crypto';

// Re-declare the types locally so this module can be compiled as a plain TS
// module without depending on the ambient sdk.d.ts declarations.
export type HookName =
  | 'request'
  | 'response'
  | 'tls_clienthello'
  | 'tcp_message'
  | 'scan_check'
  | 'editor_tab'
  | 'intruder_payload_processor'
  | 'repeater_action'
  | 'scanner_passive';

export interface ExtensionManifest {
  id: string;
  name: string;
  version: string;
  description?: string;
  author?: string;
  license?: string;
  hooks: HookName[];
  permissions: string[];
  digest?: string;
  signature?: string;
}

/** All hook names recognised by the ProxyForge Extension SDK. */
export const VALID_HOOKS: readonly HookName[] = [
  'request',
  'response',
  'tls_clienthello',
  'tcp_message',
  'scan_check',
  'editor_tab',
  'intruder_payload_processor',
  'repeater_action',
  'scanner_passive',
] as const;

/** All permission tokens that an extension may request. */
export const VALID_PERMISSIONS: readonly string[] = [
  'read:history',
  'write:history',
  'read:issues',
  'write:issues',
  'read:project',
  'network:request',
  'ui:tab',
] as const;

const VALID_HOOKS_SET = new Set<string>(VALID_HOOKS);
const VALID_PERMISSIONS_SET = new Set<string>(VALID_PERMISSIONS);

/**
 * Validate the shape and content of a manifest-like object.
 *
 * Returns `{ valid: true, errors: [] }` on success, or
 * `{ valid: false, errors: ['...'] }` listing all validation problems.
 */
export function validateManifest(obj: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];

  if (obj === null || typeof obj !== 'object') {
    return { valid: false, errors: ['manifest must be a non-null object'] };
  }

  const m = obj as Record<string, unknown>;

  // Required string fields
  for (const field of ['id', 'name', 'version'] as const) {
    if (typeof m[field] !== 'string' || (m[field] as string).trim() === '') {
      errors.push(`missing or empty required field: ${field}`);
    }
  }

  // hooks — must be an array of valid HookName values
  if (!Array.isArray(m.hooks)) {
    errors.push('hooks must be an array');
  } else {
    for (const h of m.hooks) {
      if (typeof h !== 'string' || !VALID_HOOKS_SET.has(h)) {
        errors.push(`invalid hook name: ${String(h)}`);
      }
    }
  }

  // permissions — must be an array of valid permission tokens
  if (!Array.isArray(m.permissions)) {
    errors.push('permissions must be an array');
  } else {
    for (const p of m.permissions) {
      if (typeof p !== 'string' || !VALID_PERMISSIONS_SET.has(p)) {
        errors.push(`invalid permission: ${String(p)}`);
      }
    }
  }

  return { valid: errors.length === 0, errors };
}

/**
 * Apply defaults to a partial manifest and return a complete ExtensionManifest.
 * Required fields (id, name, version) default to placeholder strings when absent.
 */
export function normalizeManifest(partial: Partial<ExtensionManifest>): ExtensionManifest {
  return {
    id: partial.id ?? 'unknown-extension',
    name: partial.name ?? 'Unnamed Extension',
    version: partial.version ?? '0.0.0',
    description: partial.description,
    author: partial.author,
    license: partial.license ?? 'UNLICENSED',
    hooks: partial.hooks ?? [],
    permissions: partial.permissions ?? [],
    digest: partial.digest,
    signature: partial.signature,
  };
}

/**
 * Compute the SHA-256 hex digest of a serialised manifest JSON string.
 * Use this to produce the `digest` field before signing.
 */
export function computeDigest(manifestJson: string): string {
  return createHash('sha256').update(manifestJson, 'utf8').digest('hex');
}
