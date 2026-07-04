// Anti-CSRF token name registry with per-context bindings.
// Keeps a registry of known anti-CSRF token names and maps them to contexts.
// No external dependencies.

import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface AntiCsrfToken {
  id: string;
  /** Human-readable name, e.g. "csrf_token" or "X-XSRF-TOKEN" */
  name: string;
  contextId: string;
  /**
   * URL to GET before a replay in order to harvest a fresh token.
   * If omitted the engine will attempt to extract the token from the response
   * of the target request itself.
   */
  refreshUrl?: string;
  /** Header name to use when injecting the token (default: same as name) */
  headerName?: string;
  /** Form field name (alternative to headerName for form submissions) */
  fieldName?: string;
  /** Cookie name that carries the token (used for the cookie-to-header pattern) */
  cookieName?: string;
}

export interface RegisterAntiCsrfTokenOptions {
  name: string;
  contextId: string;
  refreshUrl?: string;
  headerName?: string;
  fieldName?: string;
  cookieName?: string;
}

// ---------------------------------------------------------------------------
// In-process registry
// ---------------------------------------------------------------------------

const tokenRegistry = new Map<string, AntiCsrfToken>();

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Registers a new anti-CSRF token binding and returns the created record.
 */
export function registerAntiCsrfToken(options: RegisterAntiCsrfTokenOptions): AntiCsrfToken {
  const token: AntiCsrfToken = {
    id: randomBytes(8).toString('hex'),
    ...options,
  };
  tokenRegistry.set(token.id, token);
  return token;
}

/**
 * Retrieves an anti-CSRF token record by id.
 */
export function getAntiCsrfToken(id: string): AntiCsrfToken | undefined {
  return tokenRegistry.get(id);
}

/**
 * Returns all anti-CSRF tokens registered for the given context.
 */
export function getTokensForContext(contextId: string): AntiCsrfToken[] {
  return Array.from(tokenRegistry.values()).filter((t) => t.contextId === contextId);
}

/**
 * Removes a token registration by id.
 */
export function deregisterAntiCsrfToken(id: string): boolean {
  return tokenRegistry.delete(id);
}

/**
 * Lists all registered tokens.
 */
export function listAntiCsrfTokens(): AntiCsrfToken[] {
  return Array.from(tokenRegistry.values());
}
