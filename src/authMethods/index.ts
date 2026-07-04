// Auth method registry and factory.
// No external dependencies.

import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type AuthMethodType = 'form' | 'json' | 'http-basic' | 'manual' | 'totp';

export interface AuthMethod {
  id: string;
  type: AuthMethodType;
  name: string;
  /** Arbitrary config blob — shape depends on type */
  config: Record<string, unknown>;
}

export interface AuthResult {
  success: boolean;
  /** Session cookies or token extracted on success */
  sessionData?: Record<string, string>;
  error?: string;
}

// ---------------------------------------------------------------------------
// Type guards
// ---------------------------------------------------------------------------

export function isFormAuth(method: AuthMethod): boolean {
  return method.type === 'form';
}

export function isJsonAuth(method: AuthMethod): boolean {
  return method.type === 'json';
}

export function isHttpBasic(method: AuthMethod): boolean {
  return method.type === 'http-basic';
}

export function isManualAuth(method: AuthMethod): boolean {
  return method.type === 'manual';
}

export function isTotpAuth(method: AuthMethod): boolean {
  return method.type === 'totp';
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

export function createAuthMethod(
  type: AuthMethodType,
  name: string,
  config: Record<string, unknown> = {},
): AuthMethod {
  return {
    id: randomBytes(8).toString('hex'),
    type,
    name,
    config,
  };
}

// ---------------------------------------------------------------------------
// In-memory registry (singleton store for the process lifetime)
// ---------------------------------------------------------------------------

const registry = new Map<string, AuthMethod>();

export function registerAuthMethod(method: AuthMethod): void {
  registry.set(method.id, method);
}

export function getAuthMethod(id: string): AuthMethod | undefined {
  return registry.get(id);
}

export function listAuthMethods(): AuthMethod[] {
  return Array.from(registry.values());
}

export function removeAuthMethod(id: string): boolean {
  return registry.delete(id);
}
