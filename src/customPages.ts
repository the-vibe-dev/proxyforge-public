// Per-Context custom page class declarations.
// Allows operators to mark specific URL patterns as known page types so the
// scanner does not generate false-positive findings (e.g. a custom 404 that
// returns HTTP 200 would otherwise confuse passive checks).
// No external dependencies.

import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type CustomPageClass = 'error' | 'not-found' | 'ok' | 'auth-required';

export interface CustomPage {
  id: string;
  contextId: string;
  /** Glob / prefix pattern for URLs matching this page class */
  pattern: string;
  /** The declared page class */
  class: CustomPageClass;
  /** Optional comment for operators */
  notes?: string;
}

export interface AddCustomPageOptions {
  contextId: string;
  pattern: string;
  class: CustomPageClass;
  notes?: string;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function patternMatches(pattern: string, url: string): boolean {
  if (pattern.startsWith('^')) {
    try {
      return new RegExp(pattern).test(url);
    } catch {
      return false;
    }
  }
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  try {
    return new RegExp(`^${escaped}`).test(url);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Creates a new CustomPage declaration and adds it to the provided collection.
 * Returns the updated collection (the original array is mutated for convenience).
 */
export function addCustomPage(
  options: AddCustomPageOptions,
  customPages: CustomPage[],
): CustomPage {
  const page: CustomPage = {
    id: randomBytes(8).toString('hex'),
    ...options,
  };
  customPages.push(page);
  return page;
}

/**
 * Returns the page class for the first custom page whose pattern matches `url`
 * in the given context, or null if none matches.
 */
export function getCustomPageClass(
  url: string,
  contextId: string,
  customPages: CustomPage[],
): CustomPageClass | null {
  const match = customPages.find(
    (p) => p.contextId === contextId && patternMatches(p.pattern, url),
  );
  return match ? match.class : null;
}

/**
 * Returns true if a passive scanner false positive should be suppressed for
 * this URL / status combination.
 *
 * Suppression rules:
 *  - A 'not-found' page with HTTP 200 would confuse a scanner expecting 404 →
 *    suppress any finding raised on it.
 *  - An 'auth-required' page with HTTP 200/302 suppresses auth-related false
 *    positives.
 *  - An 'ok' page class never suppresses.
 *  - An 'error' page never suppresses (errors are valid targets).
 */
export function suppressFalsePositive(
  url: string,
  contextId: string,
  responseStatus: number,
  customPages: CustomPage[],
): boolean {
  const pageClass = getCustomPageClass(url, contextId, customPages);
  if (!pageClass) return false;

  switch (pageClass) {
    case 'not-found':
      // Custom not-found pages that return 200 are a common source of false positives
      return responseStatus === 200 || responseStatus === 404;
    case 'auth-required':
      // Login pages returning 200 or 302 may look like success to a scanner
      return responseStatus === 200 || responseStatus === 302 || responseStatus === 401;
    case 'ok':
      return false;
    case 'error':
      return false;
    default:
      return false;
  }
}

/**
 * Removes a custom page by id. Returns true if found and removed.
 */
export function removeCustomPage(id: string, customPages: CustomPage[]): boolean {
  const idx = customPages.findIndex((p) => p.id === id);
  if (idx < 0) return false;
  customPages.splice(idx, 1);
  return true;
}
