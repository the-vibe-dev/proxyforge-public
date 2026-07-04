// Context engine — create/dissolve contexts, URL membership, matching.
// No external dependencies.

import { randomBytes } from 'node:crypto';

export interface Context {
  id: string;
  name: string;
  /** Glob-style or prefix patterns that define in-scope URLs for this context */
  scopePatterns: string[];
  authMethodId?: string;
  /** User IDs that belong to this context */
  users: string[];
  /** Free-form tech-stack tags e.g. ["React", "Node.js", "GraphQL"] */
  techStack: string[];
  /** CustomPage ids assigned to this context */
  customPages: string[];
  createdAt: string;
}

export interface CreateContextOptions {
  name: string;
  scopePatterns?: string[];
  authMethodId?: string;
  users?: string[];
  techStack?: string[];
  customPages?: string[];
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Converts a simple scope pattern to a RegExp.
 *
 * Supported pattern forms:
 *  - Exact prefix: "https://example.com/app"
 *  - Wildcard *:   "https://*.example.com/*"
 *  - Regex string: starts with "^"
 */
function patternToRegex(pattern: string): RegExp {
  // If it already looks like a regex, use it as-is
  if (pattern.startsWith('^')) {
    return new RegExp(pattern);
  }
  // Escape everything except * and ? which are treated as glob wildcards
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.');
  return new RegExp(`^${escaped}`);
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function createContext(options: CreateContextOptions): Context {
  return {
    id: randomBytes(8).toString('hex'),
    name: options.name,
    scopePatterns: options.scopePatterns ?? [],
    authMethodId: options.authMethodId,
    users: options.users ?? [],
    techStack: options.techStack ?? [],
    customPages: options.customPages ?? [],
    createdAt: new Date().toISOString(),
  };
}

/**
 * Dissolve (remove) a context from a collection by id.
 * Returns a new array with the matching context removed.
 */
export function dissolveContext(contextId: string, contexts: Context[]): Context[] {
  return contexts.filter((c) => c.id !== contextId);
}

/**
 * Returns true if `url` matches at least one of the context's scope patterns.
 */
export function isUrlInContext(url: string, context: Context): boolean {
  if (context.scopePatterns.length === 0) return false;
  return context.scopePatterns.some((pattern) => {
    try {
      return patternToRegex(pattern).test(url);
    } catch {
      return false;
    }
  });
}

/**
 * Returns the first context whose scope patterns match `url`, or null.
 * The order of `contexts` determines precedence.
 */
export function getMatchingContext(url: string, contexts: Context[]): Context | null {
  return contexts.find((c) => isUrlInContext(url, c)) ?? null;
}
