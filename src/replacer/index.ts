// Project-wide pre-flight request and response rewriter (Match & Replace).
// Rules are applied in order; first-match-wins for 'both' scope rules.
// No external dependencies.

import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type ReplacerScope = 'request' | 'response' | 'both';

export interface ReplacerFilter {
  /** Only apply if the URL matches this pattern (glob or regex ^...) */
  urlPattern?: string;
  /** Only apply if the Host header matches this string (case-insensitive) */
  host?: string;
  /** Only apply if HTTP method matches (e.g. "POST") */
  method?: string;
  /** Only apply for responses with this status code */
  statusCode?: number;
}

export interface ReplacerRule {
  id: string;
  name: string;
  enabled: boolean;
  scope: ReplacerScope;
  /**
   * Pattern to search for. Can be a plain string or a regex (prefix with "^"
   * or wrap in /.../ notation — e.g. "/csrf_token=[^&]+/").
   */
  matchPattern: string;
  /** Replacement string. Supports $1 back-references for regex groups. */
  replaceWith: string;
  /** Optional filter to restrict when the rule fires */
  filter?: ReplacerFilter;
}

export interface CreateReplacerRuleOptions {
  name: string;
  enabled?: boolean;
  scope: ReplacerScope;
  matchPattern: string;
  replaceWith: string;
  filter?: ReplacerFilter;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function compilePattern(pattern: string): RegExp {
  // /regex/flags notation
  const slashMatch = /^\/(.+)\/([gimsuy]*)$/.exec(pattern);
  if (slashMatch) {
    return new RegExp(slashMatch[1], slashMatch[2] || 'g');
  }
  // ^regex notation
  if (pattern.startsWith('^')) {
    return new RegExp(pattern, 'g');
  }
  // Plain string — escape and match literally (globally)
  const escaped = pattern.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(escaped, 'g');
}

function urlMatchesPattern(url: string, pattern: string): boolean {
  if (pattern.startsWith('^') || pattern.startsWith('/')) {
    try {
      return compilePattern(pattern).test(url);
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

function filterMatches(filter: ReplacerFilter | undefined, rawText: string): boolean {
  if (!filter) return true;

  if (filter.host) {
    const hostMatch = /^Host:\s*(.+)$/im.exec(rawText);
    const host = hostMatch ? hostMatch[1].trim() : '';
    if (host.toLowerCase() !== filter.host.toLowerCase()) return false;
  }

  if (filter.method) {
    const methodMatch = /^([A-Z]+)\s/.exec(rawText);
    const method = methodMatch ? methodMatch[1] : '';
    if (method.toUpperCase() !== filter.method.toUpperCase()) return false;
  }

  if (filter.urlPattern) {
    // Try to extract a URL line from the raw text
    const urlLine = /^(?:[A-Z]+\s+)(https?:\/\/[^\s]+|\/[^\s]*)/m.exec(rawText);
    const url = urlLine ? urlLine[1] : '';
    if (!urlMatchesPattern(url, filter.urlPattern)) return false;
  }

  return true;
}

// ---------------------------------------------------------------------------
// Rule factory
// ---------------------------------------------------------------------------

export function createReplacerRule(options: CreateReplacerRuleOptions): ReplacerRule {
  return {
    id: randomBytes(8).toString('hex'),
    name: options.name,
    enabled: options.enabled ?? true,
    scope: options.scope,
    matchPattern: options.matchPattern,
    replaceWith: options.replaceWith,
    filter: options.filter,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Applies all enabled replacer rules to a raw HTTP request string.
 * Rules with scope 'request' or 'both' are applied in order.
 *
 * @param rawRequest  Raw HTTP/1.1 request text
 * @param rules       All configured replacer rules (inactive ones are skipped)
 * @returns           The rewritten request string
 */
export function applyReplacerRules(rawRequest: string, rules: ReplacerRule[]): string {
  let result = rawRequest;

  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (rule.scope === 'response') continue;
    if (!filterMatches(rule.filter, result)) continue;

    try {
      const re = compilePattern(rule.matchPattern);
      result = result.replace(re, rule.replaceWith);
    } catch {
      // Skip rules with invalid patterns rather than crashing
    }
  }

  return result;
}

/**
 * Applies all enabled replacer rules to a raw HTTP response string.
 * Rules with scope 'response' or 'both' are applied in order.
 *
 * @param rawResponse Raw HTTP/1.1 response text
 * @param rules       All configured replacer rules
 * @returns           The rewritten response string
 */
export function applyReplacerRulesToResponse(rawResponse: string, rules: ReplacerRule[]): string {
  let result = rawResponse;

  for (const rule of rules) {
    if (!rule.enabled) continue;
    if (rule.scope === 'request') continue;
    if (!filterMatches(rule.filter, result)) continue;

    try {
      const re = compilePattern(rule.matchPattern);
      result = result.replace(re, rule.replaceWith);
    } catch {
      // Skip rules with invalid patterns
    }
  }

  return result;
}
