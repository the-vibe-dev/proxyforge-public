// DNS record manipulation rules engine.
// Provides rule CRUD and a pure apply function used by DnsProxy.

import { randomUUID } from 'node:crypto';

export interface DnsRecordRule {
  id: string;
  name: string;
  enabled: boolean;
  matchPattern: string;
  action: 'block' | 'map' | 'pass';
  resolvedIp?: string;
}

export interface DnsRuleResult {
  action: 'block' | 'map' | 'pass';
  resolvedIp?: string;
}

/**
 * Apply an ordered list of DNS rules against a query name.
 * Rules are evaluated in order; the first matching enabled rule wins.
 * If no rule matches, returns { action: 'pass' }.
 *
 * matchPattern is treated as a glob-style suffix match when it contains no
 * regex special characters, or as a regular expression otherwise.
 */
export function applyDnsRules(
  queryName: string,
  rules: DnsRecordRule[],
): DnsRuleResult {
  const name = queryName.toLowerCase().replace(/\.$/, ''); // strip trailing dot

  for (const rule of rules) {
    if (!rule.enabled) continue;

    if (_matches(name, rule.matchPattern)) {
      if (rule.action === 'block') {
        return { action: 'block' };
      }
      if (rule.action === 'map') {
        return { action: 'map', resolvedIp: rule.resolvedIp };
      }
      // 'pass' — stop evaluating further rules
      return { action: 'pass' };
    }
  }

  return { action: 'pass' };
}

/**
 * Create a new DnsRecordRule with a generated id and enabled=true by default.
 */
export function createDnsRule(
  partial: Omit<DnsRecordRule, 'id'> & { id?: string },
): DnsRecordRule {
  return {
    id: partial.id ?? randomUUID(),
    name: partial.name,
    enabled: partial.enabled ?? true,
    matchPattern: partial.matchPattern,
    action: partial.action,
    resolvedIp: partial.resolvedIp,
  };
}

/**
 * Return a copy of the rule with enabled set to true.
 */
export function enableDnsRule(rule: DnsRecordRule): DnsRecordRule {
  return { ...rule, enabled: true };
}

/**
 * Return a copy of the rule with enabled set to false.
 */
export function disableDnsRule(rule: DnsRecordRule): DnsRecordRule {
  return { ...rule, enabled: false };
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Match a DNS name against a pattern.
 *
 * Patterns may be:
 *  - Exact domain:     "example.com"
 *  - Wildcard suffix:  "*.example.com"  (matches sub.example.com, a.b.example.com)
 *  - Plain string:     "ads"            (substring match)
 *  - Regex-like:       "/^ad\\./"       (wrapped in /.../ treated as regex)
 */
function _matches(name: string, pattern: string): boolean {
  const p = pattern.toLowerCase().replace(/\.$/, '');

  // Explicit regex: /pattern/flags
  if (p.startsWith('/') && p.lastIndexOf('/') > 0) {
    const lastSlash = p.lastIndexOf('/');
    const src = p.slice(1, lastSlash);
    const flags = p.slice(lastSlash + 1);
    try {
      return new RegExp(src, flags).test(name);
    } catch {
      return false;
    }
  }

  // Wildcard: *.example.com
  if (p.startsWith('*.')) {
    const suffix = p.slice(1); // .example.com
    return name === p.slice(2) || name.endsWith(suffix);
  }

  // Exact match
  if (name === p) return true;

  // Suffix match without wildcard (e.g. "example.com" also matches "sub.example.com")
  if (name.endsWith('.' + p)) return true;

  // Substring match (for short patterns like "ads", "tracker")
  if (!p.includes('.') && name.includes(p)) return true;

  return false;
}
