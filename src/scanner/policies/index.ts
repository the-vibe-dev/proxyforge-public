// Named scanner policies with per-rule Threshold × Strength configuration.
// Used to control which checks run and how aggressively they probe.
// No external dependencies.

import { randomBytes } from 'node:crypto';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * Confidence threshold — findings below this level are not reported.
 *  low    → report tentative + firm + certain
 *  medium → report firm + certain
 *  high   → report certain only
 */
export type ScannerThreshold = 'low' | 'medium' | 'high';

/**
 * Probe strength — how many variants / how deep the engine probes.
 *  low    → minimal probes, fastest
 *  medium → balanced (default)
 *  high   → extended probe set
 *  insane → all variants, including destructive / time-based
 */
export type ScannerStrength = 'low' | 'medium' | 'high' | 'insane';

/**
 * Confidence levels used by the scanner engine.
 */
export type FindingConfidence = 'tentative' | 'firm' | 'certain';

export interface PolicyRule {
  /** Check identifier, e.g. "sql-injection", "reflected-xss" */
  checkId: string;
  threshold: ScannerThreshold;
  strength: ScannerStrength;
  enabled: boolean;
}

export interface ScannerPolicy {
  id: string;
  name: string;
  /** Description / notes */
  description?: string;
  rules: PolicyRule[];
  createdAt: string;
}

export interface CreatePolicyOptions {
  name: string;
  description?: string;
  rules?: PolicyRule[];
}

// ---------------------------------------------------------------------------
// Default check ids (mirrors ActiveScanCheckId in types.ts)
// ---------------------------------------------------------------------------

const DEFAULT_CHECK_IDS: string[] = [
  'security-headers',
  'cors-origin',
  'cache-key',
  'method-options',
  'authz-diff',
  'jwt-claims',
  'graphql-introspection',
  'oast-ssrf',
  'reflected-xss',
  'sql-injection',
  'path-traversal',
  'open-redirect',
  'command-injection',
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CONFIDENCE_RANK: Record<FindingConfidence, number> = {
  tentative: 0,
  firm: 1,
  certain: 2,
};

const THRESHOLD_MIN_RANK: Record<ScannerThreshold, number> = {
  low: 0,    // tentative and above
  medium: 1, // firm and above
  high: 2,   // certain only
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Creates a policy rule with sensible defaults.
 */
export function createPolicyRule(
  checkId: string,
  overrides: Partial<Omit<PolicyRule, 'checkId'>> = {},
): PolicyRule {
  return {
    checkId,
    threshold: overrides.threshold ?? 'medium',
    strength: overrides.strength ?? 'medium',
    enabled: overrides.enabled ?? true,
  };
}

/**
 * Creates the default scanner policy — all built-in checks enabled at
 * medium threshold / medium strength.
 */
export function createDefaultPolicy(): ScannerPolicy {
  return {
    id: randomBytes(8).toString('hex'),
    name: 'Default Policy',
    description: 'All built-in checks at medium threshold and medium strength',
    rules: DEFAULT_CHECK_IDS.map((id) => createPolicyRule(id)),
    createdAt: new Date().toISOString(),
  };
}

/**
 * Creates a named scanner policy with optional rule overrides.
 */
export function createScannerPolicy(options: CreatePolicyOptions): ScannerPolicy {
  return {
    id: randomBytes(8).toString('hex'),
    name: options.name,
    description: options.description,
    rules: options.rules ?? DEFAULT_CHECK_IDS.map((id) => createPolicyRule(id)),
    createdAt: new Date().toISOString(),
  };
}

/**
 * Finds the policy rule for a given check id, or undefined.
 */
export function getPolicyRule(checkId: string, policy: ScannerPolicy): PolicyRule | undefined {
  return policy.rules.find((r) => r.checkId === checkId);
}

/**
 * Updates a rule in a policy (mutates the policy's rules array).
 * If the rule doesn't exist, it is added.
 */
export function upsertPolicyRule(policy: ScannerPolicy, rule: PolicyRule): void {
  const idx = policy.rules.findIndex((r) => r.checkId === rule.checkId);
  if (idx >= 0) {
    policy.rules[idx] = rule;
  } else {
    policy.rules.push(rule);
  }
}

/**
 * Determines whether a check should run and whether a finding at a given
 * confidence level should be reported.
 *
 * @param checkId     The check to evaluate
 * @param policy      The active scanner policy
 * @param confidence  The finding's confidence level
 * @returns           true if the check is enabled and the confidence meets
 *                    the rule's threshold
 */
export function shouldRunCheck(
  checkId: string,
  policy: ScannerPolicy,
  confidence: FindingConfidence,
): boolean {
  const rule = getPolicyRule(checkId, policy);
  if (!rule || !rule.enabled) return false;

  const confidenceRank = CONFIDENCE_RANK[confidence];
  const minRank = THRESHOLD_MIN_RANK[rule.threshold];
  return confidenceRank >= minRank;
}

/**
 * Returns the probe strength for a check, or 'medium' if not in the policy.
 */
export function getCheckStrength(checkId: string, policy: ScannerPolicy): ScannerStrength {
  const rule = getPolicyRule(checkId, policy);
  return rule?.strength ?? 'medium';
}

/**
 * Returns all enabled checks for a policy.
 */
export function getEnabledChecks(policy: ScannerPolicy): string[] {
  return policy.rules.filter((r) => r.enabled).map((r) => r.checkId);
}
