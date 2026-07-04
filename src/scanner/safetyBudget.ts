// Safety budget enforcement: gates destructive, OAST, and total-request limits.

import type { PayloadVariant, SafetyBudget } from './types';

export const DEFAULT_SAFETY_BUDGET: SafetyBudget = {
  maxRequests: 200,
  maxVariantsPerInsertionPoint: 12,
  throttleMs: 300,
  allowDestructive: false,
  allowOast: true,
};

export function filterVariantsByBudget(
  variants: PayloadVariant[],
  budget: SafetyBudget,
): PayloadVariant[] {
  let filtered = variants;

  if (!budget.allowOast) {
    filtered = filtered.filter((v) => !v.requiresOast);
  }

  if (!budget.allowDestructive) {
    filtered = filtered.filter((v) => v.destructiveRisk === 'none' || v.destructiveRisk === 'low');
  }

  return filtered.slice(0, budget.maxVariantsPerInsertionPoint);
}

export function budgetExceeded(requestCount: number, budget: SafetyBudget): boolean {
  return requestCount >= budget.maxRequests;
}

export function buildBudget(overrides?: Partial<SafetyBudget>): SafetyBudget {
  return { ...DEFAULT_SAFETY_BUDGET, ...overrides };
}
