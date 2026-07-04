"use strict";
// Safety budget enforcement: gates destructive, OAST, and total-request limits.
Object.defineProperty(exports, "__esModule", { value: true });
exports.DEFAULT_SAFETY_BUDGET = void 0;
exports.filterVariantsByBudget = filterVariantsByBudget;
exports.budgetExceeded = budgetExceeded;
exports.buildBudget = buildBudget;
exports.DEFAULT_SAFETY_BUDGET = {
    maxRequests: 200,
    maxVariantsPerInsertionPoint: 12,
    throttleMs: 300,
    allowDestructive: false,
    allowOast: true,
};
function filterVariantsByBudget(variants, budget) {
    let filtered = variants;
    if (!budget.allowOast) {
        filtered = filtered.filter((v) => !v.requiresOast);
    }
    if (!budget.allowDestructive) {
        filtered = filtered.filter((v) => v.destructiveRisk === 'none' || v.destructiveRisk === 'low');
    }
    return filtered.slice(0, budget.maxVariantsPerInsertionPoint);
}
function budgetExceeded(requestCount, budget) {
    return requestCount >= budget.maxRequests;
}
function buildBudget(overrides) {
    return { ...exports.DEFAULT_SAFETY_BUDGET, ...overrides };
}
