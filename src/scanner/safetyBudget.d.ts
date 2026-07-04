import type { PayloadVariant, SafetyBudget } from './types';
export declare const DEFAULT_SAFETY_BUDGET: SafetyBudget;
export declare function filterVariantsByBudget(variants: PayloadVariant[], budget: SafetyBudget): PayloadVariant[];
export declare function budgetExceeded(requestCount: number, budget: SafetyBudget): boolean;
export declare function buildBudget(overrides?: Partial<SafetyBudget>): SafetyBudget;
