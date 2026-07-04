import type { InsertionPointKind, PayloadFamily, SafetyBudget } from './types';
export interface InsertionPointSpec {
    id: string;
    name: string;
    kind: InsertionPointKind;
    baseValue: string;
    exchangeId: string;
    url: string;
    host: string;
    path: string;
}
export interface ProbePlan {
    insertionPoint: InsertionPointSpec;
    checkId: string;
    family: PayloadFamily;
    priority: number;
}
export declare function planProbes(insertionPoints: InsertionPointSpec[], requestedCheckIds: string[], budget: SafetyBudget): ProbePlan[];
