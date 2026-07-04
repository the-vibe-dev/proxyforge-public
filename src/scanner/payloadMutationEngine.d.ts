import type { MutationContext, PayloadFamily, PayloadVariant } from './types';
export declare function generatePayloadVariants(ctx: MutationContext): PayloadVariant[];
export declare function familiesForInsertionPoint(kind: MutationContext['insertionPointKind']): PayloadFamily[];
