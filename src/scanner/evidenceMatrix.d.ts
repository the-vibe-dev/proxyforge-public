import type { EvidenceConclusion, ScanProbeMatrix } from './types';
export declare function concludeMatrix(matrix: Pick<ScanProbeMatrix, 'classifications' | 'variants'>): EvidenceConclusion;
export declare function buildNegativeEvidence(checkId: string, insertionPointId: string, exchangeId: string, variantCount: number, reason: string): Record<string, unknown>;
