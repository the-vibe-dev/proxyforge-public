import type { OracleClassification, PayloadVariant, ScanProbeMatrix } from './types';
export declare function createProbeMatrix(projectId: string, sourceExchangeId: string, checkId: string, insertionPointId: string, variants: PayloadVariant[]): ScanProbeMatrix;
export declare function recordClassification(matrix: ScanProbeMatrix, classification: OracleClassification): ScanProbeMatrix;
export declare function markMatrixStopped(matrix: ScanProbeMatrix, reason?: 'inconclusive' | 'stopped'): ScanProbeMatrix;
export declare function isMatrixComplete(matrix: ScanProbeMatrix): boolean;
