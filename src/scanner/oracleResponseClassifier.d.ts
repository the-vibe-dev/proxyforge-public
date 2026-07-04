import type { OracleClassification, OracleObservation, OracleResponseClass, PayloadVariant, ResponseFingerprint, ScannerResponseInput } from './types';
export declare function fingerprintResponse(response: ScannerResponseInput): ResponseFingerprint;
export declare function classifyOracleObservation(obs: OracleObservation, variant: PayloadVariant, baseline?: ResponseFingerprint): OracleClassification;
export declare function shouldPromoteToFinding(classifications: OracleClassification[]): boolean;
export declare function highestConfidenceClassification(classifications: OracleClassification[]): OracleClassification | undefined;
export declare function buildOracleObservation(variantId: string, payload: string, response: ScannerResponseInput, baseline?: ResponseFingerprint): OracleObservation;
export type { OracleClassification, OracleObservation, OracleResponseClass, ResponseFingerprint };
