import type { ActiveScanFinding, Issue } from '../types';
import type { EvidenceConclusion, OracleClassification, PayloadVariant } from './types';
export declare function buildFinding(checkId: string, family: string, host: string, path: string, insertionPointId: string, conclusion: EvidenceConclusion, bestClassification: OracleClassification, variant: PayloadVariant, exchangeId?: string): ActiveScanFinding;
export declare function buildIssueFromFinding(finding: ActiveScanFinding): Issue;
