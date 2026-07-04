// Probe matrix: plans and tracks a single check × insertion-point run.

import type {
  OracleClassification,
  PayloadVariant,
  ScanProbeMatrix,
} from './types';

let matrixCounter = 0;

function matrixId(checkId: string, insertionPointId: string) {
  matrixCounter += 1;
  return `pm-${checkId}-${insertionPointId.slice(0, 12)}-${matrixCounter.toString(36)}-${Date.now().toString(36)}`;
}

export function createProbeMatrix(
  projectId: string,
  sourceExchangeId: string,
  checkId: string,
  insertionPointId: string,
  variants: PayloadVariant[],
): ScanProbeMatrix {
  const now = new Date().toISOString();
  return {
    id: matrixId(checkId, insertionPointId),
    projectId,
    sourceExchangeId,
    checkId,
    insertionPointId,
    variants,
    classifications: [],
    oastPayloadIds: [],
    finalState: 'running',
    confidence: 0,
    createdAt: now,
    updatedAt: now,
  };
}

export function recordClassification(
  matrix: ScanProbeMatrix,
  classification: OracleClassification,
): ScanProbeMatrix {
  const now = new Date().toISOString();
  const classifications = [...matrix.classifications, classification];

  const hasFinding = classifications.some(
    (c) => c.responseClass === 'expected-proof' || c.responseClass === 'oast-callback-confirmed',
  );
  const allNegative = classifications.length >= Math.min(matrix.variants.length, 2)
    && classifications.every(
      (c) => c.responseClass === 'neutral-or-not-parsed' || c.responseClass === 'tag-stripped-or-ignored',
    );

  const finalState: ScanProbeMatrix['finalState'] = hasFinding
    ? 'finding'
    : allNegative ? 'negative'
    : 'running';

  const confidence = classifications.reduce((max, c) => Math.max(max, c.confidence), 0);

  return {
    ...matrix,
    classifications,
    finalState,
    confidence,
    updatedAt: now,
  };
}

export function markMatrixStopped(matrix: ScanProbeMatrix, reason: 'inconclusive' | 'stopped' = 'stopped'): ScanProbeMatrix {
  const hasData = matrix.classifications.length > 0;
  return {
    ...matrix,
    finalState: hasData ? reason : 'stopped',
    updatedAt: new Date().toISOString(),
  };
}

export function isMatrixComplete(matrix: ScanProbeMatrix): boolean {
  return matrix.finalState !== 'running';
}
