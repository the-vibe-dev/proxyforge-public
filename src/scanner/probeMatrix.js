"use strict";
// Probe matrix: plans and tracks a single check × insertion-point run.
Object.defineProperty(exports, "__esModule", { value: true });
exports.createProbeMatrix = createProbeMatrix;
exports.recordClassification = recordClassification;
exports.markMatrixStopped = markMatrixStopped;
exports.isMatrixComplete = isMatrixComplete;
let matrixCounter = 0;
function matrixId(checkId, insertionPointId) {
    matrixCounter += 1;
    return `pm-${checkId}-${insertionPointId.slice(0, 12)}-${matrixCounter.toString(36)}-${Date.now().toString(36)}`;
}
function createProbeMatrix(projectId, sourceExchangeId, checkId, insertionPointId, variants) {
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
function recordClassification(matrix, classification) {
    const now = new Date().toISOString();
    const classifications = [...matrix.classifications, classification];
    const hasFinding = classifications.some((c) => c.responseClass === 'expected-proof' || c.responseClass === 'oast-callback-confirmed');
    const allNegative = classifications.length >= Math.min(matrix.variants.length, 2)
        && classifications.every((c) => c.responseClass === 'neutral-or-not-parsed' || c.responseClass === 'tag-stripped-or-ignored');
    const finalState = hasFinding
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
function markMatrixStopped(matrix, reason = 'stopped') {
    const hasData = matrix.classifications.length > 0;
    return {
        ...matrix,
        finalState: hasData ? reason : 'stopped',
        updatedAt: new Date().toISOString(),
    };
}
function isMatrixComplete(matrix) {
    return matrix.finalState !== 'running';
}
