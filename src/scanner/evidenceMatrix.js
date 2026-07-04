"use strict";
// Evidence matrix: builds a structured record of probe results.
// Adapted from source-reference/vantix/secops/skills/ evidence model.
// No runtime dependency on the vendored source.
Object.defineProperty(exports, "__esModule", { value: true });
exports.concludeMatrix = concludeMatrix;
exports.buildNegativeEvidence = buildNegativeEvidence;
const oracleResponseClassifier_1 = require("./oracleResponseClassifier");
function concludeMatrix(matrix) {
    const { classifications, variants } = matrix;
    if (classifications.length === 0) {
        return {
            state: 'inconclusive',
            confidence: 0,
            summary: 'No classifications recorded — probe did not complete',
            evidenceIds: [],
        };
    }
    const promote = (0, oracleResponseClassifier_1.shouldPromoteToFinding)(classifications);
    if (promote) {
        const best = (0, oracleResponseClassifier_1.highestConfidenceClassification)(classifications.filter((c) => c.responseClass === 'expected-proof' || c.responseClass === 'oast-callback-confirmed'));
        return {
            state: 'finding',
            confidence: best?.confidence ?? 0.8,
            summary: best?.evidence.join('; ') ?? 'Oracle-classified proof observed',
            evidenceIds: classifications.map((c) => c.payloadVariantId),
        };
    }
    const allNegative = classifications.every((c) => c.responseClass === 'neutral-or-not-parsed' || c.responseClass === 'tag-stripped-or-ignored');
    if (allNegative && classifications.length >= Math.min(variants.length, 3)) {
        return {
            state: 'negative',
            confidence: 0.7,
            summary: `All ${classifications.length} probe(s) produced neutral/negative classification`,
            evidenceIds: classifications.map((c) => c.payloadVariantId),
        };
    }
    const hasTimingOrLength = classifications.some((c) => c.responseClass === 'timing-delta' || c.responseClass === 'length-delta');
    if (hasTimingOrLength) {
        return {
            state: 'inconclusive',
            confidence: 0.4,
            summary: 'Timing or length delta observed — needs confirmation',
            evidenceIds: classifications.map((c) => c.payloadVariantId),
        };
    }
    return {
        state: 'inconclusive',
        confidence: 0.2,
        summary: `Mixed results across ${classifications.length} probe(s)`,
        evidenceIds: classifications.map((c) => c.payloadVariantId),
    };
}
function buildNegativeEvidence(checkId, insertionPointId, exchangeId, variantCount, reason) {
    return {
        kind: 'proxyforge-scanner-negative-evidence',
        checkId,
        insertionPointId,
        sourceExchangeId: exchangeId,
        variantsTested: variantCount,
        conclusion: 'negative',
        reason,
        createdAt: new Date().toISOString(),
    };
}
