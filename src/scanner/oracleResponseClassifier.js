"use strict";
// Adapted from source-reference/vantix/secops/skills/oracle_classifier.py
// (snapshot 2026-05-26). Rewritten in TypeScript with Proxy Forge naming.
// No runtime dependency on the vendored source.
Object.defineProperty(exports, "__esModule", { value: true });
exports.fingerprintResponse = fingerprintResponse;
exports.classifyOracleObservation = classifyOracleObservation;
exports.shouldPromoteToFinding = shouldPromoteToFinding;
exports.highestConfidenceClassification = highestConfidenceClassification;
exports.buildOracleObservation = buildOracleObservation;
const responseSignals_1 = require("./responseSignals");
function fingerprintResponse(response) {
    return {
        statusCode: response.statusCode,
        contentType: response.headers['content-type'] ?? '',
        bodyLength: response.bodyText.length,
        bodyHash: (0, responseSignals_1.simpleBodyHash)(response.bodyText),
        responseTimeMs: response.responseTimeMs,
    };
}
function detectReflection(payload, bodyText) {
    if (!payload || !bodyText)
        return null;
    const trimmed = payload.slice(0, 100);
    if (bodyText.includes(trimmed))
        return trimmed;
    // URL-decoded check
    try {
        const decoded = decodeURIComponent(trimmed);
        if (decoded !== trimmed && bodyText.includes(decoded))
            return decoded;
    }
    catch { }
    return null;
}
function classifyBySqlSignals(obs) {
    const match = (0, responseSignals_1.matchesAnyPattern)(obs.responseTextPreview, responseSignals_1.SQL_ERROR_PATTERNS);
    if (!match)
        return null;
    return {
        payloadVariantId: obs.payloadVariantId,
        responseClass: 'expected-proof',
        confidence: 0.85,
        observedValue: match,
        evidence: [`SQL error pattern matched: ${match}`],
        nextAction: 'promote-finding',
    };
}
function classifyByXssSignals(obs, payload) {
    const reflected = detectReflection(payload, obs.responseTextPreview);
    if (!reflected)
        return null;
    const activeExec = (0, responseSignals_1.matchesAnyPattern)(obs.responseTextPreview, responseSignals_1.XSS_REFLECTION_PATTERNS);
    if (activeExec) {
        return {
            payloadVariantId: obs.payloadVariantId,
            responseClass: 'expected-proof',
            confidence: 0.9,
            reflectedValue: reflected,
            evidence: [`XSS payload reflected and active: ${activeExec}`],
            nextAction: 'promote-finding',
        };
    }
    // Reflected but inert
    return {
        payloadVariantId: obs.payloadVariantId,
        responseClass: 'reflected-inert',
        confidence: 0.4,
        reflectedValue: reflected,
        evidence: ['Payload reflected without execution context'],
        nextAction: 'continue',
    };
}
function classifyBySstiSignals(obs) {
    const match = (0, responseSignals_1.matchesAnyPattern)(obs.responseTextPreview, responseSignals_1.SSTI_MATH_PATTERNS);
    if (!match)
        return null;
    return {
        payloadVariantId: obs.payloadVariantId,
        responseClass: 'expected-proof',
        confidence: 0.88,
        observedValue: match,
        evidence: [`SSTI math expression evaluated: found ${match}`],
        nextAction: 'promote-finding',
    };
}
function classifyByFileContentSignals(obs) {
    const match = (0, responseSignals_1.matchesAnyPattern)(obs.responseTextPreview, responseSignals_1.FILE_CONTENT_PATTERNS);
    if (!match)
        return null;
    return {
        payloadVariantId: obs.payloadVariantId,
        responseClass: 'expected-proof',
        confidence: 0.92,
        observedValue: match,
        evidence: [`File content pattern matched: ${match}`],
        nextAction: 'promote-finding',
    };
}
function classifyByCommandOutputSignals(obs) {
    const match = (0, responseSignals_1.matchesAnyPattern)(obs.responseTextPreview, responseSignals_1.COMMAND_OUTPUT_PATTERNS);
    if (!match)
        return null;
    return {
        payloadVariantId: obs.payloadVariantId,
        responseClass: 'expected-proof',
        confidence: 0.9,
        observedValue: match,
        evidence: [`Command output pattern matched: ${match}`],
        nextAction: 'promote-finding',
    };
}
function classifyByTimingDelta(obs) {
    if (obs.timingMs === undefined || !obs.baseline)
        return null;
    const delta = obs.timingMs - obs.baseline.responseTimeMs;
    if (delta >= 4500) {
        return {
            payloadVariantId: obs.payloadVariantId,
            responseClass: 'timing-delta',
            confidence: 0.72,
            observedValue: `${delta.toFixed(0)}ms delta`,
            evidence: [`Timing delta of ${delta.toFixed(0)}ms exceeds 4500ms threshold`],
            nextAction: 'confirm',
        };
    }
    return null;
}
function classifyByLengthDelta(obs, baseline) {
    const currentLength = obs.responseTextPreview.length;
    const baselineLength = baseline.bodyLength;
    if (baselineLength === 0)
        return null;
    const ratio = Math.abs(currentLength - baselineLength) / baselineLength;
    if (ratio > 0.5 && Math.abs(currentLength - baselineLength) > 200) {
        return {
            payloadVariantId: obs.payloadVariantId,
            responseClass: 'length-delta',
            confidence: 0.3,
            observedValue: `${currentLength} vs baseline ${baselineLength}`,
            evidence: [`Body length differs by ${(ratio * 100).toFixed(1)}%`],
            nextAction: 'continue',
        };
    }
    return null;
}
function classifyByStatusDelta(obs, baseline) {
    if (!obs.statusCode || obs.statusCode === baseline.statusCode)
        return null;
    const confidence = obs.statusCode >= 500 ? 0.55 : 0.25;
    return {
        payloadVariantId: obs.payloadVariantId,
        responseClass: 'status-delta',
        confidence,
        observedValue: String(obs.statusCode),
        evidence: [`Status changed from ${baseline.statusCode} to ${obs.statusCode}`],
        nextAction: obs.statusCode >= 500 ? 'continue' : 'continue',
    };
}
function classifyByNoSqlSignals(obs) {
    const match = (0, responseSignals_1.matchesAnyPattern)(obs.responseTextPreview, responseSignals_1.NOSQL_AUTH_BYPASS_PATTERNS);
    if (!match)
        return null;
    return {
        payloadVariantId: obs.payloadVariantId,
        responseClass: 'observed-value',
        confidence: 0.65,
        observedValue: match,
        evidence: [`NoSQL auth bypass pattern found: ${match}`],
        nextAction: 'confirm',
    };
}
function classifyByRedirectSignals(obs) {
    const location = obs.responseHeaders?.['location'] ?? obs.responseHeaders?.['Location'] ?? '';
    if (!location)
        return null;
    const match = (0, responseSignals_1.matchesAnyPattern)(location, responseSignals_1.REDIRECT_LOCATION_PATTERNS);
    if (match) {
        return {
            payloadVariantId: obs.payloadVariantId,
            responseClass: 'expected-proof',
            confidence: 0.88,
            observedValue: location,
            evidence: [`Redirect to attacker-controlled location: ${location}`],
            nextAction: 'promote-finding',
        };
    }
    return null;
}
function classifyOracleObservation(obs, variant, baseline) {
    // OAST confirmation is handled externally (callback broker).
    if (variant.requiresOast) {
        return {
            payloadVariantId: obs.payloadVariantId,
            responseClass: 'unknown',
            confidence: 0,
            evidence: ['OAST variant — classification deferred to callback correlation'],
            nextAction: 'continue',
        };
    }
    const body = obs.responseTextPreview;
    const family = variant.family;
    // Family-targeted classification
    if (family === 'sql-injection') {
        const result = classifyBySqlSignals(obs);
        if (result)
            return result;
    }
    if (family === 'xss-reflected' || family === 'xss-oracle') {
        const result = classifyByXssSignals(obs, variant.value);
        if (result)
            return result;
    }
    if (family === 'ssti' || family === 'ssti-blind-time') {
        const result = classifyBySstiSignals(obs);
        if (result)
            return result;
    }
    if (family === 'lfi-traversal') {
        const result = classifyByFileContentSignals(obs);
        if (result)
            return result;
    }
    if (family === 'command-injection') {
        const result = classifyByCommandOutputSignals(obs);
        if (result)
            return result;
    }
    if (family === 'nosql-injection') {
        const result = classifyByNoSqlSignals(obs);
        if (result)
            return result;
    }
    if (family === 'open-redirect') {
        const result = classifyByRedirectSignals(obs);
        if (result)
            return result;
    }
    // Generic timing delta
    if (variant.expectedSignals.includes('timing-delta') && obs.timingMs !== undefined && obs.baseline) {
        const result = classifyByTimingDelta(obs);
        if (result)
            return result;
    }
    // Generic baseline deltas
    if (baseline) {
        const statusResult = classifyByStatusDelta(obs, baseline);
        if (statusResult)
            return statusResult;
        const lengthResult = classifyByLengthDelta(obs, baseline);
        if (lengthResult)
            return lengthResult;
    }
    // Check for raw reflection (inert)
    const reflected = detectReflection(variant.value, body);
    if (reflected) {
        return {
            payloadVariantId: obs.payloadVariantId,
            responseClass: 'reflected-inert',
            confidence: 0.2,
            reflectedValue: reflected,
            evidence: ['Payload value reflected in response without signal pattern'],
            nextAction: 'continue',
        };
    }
    return {
        payloadVariantId: obs.payloadVariantId,
        responseClass: 'neutral-or-not-parsed',
        confidence: 0,
        evidence: ['No signals detected'],
        nextAction: 'stop-negative',
    };
}
function shouldPromoteToFinding(classifications) {
    return classifications.some((c) => c.responseClass === 'expected-proof' || c.responseClass === 'oast-callback-confirmed');
}
function highestConfidenceClassification(classifications) {
    return classifications.reduce((best, c) => {
        if (!best || c.confidence > best.confidence)
            return c;
        return best;
    }, undefined);
}
function buildOracleObservation(variantId, payload, response, baseline) {
    return {
        payloadVariantId: variantId,
        payload,
        statusCode: response.statusCode,
        contentType: response.headers['content-type'],
        responseTextPreview: response.bodyText.slice(0, 4096),
        responseHeaders: response.headers,
        baseline,
        timingMs: response.responseTimeMs,
    };
}
