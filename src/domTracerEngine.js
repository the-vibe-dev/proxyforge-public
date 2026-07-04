"use strict";
// DOM tracer engine — session/canary/event reducer (off-thread state machine).
// Receives instrumented events from domTracerInstrumentation.ts and maintains
// session state: sources observed, sinks fired, canary traces.
// No external dependencies.
Object.defineProperty(exports, "__esModule", { value: true });
exports.createTracerSession = createTracerSession;
exports.getTracerSession = getTracerSession;
exports.stopTracerSession = stopTracerSession;
exports.getAllSessions = getAllSessions;
exports.recordSourceEvent = recordSourceEvent;
exports.recordSinkEvent = recordSinkEvent;
exports.setCanary = setCanary;
exports.clearCanary = clearCanary;
exports.getCanaryTraces = getCanaryTraces;
exports.getHighValueSinks = getHighValueSinks;
const node_crypto_1 = require("node:crypto");
// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------
const sessions = new Map();
function createTracerSession(tabId, projectId, url) {
    const session = {
        id: (0, node_crypto_1.randomBytes)(8).toString('hex'),
        tabId,
        projectId,
        url,
        sources: [],
        sinks: [],
        status: 'active',
        startedAt: new Date().toISOString(),
    };
    sessions.set(session.id, session);
    return session;
}
function getTracerSession(sessionId) {
    return sessions.get(sessionId) ?? null;
}
function stopTracerSession(sessionId) {
    const s = sessions.get(sessionId);
    if (s) {
        s.status = 'stopped';
        s.stoppedAt = new Date().toISOString();
    }
}
function getAllSessions() {
    return Array.from(sessions.values());
}
// ---------------------------------------------------------------------------
// Event ingestion
// ---------------------------------------------------------------------------
function recordSourceEvent(sessionId, source, value, url) {
    const s = sessions.get(sessionId);
    if (!s || s.status !== 'active')
        return null;
    const evt = {
        id: (0, node_crypto_1.randomBytes)(6).toString('hex'),
        sessionId,
        source,
        value,
        url,
        timestamp: new Date().toISOString(),
    };
    s.sources.push(evt);
    return evt;
}
function recordSinkEvent(sessionId, sink, value, url, stack) {
    const s = sessions.get(sessionId);
    if (!s || s.status !== 'active')
        return null;
    const canaryMatched = s.canary ? value.includes(s.canary.nonce) : undefined;
    const canaryTransformation = canaryMatched && s.canary
        ? detectTransformation(s.canary.nonce, value)
        : undefined;
    const evt = {
        id: (0, node_crypto_1.randomBytes)(6).toString('hex'),
        sessionId,
        sink,
        value,
        canaryMatched,
        canaryTransformation,
        stack,
        url,
        timestamp: new Date().toISOString(),
    };
    s.sinks.push(evt);
    return evt;
}
// ---------------------------------------------------------------------------
// Canary management
// ---------------------------------------------------------------------------
function setCanary(sessionId, source, probeCharSet) {
    const s = sessions.get(sessionId);
    if (!s)
        return null;
    const canary = {
        nonce: `pf-${(0, node_crypto_1.randomBytes)(6).toString('hex')}`,
        source,
        probeCharSet,
    };
    s.canary = canary;
    return canary;
}
function clearCanary(sessionId) {
    const s = sessions.get(sessionId);
    if (s)
        s.canary = undefined;
}
// ---------------------------------------------------------------------------
// Analysis
// ---------------------------------------------------------------------------
function getCanaryTraces(sessionId) {
    const s = sessions.get(sessionId);
    if (!s)
        return [];
    return s.sinks.filter((e) => e.canaryMatched === true);
}
function getHighValueSinks(sessionId) {
    const HIGH_VALUE = ['innerHTML', 'outerHTML', 'eval', 'Function', 'document.write', 'setTimeout(string)', 'location.href', 'location.assign'];
    const s = sessions.get(sessionId);
    if (!s)
        return [];
    return s.sinks.filter((e) => HIGH_VALUE.includes(e.sink));
}
function detectTransformation(nonce, sinkValue) {
    if (sinkValue.includes(encodeURIComponent(nonce)))
        return 'url-encoded';
    if (sinkValue.includes(nonce.replace(/-/g, '_')))
        return 'dash-to-underscore';
    if (sinkValue.toLowerCase().includes(nonce.toLowerCase()))
        return 'case-normalized';
    if (sinkValue.includes(nonce.replace('<', '&lt;')))
        return 'html-encoded';
    return 'raw';
}
