// Phase 10b — Tests for domTracerEngine.ts
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let tracer;
try {
  tracer = require('../dist-electron/src/domTracerEngine.js');
} catch {
  console.log('SKIP dom-tracer-canary-reflection (module not compiled)');
  process.exit(0);
}

const {
  createTracerSession, getTracerSession, stopTracerSession,
  recordSourceEvent, recordSinkEvent, setCanary, clearCanary,
  getCanaryTraces, getHighValueSinks, getAllSessions,
} = tracer;

// Create session
const session = createTracerSession('tab-001', 'proj-test', 'https://app.example.com/');
assert.ok(session.id, 'session has id');
assert.equal(session.status, 'active', 'session starts active');
assert.equal(session.tabId, 'tab-001', 'tabId set');
assert.equal(session.sources.length, 0, 'no sources yet');
assert.equal(session.sinks.length, 0, 'no sinks yet');
console.log('  createTracerSession: PASS');

// getTracerSession round-trip
const fetched = getTracerSession(session.id);
assert.equal(fetched?.id, session.id, 'session retrieved');
console.log('  getTracerSession: PASS');

// Record source event
const srcEvt = recordSourceEvent(session.id, 'location.hash', '#user=alice', 'https://app.example.com/');
assert.ok(srcEvt, 'source event recorded');
assert.equal(srcEvt.source, 'location.hash', 'source kind');
assert.equal(srcEvt.value, '#user=alice', 'source value');
console.log('  recordSourceEvent: PASS');

// Set canary
const canary = setCanary(session.id, 'location.hash');
assert.ok(canary, 'canary set');
assert.ok(canary.nonce.startsWith('pf-'), 'canary nonce has pf- prefix');
console.log('  setCanary: PASS');

// Record sink event — canary matched
const sinkWithCanary = recordSinkEvent(session.id, 'innerHTML', `<div>${canary.nonce}</div>`, 'https://app.example.com/');
assert.ok(sinkWithCanary, 'sink recorded with canary');
assert.equal(sinkWithCanary?.canaryMatched, true, 'canary matched in sink');
assert.ok(sinkWithCanary?.canaryTransformation, 'transformation detected');
console.log('  canary detection in sink: PASS');

// Record sink without canary match
const sinkNoCanary = recordSinkEvent(session.id, 'eval', 'console.log("safe")', 'https://app.example.com/');
assert.equal(sinkNoCanary?.canaryMatched, false, 'no canary in safe eval');
console.log('  sink without canary: PASS');

// getCanaryTraces
const traces = getCanaryTraces(session.id);
assert.equal(traces.length, 1, 'one canary trace');
assert.equal(traces[0].sink, 'innerHTML', 'correct sink in trace');
console.log('  getCanaryTraces: PASS');

// getHighValueSinks
const highValue = getHighValueSinks(session.id);
assert.ok(highValue.length >= 2, 'innerHTML + eval are high value');
assert.ok(highValue.some((s) => s.sink === 'innerHTML'), 'innerHTML in high value');
assert.ok(highValue.some((s) => s.sink === 'eval'), 'eval in high value');
console.log('  getHighValueSinks: PASS');

// Stop session — recording after stop returns null
stopTracerSession(session.id);
assert.equal(getTracerSession(session.id)?.status, 'stopped', 'session stopped');
const afterStop = recordSourceEvent(session.id, 'location.search', '?x=1', 'https://app.example.com/');
assert.equal(afterStop, null, 'recording after stop returns null');
console.log('  stop session: PASS');

// null for unknown session
assert.equal(getTracerSession('nonexistent'), null, 'null for unknown session');
assert.equal(setCanary('nonexistent', 'location.hash'), null, 'setCanary on nonexistent → null');
console.log('  unknown session guards: PASS');

console.log('PASS dom-tracer-canary-reflection');
