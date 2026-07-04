// Phase 10b — DOM tracer engine end-to-end with a SPA-like fixture.
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let tracer, sinksData;
try {
  tracer = require('../dist-electron/src/domTracerEngine.js');
  sinksData = require('../dist-electron/src/data/domTracerSinks.js');
} catch {
  console.log('SKIP dom-tracer-fixture-spa (module not compiled)');
  process.exit(0);
}

const {
  createTracerSession,
  recordSourceEvent,
  recordSinkEvent,
  setCanary,
  getCanaryTraces,
  getHighValueSinks,
} = tracer;

const { DOM_TRACER_SINKS, getSinkDescriptor, getCriticalSinks } = sinksData;

// Create session simulating a SPA at /app
const session = createTracerSession('tab-spa-001', 'proj-spa', 'https://spa.example.com/app');
assert.ok(session.id, 'session has id');
assert.equal(session.status, 'active', 'session starts active');
assert.equal(session.tabId, 'tab-spa-001', 'tabId matches');
assert.equal(session.sources.length, 0, 'no sources initially');
assert.equal(session.sinks.length, 0, 'no sinks initially');
console.log('  createTracerSession for SPA: PASS');

// Inject multiple sources (SPA reads hash, search, and postMessage)
recordSourceEvent(session.id, 'location.hash', '#route=/profile&id=42', 'https://spa.example.com/app');
recordSourceEvent(session.id, 'location.search', '?debug=1', 'https://spa.example.com/app');
recordSourceEvent(session.id, 'postMessage', '{"type":"nav","path":"/admin"}', 'https://spa.example.com/app');

// Set canary from hash source
const canary = setCanary(session.id, 'location.hash');
assert.ok(canary, 'canary config returned');
assert.ok(canary.nonce.startsWith('pf-'), 'canary nonce has pf- prefix');
console.log('  setCanary: PASS');

// Inject sinks — one with canary nonce present, others without
const sinkWithCanary = recordSinkEvent(
  session.id,
  'innerHTML',
  `<span class="username">${canary.nonce}</span>`,
  'https://spa.example.com/app',
);
assert.ok(sinkWithCanary, 'innerHTML sink recorded');
assert.equal(sinkWithCanary.canaryMatched, true, 'canary matched in innerHTML sink');

recordSinkEvent(session.id, 'eval', 'updateRoute()', 'https://spa.example.com/app');
recordSinkEvent(session.id, 'location.href', 'https://spa.example.com/profile', 'https://spa.example.com/app');
recordSinkEvent(session.id, 'fetch.url', 'https://api.example.com/data', 'https://spa.example.com/app');
console.log('  Source and sink injection: PASS');

// getCanaryTraces returns only sinks where nonce matched
const traces = getCanaryTraces(session.id);
assert.equal(traces.length, 1, 'only one canary trace (innerHTML)');
assert.equal(traces[0].sink, 'innerHTML', 'canary trace is the innerHTML sink');
assert.equal(traces[0].canaryMatched, true, 'canaryMatched flag set on trace');
console.log('  getCanaryTraces: PASS');

// getHighValueSinks returns eval/innerHTML sinks
const highValue = getHighValueSinks(session.id);
assert.ok(highValue.length >= 2, 'at least 2 high-value sinks (innerHTML + eval)');
assert.ok(highValue.some((s) => s.sink === 'innerHTML'), 'innerHTML in high-value sinks');
assert.ok(highValue.some((s) => s.sink === 'eval'), 'eval in high-value sinks');
console.log('  getHighValueSinks: PASS');

// Session source/sink counts are correct after recording
const sessionRef = tracer.getTracerSession(session.id);
assert.ok(sessionRef, 'session still accessible');
assert.equal(sessionRef.sources.length, 3, '3 source events recorded');
assert.equal(sessionRef.sinks.length, 4, '4 sink events recorded');
console.log('  Session source/sink counts: PASS');

// getSinkDescriptor('innerHTML') returns descriptor with severity 'high'
const inlineDescriptor = getSinkDescriptor('innerHTML');
assert.ok(inlineDescriptor, 'innerHTML descriptor returned');
assert.equal(inlineDescriptor.id, 'innerHTML', 'descriptor id matches');
assert.equal(inlineDescriptor.severity, 'high', 'innerHTML severity is high');
assert.ok(typeof inlineDescriptor.description === 'string', 'descriptor has description');
assert.ok(typeof inlineDescriptor.cweId === 'string', 'descriptor has cweId');
console.log('  getSinkDescriptor(innerHTML): PASS');

// getCriticalSinks() returns eval, Function, document.write etc.
const criticalSinks = getCriticalSinks();
assert.ok(Array.isArray(criticalSinks), 'getCriticalSinks returns array');
assert.ok(criticalSinks.length >= 3, 'at least 3 critical sinks');
const criticalIds = criticalSinks.map((s) => s.id);
assert.ok(criticalIds.includes('eval'), 'eval is critical');
assert.ok(criticalIds.includes('Function'), 'Function is critical');
assert.ok(criticalIds.includes('document.write'), 'document.write is critical');
assert.ok(criticalSinks.every((s) => s.severity === 'critical'), 'all returned sinks have critical severity');
console.log('  getCriticalSinks: PASS');

// DOM_TRACER_SINKS.length >= 15 (enough sinks registered)
assert.ok(Array.isArray(DOM_TRACER_SINKS), 'DOM_TRACER_SINKS is an array');
assert.ok(DOM_TRACER_SINKS.length >= 15, `at least 15 sinks registered (got ${DOM_TRACER_SINKS.length})`);
assert.ok(
  DOM_TRACER_SINKS.every((s) => s.id && s.category && s.severity && s.description),
  'all sink descriptors have required fields',
);
console.log(`  DOM_TRACER_SINKS.length >= 15 (got ${DOM_TRACER_SINKS.length}): PASS`);

console.log('PASS dom-tracer-fixture-spa');
