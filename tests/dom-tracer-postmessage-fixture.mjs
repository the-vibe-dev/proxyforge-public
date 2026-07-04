// Tests for domTracerEngine.ts — postMessage source scenario
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let tracer;
try {
  tracer = require('../dist-electron/src/domTracerEngine.js');
} catch {
  console.log('SKIP dom-tracer-postmessage-fixture (module not compiled)');
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

// 1. createTracerSession creates a new session
const session = createTracerSession('tab-pm-001', 'proj-pm', 'https://app.example.com/');
assert.ok(session, 'session object returned');
assert.ok(session.id, 'session has an id');
assert.equal(session.status, 'active', 'session starts active');
assert.equal(session.tabId, 'tab-pm-001', 'tabId is set correctly');
assert.equal(session.projectId, 'proj-pm', 'projectId is set correctly');
assert.equal(session.sources.length, 0, 'no sources initially');
assert.equal(session.sinks.length, 0, 'no sinks initially');
console.log('  [1] createTracerSession creates a new session: PASS');

// Set up canary so we can verify canaryMatched below
const canary = setCanary(session.id, 'postMessage');
assert.ok(canary, 'canary configured');
assert.ok(canary.nonce.startsWith('pf-'), 'canary nonce has pf- prefix');
const canaryNonce = canary.nonce;

// 2. recordSourceEvent with postMessage records a source
const postMessageValue = JSON.stringify({ data: `<${canaryNonce}>`, origin: 'https://attacker.com' });
const srcEvt = recordSourceEvent(session.id, 'postMessage', postMessageValue, 'https://app.example.com/');
assert.ok(srcEvt, 'postMessage source event recorded');
assert.equal(srcEvt.source, 'postMessage', 'source type is postMessage');
assert.equal(srcEvt.value, postMessageValue, 'source value matches');
assert.equal(srcEvt.sessionId, session.id, 'sessionId on source event matches session');
console.log('  [2] recordSourceEvent for postMessage records source: PASS');

// 3. recordSinkEvent with the canary nonce in the value reports canaryMatched: true
const sinkValue = `<img src=x onerror="${canaryNonce}">`;
const sinkEvt = recordSinkEvent(session.id, 'innerHTML', sinkValue, 'https://app.example.com/');
assert.ok(sinkEvt, 'sink event recorded');
assert.equal(sinkEvt.canaryMatched, true, 'canaryMatched is true when nonce present in sink value');
console.log('  [3] recordSinkEvent with canary nonce reports canaryMatched:true: PASS');

// 4. getHighValueSinks includes the matched sink
const highValue = getHighValueSinks(session.id);
assert.ok(Array.isArray(highValue), 'getHighValueSinks returns array');
assert.ok(highValue.length > 0, 'at least one high-value sink recorded');
const matchedHighValue = highValue.find((s) => s.canaryMatched === true);
assert.ok(matchedHighValue, 'the canary-matched sink is in high-value sinks');
assert.equal(matchedHighValue.sink, 'innerHTML', 'matched high-value sink is innerHTML');
console.log('  [4] getHighValueSinks includes the matched sink: PASS');

// 5. Source event with postMessage has correct type field
const sessionRef = tracer.getTracerSession(session.id);
assert.ok(sessionRef, 'session accessible');
const pmSources = sessionRef.sources.filter((e) => e.source === 'postMessage');
assert.equal(pmSources.length, 1, 'exactly one postMessage source');
assert.equal(pmSources[0].source, 'postMessage', 'source event type is postMessage');
assert.ok(pmSources[0].value.includes('attacker.com'), 'origin is captured in source value');
console.log('  [5] postMessage source event has correct type: PASS');

// Bonus: getCanaryTraces returns the matched sink
const traces = getCanaryTraces(session.id);
assert.ok(traces.length >= 1, 'at least one canary trace');
assert.ok(traces.some((t) => t.sink === 'innerHTML'), 'innerHTML trace present');
console.log('  getCanaryTraces includes matched sink: PASS');

console.log('PASS dom-tracer-postmessage-fixture');
