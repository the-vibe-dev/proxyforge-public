// Tests for domTracerEngine + domTracerSinks — redirect/location sink detection
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
let tracer, sinksData;
try {
  tracer = require('../dist-electron/src/domTracerEngine.js');
  sinksData = require('../dist-electron/src/data/domTracerSinks.js');
} catch {
  console.log('SKIP dom-tracer-redirect-scheme (module not compiled)');
  process.exit(0);
}

const {
  createTracerSession,
  recordSinkEvent,
  setCanary,
  getCanaryTraces,
} = tracer;

const { DOM_TRACER_SINKS, getSinkDescriptor } = sinksData;

// Create a session for redirect testing
const session = createTracerSession('tab-redirect-001', 'proj-redirect', 'https://app.example.com/');
assert.ok(session.id, 'session has id');

const canary = setCanary(session.id, 'location.hash');
assert.ok(canary, 'canary configured');
const canaryNonce = canary.nonce;

// 1. recordSinkEvent for location.href with javascript: and matching nonce → canaryMatched: true
const locationHrefValue = `javascript:alert(${canaryNonce})`;
const sinkEvt = recordSinkEvent(session.id, 'location.href', locationHrefValue, 'https://app.example.com/');
assert.ok(sinkEvt, 'location.href sink event recorded');
assert.equal(sinkEvt.canaryMatched, true, 'canaryMatched is true for location.href sink containing nonce');
assert.equal(sinkEvt.sink, 'location.href', 'sink type is location.href');
console.log('  [1] location.href with canary nonce reports canaryMatched:true: PASS');

// 2. location.href sink has medium severity in sink descriptors
const locationHrefDescriptor = getSinkDescriptor('location.href');
assert.ok(locationHrefDescriptor, 'location.href descriptor exists');
assert.equal(locationHrefDescriptor.severity, 'medium', 'location.href severity is medium');
assert.equal(locationHrefDescriptor.category, 'navigation', 'location.href category is navigation');
console.log('  [2] location.href sink has medium severity: PASS');

// 3. getCanaryTraces after recording a matching location.href sink returns non-empty trace
const traces = getCanaryTraces(session.id);
assert.ok(Array.isArray(traces), 'getCanaryTraces returns array');
assert.ok(traces.length > 0, 'at least one canary trace after recording matching sink');
console.log('  [3] getCanaryTraces returns non-empty trace: PASS');

// 4. Trace has expected fields: sinkId (sink), sinkName (sink), canaryNonce, value
const trace = traces[0];
assert.ok(trace.sink, 'trace has sink field');
assert.equal(trace.sink, 'location.href', 'trace sinkName is location.href');
assert.equal(trace.canaryMatched, true, 'trace has canaryMatched true');
assert.ok(trace.value, 'trace has value field');
assert.ok(trace.value.includes(canaryNonce), 'trace value contains the canary nonce');
assert.ok(trace.sessionId, 'trace has sessionId field');
assert.ok(trace.id, 'trace has id field');
console.log('  [4] trace has expected fields (sink, canaryMatched, value, sessionId, id): PASS');

// Additional coverage: location.assign and location.replace also exist and have medium severity
const locationAssignDescriptor = getSinkDescriptor('location.assign');
assert.ok(locationAssignDescriptor, 'location.assign descriptor exists');
assert.equal(locationAssignDescriptor.severity, 'medium', 'location.assign severity is medium');

const locationReplaceDescriptor = getSinkDescriptor('location.replace');
assert.ok(locationReplaceDescriptor, 'location.replace descriptor exists');
assert.equal(locationReplaceDescriptor.severity, 'medium', 'location.replace severity is medium');
console.log('  location.assign + location.replace descriptors valid: PASS');

// Non-matching sink (no nonce) should have canaryMatched: false
const safeRedirect = recordSinkEvent(session.id, 'location.href', 'https://app.example.com/safe', 'https://app.example.com/');
assert.ok(safeRedirect, 'safe redirect sink recorded');
assert.equal(safeRedirect.canaryMatched, false, 'non-matching sink has canaryMatched: false');
console.log('  non-matching location.href sink has canaryMatched:false: PASS');

console.log('PASS dom-tracer-redirect-scheme');
