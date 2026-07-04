// Test: prototype pollution browser probe spec + browser oracle classification.
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function tryLoad(candidates) {
  for (const c of candidates) {
    try { return require(c); } catch { /* next */ }
  }
  return null;
}

// ── Part 1: browserScanWorker ─────────────────────────────────────────────────

const workerMod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'electron', 'browserScanWorker.js'),
  path.join(__dirname, '..', 'dist-electron', 'browserScanWorker.js'),
]);

if (!workerMod) {
  console.log('SKIP: scanner-proto-pollution-browser-fixture — dist-electron/electron/browserScanWorker.js not compiled, run tsc first.');
  process.exit(0);
}

const { buildPrototypePollutionProbeSpec, evaluateProbeResult } = workerMod;

// 1. buildPrototypePollutionProbeSpec returns spec with required fields
assert.ok(typeof buildPrototypePollutionProbeSpec === 'function', 'buildPrototypePollutionProbeSpec must be a function');
const spec = buildPrototypePollutionProbeSpec();
assert.ok(spec !== null && typeof spec === 'object', 'spec should be an object');
assert.equal(spec.checkId, 'prototype-pollution-client', 'spec.checkId should be "prototype-pollution-client"');
assert.equal(spec.expectedSignal, 'property-mutated', 'spec.expectedSignal should be "property-mutated"');
assert.ok(typeof spec.probeExpression === 'string' && spec.probeExpression.length > 0, 'spec.probeExpression should be a non-empty string');
assert.ok(typeof spec.timeoutMs === 'number' && spec.timeoutMs > 0, 'spec.timeoutMs should be a positive number');

// 2. evaluateProbeResult with rawResult=false → triggered:false
assert.ok(typeof evaluateProbeResult === 'function', 'evaluateProbeResult must be a function');
const notTriggered = evaluateProbeResult(spec, false);
assert.ok(notTriggered !== null && typeof notTriggered === 'object', 'evaluateProbeResult should return an object');
assert.equal(notTriggered.triggered, false, 'triggered should be false when rawResult=false');
assert.equal(notTriggered.checkId, 'prototype-pollution-client', 'checkId should be propagated');
assert.equal(notTriggered.signal, undefined, 'signal should be undefined when not triggered');

// 3. evaluateProbeResult with rawResult=true → triggered:true + signal
const triggered = evaluateProbeResult(spec, true);
assert.ok(triggered !== null && typeof triggered === 'object', 'evaluateProbeResult should return an object');
assert.equal(triggered.triggered, true, 'triggered should be true when rawResult=true');
assert.equal(triggered.signal, 'property-mutated', 'signal should be "property-mutated" when triggered');
assert.equal(triggered.checkId, 'prototype-pollution-client', 'checkId should be propagated');

// ── Part 2: browserOracle ─────────────────────────────────────────────────────

const oracleMod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'src', 'scanner', 'browserOracle.js'),
  path.join(__dirname, '..', 'dist-electron', 'scanner', 'browserOracle.js'),
]);

if (!oracleMod) {
  console.log('NOTE: scanner-proto-pollution-browser-fixture — browserOracle not compiled; skipping oracle assertions.');
  console.log('PASS scanner-proto-pollution-browser-fixture (worker portion only)');
  process.exit(0);
}

const { classifyBrowserObservations } = oracleMod;
assert.ok(typeof classifyBrowserObservations === 'function', 'classifyBrowserObservations must be a function');

// 4. classifyBrowserObservations([], []) returns null
const emptyResult = classifyBrowserObservations([], []);
assert.equal(emptyResult, null, 'Empty observations should return null');

// 5. A matching observation → non-null result with matched=true
//
// browserOracle.classifyBrowserObservations uses { type, value } observations and
// { payload } payloads. It checks if the payload string appears in the observation
// type+value concatenation (case-insensitive).
// We pass a property-mutated observation carrying our canary payload.
const ppObservations = [
  { type: 'property-mutated', value: '__proto__', timestamp: Date.now() },
];
const ppPayloads = [
  {
    payload: 'property-mutated',   // will appear in obs.type + obs.value join
    family: 'prototype-pollution-client',
    variantId: 'pp1',
  },
];
const matchResult = classifyBrowserObservations(ppObservations, ppPayloads);
assert.ok(matchResult !== null, 'Non-empty observations matching a payload should return non-null');
assert.ok(typeof matchResult === 'object', 'classifyBrowserObservations should return an object');
assert.ok('matched' in matchResult, 'result should have a "matched" field');
assert.equal(matchResult.matched, true, 'matched should be true when payload is found in observation');

console.log('PASS scanner-proto-pollution-browser-fixture: probe spec and oracle both functional.');
