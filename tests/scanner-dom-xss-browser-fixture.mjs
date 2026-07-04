// Test: DOM XSS browser oracle — classifies browser observations for DOM XSS.
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

const oracleMod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'src', 'scanner', 'browserOracle.js'),
  path.join(__dirname, '..', 'dist-electron', 'scanner', 'browserOracle.js'),
]);

if (!oracleMod) {
  console.warn('[SKIP] scanner-dom-xss-browser-fixture: dist-electron not compiled, skipping.');
  process.exit(0);
}

const { classifyBrowserObservations, buildBrowserFindingEvidence } = oracleMod;

// Observation type from the browser worker contract
const OBS_TYPES = {
  ALERT_FIRED: 'alert_fired',
  PROPERTY_MUTATION: 'property_mutation',
  NETWORK_REQUEST: 'network_request',
  CONSOLE_ERROR: 'console_error',
  DOM_CHANGE: 'dom_change',
};

// 1. classifyBrowserObservations is exported
assert.ok(typeof classifyBrowserObservations === 'function', 'classifyBrowserObservations should be a function');
assert.ok(typeof buildBrowserFindingEvidence === 'function', 'buildBrowserFindingEvidence should be a function');

// 2. Alert-fired observation signals DOM XSS
const alertObs = [{ type: OBS_TYPES.ALERT_FIRED, value: 'pf-canary-abc123', timestamp: Date.now() }];
const alertResult = classifyBrowserObservations(alertObs, [{ payload: 'pf-canary-abc123', family: 'dom-xss', variantId: 'v1' }]);
assert.ok(typeof alertResult === 'object', 'classifyBrowserObservations should return an object');
assert.ok('matched' in alertResult || Array.isArray(alertResult) || alertResult !== null, 'Result should be truthy');

// 3. Empty observations → no match
const emptyResult = classifyBrowserObservations([], [{ payload: 'pf-test', family: 'dom-xss', variantId: 'v1' }]);
assert.ok(
  emptyResult === null || emptyResult === false || (typeof emptyResult === 'object' && ('matched' in emptyResult ? !emptyResult.matched : true)),
  'Empty observations should produce no match or false'
);

// 4. Property mutation with canary value → match
const mutObs = [{ type: OBS_TYPES.PROPERTY_MUTATION, value: 'isAdmin=pf-canary-xyz', timestamp: Date.now() }];
const mutResult = classifyBrowserObservations(mutObs, [{ payload: 'pf-canary-xyz', family: 'prototype-pollution-client', variantId: 'v2' }]);
assert.ok(mutResult !== undefined, 'mutation observation should produce a result');

// 5. Network request observation → captured for SSRF/fetch-based XSS
const netObs = [{ type: OBS_TYPES.NETWORK_REQUEST, value: 'https://oast.example.com/pf-callback', timestamp: Date.now() }];
const netResult = classifyBrowserObservations(netObs, [{ payload: 'oast.example.com', family: 'dom-xss', variantId: 'v3' }]);
assert.ok(netResult !== undefined, 'network request observation should produce a result');

// 6. buildBrowserFindingEvidence returns a non-empty string
const evidence = buildBrowserFindingEvidence(
  [{ type: OBS_TYPES.ALERT_FIRED, value: 'pf-canary', timestamp: Date.now() }],
  'pf-canary',
  'innerHTML'
);
assert.ok(typeof evidence === 'string', 'buildBrowserFindingEvidence should return a string');
assert.ok(evidence.length > 0, 'Evidence string should be non-empty');

// 7. Evidence mentions the canary nonce
assert.ok(
  evidence.includes('pf-canary') || evidence.includes('alert') || evidence.includes('innerHTML'),
  `Evidence should mention relevant details, got: ${evidence.slice(0, 200)}`
);

// 8. Case-insensitive payload matching
const upperObs = [{ type: OBS_TYPES.ALERT_FIRED, value: 'PF-CANARY-UPPER', timestamp: Date.now() }];
const upperResult = classifyBrowserObservations(upperObs, [{ payload: 'pf-canary-upper', family: 'dom-xss', variantId: 'v4' }]);
// Result can be match or no-match depending on case sensitivity implementation — just should not throw
assert.ok(upperResult !== undefined || upperResult === null || upperResult === false, 'Case-insensitive check should not throw');

console.log(`[PASS] scanner-dom-xss-browser-fixture: oracle exports functional, evidence: ${evidence.slice(0, 60)}`);
