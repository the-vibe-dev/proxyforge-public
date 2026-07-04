// Test: browser scan driver — CDP/Playwright orchestrator for browser-required checks.
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

const mod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'electron', 'browserScanDriver.js'),
  path.join(__dirname, '..', 'dist-electron', 'browserScanDriver.js'),
]);

if (!mod) {
  console.log('SKIP: browser-scan-driver — dist-electron/electron/browserScanDriver.js not compiled, run tsc first.');
  process.exit(0);
}

const {
  isBrowserScanSupported,
  isPlaywrightAvailable,
  createBrowserScanSession,
  buildStubObservation,
  runBrowserScanSession,
} = mod;

// 1. isBrowserScanSupported returns boolean
assert.ok(typeof isBrowserScanSupported === 'function', 'isBrowserScanSupported must be a function');
const supported = isBrowserScanSupported();
assert.ok(typeof supported === 'boolean', `isBrowserScanSupported() should return boolean, got ${typeof supported}`);

// 2. isPlaywrightAvailable returns boolean
assert.ok(typeof isPlaywrightAvailable === 'function', 'isPlaywrightAvailable must be a function');
const pwAvailable = isPlaywrightAvailable();
assert.ok(typeof pwAvailable === 'boolean', `isPlaywrightAvailable() should return boolean, got ${typeof pwAvailable}`);

// 3. createBrowserScanSession returns correct shape
assert.ok(typeof createBrowserScanSession === 'function', 'createBrowserScanSession must be a function');
const session = createBrowserScanSession('https://example.com', ['dom-xss']);
assert.ok(session !== null && typeof session === 'object', 'createBrowserScanSession should return an object');
assert.ok(typeof session.sessionId === 'string' && session.sessionId.length > 0, 'session.sessionId should be a non-empty string');
assert.equal(session.targetUrl, 'https://example.com', 'session.targetUrl should match');
assert.deepEqual(session.checkIds, ['dom-xss'], 'session.checkIds should match');
assert.equal(session.status, 'pending', 'session.status should be "pending"');

// 4. buildStubObservation returns observation with correct fields
assert.ok(typeof buildStubObservation === 'function', 'buildStubObservation must be a function');
const obs = buildStubObservation(session.sessionId, 'dom-xss', 'alert-fired', 'Test detail');
assert.ok(obs !== null && typeof obs === 'object', 'buildStubObservation should return an object');
assert.equal(obs.sessionId, session.sessionId, 'obs.sessionId should match');
assert.equal(obs.checkId, 'dom-xss', 'obs.checkId should be "dom-xss"');
assert.equal(obs.signal, 'alert-fired', 'obs.signal should be "alert-fired"');
assert.equal(obs.detail, 'Test detail', 'obs.detail should match');
assert.ok(typeof obs.timestamp === 'string' && obs.timestamp.length > 0, 'obs.timestamp should be a non-empty string');

// 5. runBrowserScanSession returns a Promise resolving to the correct shape
assert.ok(typeof runBrowserScanSession === 'function', 'runBrowserScanSession must be a function');
const resultPromise = runBrowserScanSession(session);
assert.ok(resultPromise instanceof Promise, 'runBrowserScanSession should return a Promise');

const result = await resultPromise;
assert.ok(result !== null && typeof result === 'object', 'runBrowserScanSession should resolve to an object');
assert.equal(result.sessionId, session.sessionId, 'result.sessionId should match the session');
assert.ok(Array.isArray(result.observations), 'result.observations should be an array');
assert.ok(Array.isArray(result.confirmedCheckIds), 'result.confirmedCheckIds should be an array');
assert.ok(typeof result.durationMs === 'number' && result.durationMs >= 0, 'result.durationMs should be a non-negative number');

// 6. Multiple checkIds are preserved on the session
const multiSession = createBrowserScanSession('https://example.com', ['dom-xss', 'prototype-pollution-client', 'postmessage-misconfig']);
assert.equal(multiSession.checkIds.length, 3, 'session should hold all checkIds');
assert.equal(multiSession.status, 'pending', 'new session should always start as pending');

console.log(`PASS browser-scan-driver: isBrowserScanSupported=${supported}, session.sessionId=${session.sessionId.slice(0, 8)}…, durationMs=${result.durationMs}`);
