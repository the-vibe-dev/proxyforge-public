// Tests: transparentMode.ts — TPROXY side-car stubs
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

function tryLoad(candidates) {
  for (const c of candidates) {
    try { return require(c); } catch { }
  }
  return null;
}

const mod = tryLoad([
  path.join(__dirname, '..', 'dist-electron', 'electron', 'traffic', 'transparentMode.js'),
  path.join(__dirname, '..', 'dist-electron', 'traffic', 'transparentMode.js'),
]);

if (!mod) {
  console.warn('[SKIP] traffic-transparent-linux: dist-electron not compiled');
  process.exit(0);
}

const {
  isTransparentModeSupported,
  getTransparentModeCapabilities,
  startTransparentCapture,
  stopTransparentCapture,
} = mod;

// 1. isTransparentModeSupported returns a boolean
assert.equal(typeof isTransparentModeSupported, 'function', 'isTransparentModeSupported is exported');
const supported = isTransparentModeSupported();
assert.equal(typeof supported, 'boolean', 'isTransparentModeSupported() returns boolean');
console.log('  [1] isTransparentModeSupported() returns boolean:', supported);

// 2. getTransparentModeCapabilities returns an object with a supported field
assert.equal(typeof getTransparentModeCapabilities, 'function', 'getTransparentModeCapabilities is exported');
const caps = getTransparentModeCapabilities();
assert.equal(typeof caps, 'object', 'getTransparentModeCapabilities() returns object');
assert(caps !== null, 'capabilities object is not null');
assert('supported' in caps, 'capabilities has supported field');
assert.equal(typeof caps.supported, 'boolean', 'capabilities.supported is boolean');
assert('reason' in caps, 'capabilities has reason field');
assert.equal(typeof caps.reason, 'string', 'capabilities.reason is string');
assert('platform' in caps, 'capabilities has platform field');
console.log('  [2] getTransparentModeCapabilities() shape OK, supported =', caps.supported);

// 3. stopTransparentCapture with a nonexistent session does not throw
assert.equal(typeof stopTransparentCapture, 'function', 'stopTransparentCapture is exported');
const stopResult = await stopTransparentCapture('nonexistent-session-id');
assert.equal(typeof stopResult, 'object', 'stopTransparentCapture returns object');
assert('stopped' in stopResult, 'stop result has stopped field');
console.log('  [3] stopTransparentCapture("nonexistent") resolved gracefully, stopped =', stopResult.stopped);

// 4. startTransparentCapture returns a session result object
assert.equal(typeof startTransparentCapture, 'function', 'startTransparentCapture is exported');
const startResult = await startTransparentCapture({ interface: 'eth0', ports: [80, 443] });
assert.equal(typeof startResult, 'object', 'startTransparentCapture returns object');
assert('sessionId' in startResult, 'start result has sessionId field');
assert('started' in startResult, 'start result has started field');
assert.equal(typeof startResult.started, 'boolean', 'started is boolean');
console.log('  [4] startTransparentCapture() returned sessionId:', startResult.sessionId);

console.log('PASS traffic-transparent-linux');
