// Tests: wireguardMode.ts — WireGuard capture mode stubs
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
  path.join(__dirname, '..', 'dist-electron', 'electron', 'traffic', 'wireguardMode.js'),
  path.join(__dirname, '..', 'dist-electron', 'traffic', 'wireguardMode.js'),
]);

if (!mod) {
  console.warn('[SKIP] traffic-wireguard: dist-electron not compiled');
  process.exit(0);
}

const {
  isWireguardSupported,
  getWireguardCapabilities,
  startWireguardCapture,
  stopWireguardCapture,
} = mod;

// 1. isWireguardSupported returns a boolean
assert.equal(typeof isWireguardSupported, 'function', 'isWireguardSupported is exported');
const supported = isWireguardSupported();
assert.equal(typeof supported, 'boolean', 'isWireguardSupported() returns boolean');
console.log('  [1] isWireguardSupported() =', supported);

// 2. getWireguardCapabilities returns object with supported field
assert.equal(typeof getWireguardCapabilities, 'function', 'getWireguardCapabilities is exported');
const caps = getWireguardCapabilities();
assert.equal(typeof caps, 'object', 'getWireguardCapabilities() returns object');
assert(caps !== null, 'capabilities is not null');
assert('supported' in caps, 'capabilities has supported field');
assert.equal(typeof caps.supported, 'boolean', 'caps.supported is boolean');
assert('reason' in caps, 'capabilities has reason field');
assert.equal(typeof caps.reason, 'string', 'caps.reason is string');
console.log('  [2] getWireguardCapabilities() — supported:', caps.supported, 'reason:', caps.reason);

// 3. stopWireguardCapture with a nonexistent session does not throw
assert.equal(typeof stopWireguardCapture, 'function', 'stopWireguardCapture is exported');
const stopResult = await stopWireguardCapture('nonexistent-wg-session');
assert.equal(typeof stopResult, 'object', 'stopWireguardCapture returns object');
assert('stopped' in stopResult, 'stop result has stopped field');
assert.equal(typeof stopResult.stopped, 'boolean', 'stopped is boolean');
console.log('  [3] stopWireguardCapture("nonexistent-wg-session") resolved, stopped =', stopResult.stopped);

// 4. startWireguardCapture returns a session result
assert.equal(typeof startWireguardCapture, 'function', 'startWireguardCapture is exported');
const startResult = await startWireguardCapture({
  interface: 'wg0',
  peerEndpoint: '10.0.0.1:51820',
  allowedIps: ['0.0.0.0/0'],
});
assert.equal(typeof startResult, 'object', 'startWireguardCapture returns object');
assert('sessionId' in startResult, 'start result has sessionId field');
assert('started' in startResult, 'start result has started field');
assert.equal(typeof startResult.started, 'boolean', 'started is boolean');
console.log('  [4] startWireguardCapture() returned sessionId:', startResult.sessionId, 'started:', startResult.started);

// 5. platform field is present in capabilities
assert('platform' in caps, 'capabilities has platform field');
assert.equal(typeof caps.platform, 'string', 'caps.platform is string');
console.log('  [5] caps.platform:', caps.platform);

console.log('PASS traffic-wireguard');
