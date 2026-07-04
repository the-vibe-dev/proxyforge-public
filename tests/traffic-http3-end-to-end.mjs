// Tests: http3Transport.ts — HTTP/3/QUIC transport stubs
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
  path.join(__dirname, '..', 'dist-electron', 'electron', 'traffic', 'http3Transport.js'),
  path.join(__dirname, '..', 'dist-electron', 'traffic', 'http3Transport.js'),
]);

if (!mod) {
  console.warn('[SKIP] traffic-http3-end-to-end: dist-electron not compiled');
  process.exit(0);
}

const {
  isHttp3Supported,
  getHttp3Capabilities,
  openHttp3Connection,
} = mod;

// 1. isHttp3Supported returns a boolean
assert.equal(typeof isHttp3Supported, 'function', 'isHttp3Supported is exported');
const supported = isHttp3Supported();
assert.equal(typeof supported, 'boolean', 'isHttp3Supported() returns boolean');
console.log('  [1] isHttp3Supported() =', supported);

// 2. getHttp3Capabilities returns object with version/supported info
assert.equal(typeof getHttp3Capabilities, 'function', 'getHttp3Capabilities is exported');
const caps = getHttp3Capabilities();
assert.equal(typeof caps, 'object', 'getHttp3Capabilities() returns object');
assert(caps !== null, 'capabilities is not null');
assert('supported' in caps, 'capabilities has supported field');
assert.equal(typeof caps.supported, 'boolean', 'caps.supported is boolean');
// version field may be null (no side-car) but must be present
assert('version' in caps, 'capabilities has version field');
console.log('  [2] getHttp3Capabilities() shape OK — supported:', caps.supported, 'version:', caps.version);

// 3. capabilities has reason string
assert('reason' in caps, 'capabilities has reason field');
assert.equal(typeof caps.reason, 'string', 'caps.reason is string');
assert(caps.reason.length > 0, 'caps.reason is non-empty');
console.log('  [3] caps.reason:', caps.reason);

// 4. openHttp3Connection resolves without throwing
assert.equal(typeof openHttp3Connection, 'function', 'openHttp3Connection is exported');
const connResult = await openHttp3Connection('https://example.com');
assert.equal(typeof connResult, 'object', 'openHttp3Connection returns object');
assert('connected' in connResult, 'result has connected field');
assert.equal(typeof connResult.connected, 'boolean', 'connected is boolean');
assert('url' in connResult, 'result has url field');
assert.equal(connResult.url, 'https://example.com', 'url is preserved in result');
console.log('  [4] openHttp3Connection("https://example.com") resolved, connected =', connResult.connected);

// 5. openHttp3Connection with options does not throw
const connWithOpts = await openHttp3Connection('https://target.example', {
  maxStreams: 100,
  idleTimeoutMs: 30000,
  allowInsecure: true,
});
assert.equal(typeof connWithOpts.connected, 'boolean', 'opts call returns boolean connected');
console.log('  [5] openHttp3Connection with opts resolved, connected =', connWithOpts.connected);

console.log('PASS traffic-http3-end-to-end');
