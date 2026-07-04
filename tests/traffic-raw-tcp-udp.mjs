// Tests: rawTcpUdp.ts — raw TCP/UDP transport stubs
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
  path.join(__dirname, '..', 'dist-electron', 'electron', 'traffic', 'rawTcpUdp.js'),
  path.join(__dirname, '..', 'dist-electron', 'traffic', 'rawTcpUdp.js'),
]);

if (!mod) {
  console.warn('[SKIP] traffic-raw-tcp-udp: dist-electron not compiled');
  process.exit(0);
}

const {
  getRawTransportCapabilities,
  openRawTcpSocket,
  openRawUdpSocket,
} = mod;

// 1. getRawTransportCapabilities returns an object
assert.equal(typeof getRawTransportCapabilities, 'function', 'getRawTransportCapabilities is exported');
const caps = getRawTransportCapabilities();
assert.equal(typeof caps, 'object', 'getRawTransportCapabilities() returns object');
assert(caps !== null, 'capabilities is not null');
console.log('  [1] getRawTransportCapabilities() returns object');

// 2. capabilities has tcp and udp fields (or a top-level supported field)
const hasFields =
  ('tcp' in caps && 'udp' in caps) || ('supported' in caps);
assert(hasFields, 'capabilities has tcp+udp fields or supported field');
if ('tcp' in caps && 'udp' in caps) {
  assert.equal(typeof caps.tcp, 'object', 'caps.tcp is object');
  assert.equal(typeof caps.udp, 'object', 'caps.udp is object');
  console.log('  [2] caps has tcp:', JSON.stringify(caps.tcp), 'udp:', JSON.stringify(caps.udp));
} else {
  console.log('  [2] caps.supported =', caps.supported);
}

// 3. openRawTcpSocket with an invalid host does not throw synchronously
assert.equal(typeof openRawTcpSocket, 'function', 'openRawTcpSocket is exported');
const tcpResult = await openRawTcpSocket('', 80);
assert.equal(typeof tcpResult, 'object', 'openRawTcpSocket returns object');
assert('opened' in tcpResult, 'tcp result has opened field');
assert.equal(typeof tcpResult.opened, 'boolean', 'opened is boolean');
console.log('  [3] openRawTcpSocket("", 80) resolved, opened =', tcpResult.opened);

// 4. openRawUdpSocket with an invalid host does not throw synchronously
assert.equal(typeof openRawUdpSocket, 'function', 'openRawUdpSocket is exported');
const udpResult = await openRawUdpSocket('', 53);
assert.equal(typeof udpResult, 'object', 'openRawUdpSocket returns object');
assert('opened' in udpResult, 'udp result has opened field');
assert.equal(typeof udpResult.opened, 'boolean', 'opened is boolean');
console.log('  [4] openRawUdpSocket("", 53) resolved, opened =', udpResult.opened);

// 5. Valid host/port call also resolves (stub always returns opened: false)
const tcpValid = await openRawTcpSocket('localhost', 8080);
assert.equal(typeof tcpValid.opened, 'boolean', 'valid tcp call opened is boolean');
console.log('  [5] openRawTcpSocket("localhost", 8080) resolved, opened =', tcpValid.opened);

console.log('PASS traffic-raw-tcp-udp');
