// Tests for http2Transport and http2Alpn modules.

import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

let transport;
let alpn;

try {
  transport = require('../dist-electron/traffic/http2Transport.js');
  alpn = require('../dist-electron/traffic/http2Alpn.js');
} catch (err) {
  console.log(`SKIP: compiled modules not found (${err.message})`);
  process.exit(0);
}

const { parseHttp2Headers, buildHttp2Headers } = transport;
const { SUPPORTED_ALPN_PROTOCOLS, shouldUpgradeToH2, stripH2cUpgradeHeaders } = alpn;

// ---------------------------------------------------------------------------
// parseHttp2Headers
// ---------------------------------------------------------------------------

{
  const raw = {
    ':method': 'GET',
    ':path': '/api/v1/users',
    ':scheme': 'https',
    ':authority': 'example.com',
    'content-type': 'application/json',
    'x-custom': 'value',
    'accept': 'text/html',
  };

  const result = parseHttp2Headers(raw);

  assert.ok(!(':method' in result), 'should strip :method');
  assert.ok(!(':path' in result), 'should strip :path');
  assert.ok(!(':scheme' in result), 'should strip :scheme');
  assert.ok(!(':authority' in result), 'should strip :authority');
  assert.equal(result['content-type'], 'application/json', 'should keep content-type');
  assert.equal(result['x-custom'], 'value', 'should keep x-custom');
  assert.equal(result['accept'], 'text/html', 'should keep accept');

  console.log('PASS parseHttp2Headers strips pseudo-headers and keeps regular headers');
}

{
  // Array values should be joined
  const raw = {
    ':method': 'POST',
    'set-cookie': ['a=1', 'b=2'],
  };

  const result = parseHttp2Headers(raw);
  assert.ok(!(':method' in result), 'should strip :method');
  assert.equal(result['set-cookie'], 'a=1, b=2', 'should join array values');

  console.log('PASS parseHttp2Headers joins array header values');
}

{
  // Empty headers object
  const result = parseHttp2Headers({});
  assert.deepEqual(result, {}, 'should return empty object for empty input');

  console.log('PASS parseHttp2Headers handles empty headers');
}

// ---------------------------------------------------------------------------
// buildHttp2Headers
// ---------------------------------------------------------------------------

{
  const result = buildHttp2Headers('GET', '/search?q=test', 'api.example.com', {
    accept: 'application/json',
    'x-request-id': 'abc123',
  });

  assert.equal(result[':method'], 'GET', 'should set :method');
  assert.equal(result[':path'], '/search?q=test', 'should set :path');
  assert.equal(result[':scheme'], 'https', 'should set :scheme to https');
  assert.equal(result[':authority'], 'api.example.com', 'should set :authority');
  assert.equal(result['accept'], 'application/json', 'should include regular headers');
  assert.equal(result['x-request-id'], 'abc123', 'should include x-request-id');

  console.log('PASS buildHttp2Headers includes all four pseudo-headers plus regular headers');
}

{
  // Method should be uppercased
  const result = buildHttp2Headers('post', '/data', 'host.test', {});
  assert.equal(result[':method'], 'POST', 'should uppercase method');

  console.log('PASS buildHttp2Headers uppercases the method');
}

{
  // Caller-supplied pseudo-headers in headers map should be ignored
  const result = buildHttp2Headers('GET', '/', 'host.test', {
    ':method': 'DELETE', // should be ignored
    'x-real': 'yes',
  });
  assert.equal(result[':method'], 'GET', 'should ignore caller pseudo-headers in headers map');
  assert.equal(result['x-real'], 'yes', 'should keep regular headers');

  console.log('PASS buildHttp2Headers ignores pseudo-headers passed in headers map');
}

// ---------------------------------------------------------------------------
// SUPPORTED_ALPN_PROTOCOLS
// ---------------------------------------------------------------------------

{
  assert.ok(Array.isArray(SUPPORTED_ALPN_PROTOCOLS), 'should be an array');
  assert.ok(SUPPORTED_ALPN_PROTOCOLS.includes('h2'), 'should include h2');
  assert.ok(SUPPORTED_ALPN_PROTOCOLS.includes('http/1.1'), 'should include http/1.1');

  console.log('PASS SUPPORTED_ALPN_PROTOCOLS contains h2 and http/1.1');
}

// ---------------------------------------------------------------------------
// shouldUpgradeToH2
// ---------------------------------------------------------------------------

{
  assert.equal(
    shouldUpgradeToH2({ upgrade: 'h2c' }),
    true,
    'should return true for upgrade: h2c',
  );

  assert.equal(
    shouldUpgradeToH2({ upgrade: 'h2c', connection: 'Upgrade' }),
    true,
    'should return true for upgrade + connection headers',
  );

  assert.equal(
    shouldUpgradeToH2({ upgrade: 'websocket' }),
    false,
    'should return false for websocket upgrade',
  );

  assert.equal(
    shouldUpgradeToH2({}),
    false,
    'should return false for no upgrade headers',
  );

  console.log('PASS shouldUpgradeToH2 correctly identifies h2c upgrade headers');
}

// ---------------------------------------------------------------------------
// stripH2cUpgradeHeaders
// ---------------------------------------------------------------------------

{
  const headers = {
    'host': 'example.com',
    'upgrade': 'h2c',
    'connection': 'Upgrade',
    'http2-settings': 'AAMAAABkAAQAAP__',
    'content-type': 'application/json',
    'x-custom': 'value',
  };

  const result = stripH2cUpgradeHeaders(headers);

  assert.ok(!('upgrade' in result), 'should remove Upgrade');
  assert.ok(!('http2-settings' in result), 'should remove HTTP2-Settings');
  assert.ok(!result['connection'] || !result['connection'].toLowerCase().includes('upgrade'),
    'should remove upgrade token from Connection');
  assert.equal(result['host'], 'example.com', 'should keep host');
  assert.equal(result['content-type'], 'application/json', 'should keep content-type');
  assert.equal(result['x-custom'], 'value', 'should keep x-custom');

  console.log('PASS stripH2cUpgradeHeaders removes Upgrade/Connection/HTTP2-Settings');
}

{
  // When Connection has multiple tokens, keep non-upgrade ones
  const headers = {
    'connection': 'keep-alive, Upgrade',
    'upgrade': 'h2c',
  };
  const result = stripH2cUpgradeHeaders(headers);
  assert.ok(!('upgrade' in result), 'should remove upgrade');
  if ('connection' in result) {
    assert.ok(
      !result['connection'].toLowerCase().includes('upgrade'),
      'upgrade token should be removed from connection',
    );
    assert.ok(
      result['connection'].toLowerCase().includes('keep-alive'),
      'keep-alive token should remain',
    );
  }

  console.log('PASS stripH2cUpgradeHeaders keeps non-upgrade Connection tokens');
}

console.log('\nAll traffic-http2-transport tests passed.');
