// Tests: ReverseServer — HTTP reverse proxy to a configured upstream origin
import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';
import net from 'node:net';

const require = createRequire(import.meta.url);
const { ReverseServer } = require('../dist-electron/traffic/reverseMode.js');

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function close(server) {
  await new Promise((resolve) => {
    server.close(() => resolve());
  });
}

function httpGet(port, path = '/', headers = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { hostname: '127.0.0.1', port, path, method: 'GET', headers },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') })
        );
      }
    );
    req.once('error', reject);
    req.end();
  });
}

function httpPost(port, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const bodyBuf = Buffer.from(body);
    const req = http.request(
      {
        hostname: '127.0.0.1',
        port,
        path,
        method: 'POST',
        headers: { 'Content-Length': bodyBuf.length, ...headers },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () =>
          resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') })
        );
      }
    );
    req.once('error', reject);
    req.write(bodyBuf);
    req.end();
  });
}

// ─── Tests ───────────────────────────────────────────────────────────────────

let upstream;
let reverseProxy;

try {
  // Stand up a minimal upstream HTTP server
  upstream = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      if (req.url === '/ping') {
        res.writeHead(200, { 'content-type': 'text/plain', 'x-upstream': 'true' });
        res.end('pong');
        return;
      }
      if (req.url === '/echo' && req.method === 'POST') {
        res.writeHead(201, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ received: body, host: req.headers['host'] }));
        return;
      }
      if (req.url === '/headers') {
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ host: req.headers['host'] }));
        return;
      }
      res.writeHead(404, { 'content-type': 'text/plain' });
      res.end('not found');
    });
  });

  const upstreamPort = await listen(upstream);

  reverseProxy = new ReverseServer();
  const requestLogs = [];
  reverseProxy.on('request', (log) => requestLogs.push(log));

  const persistedConfigs = [];
  await reverseProxy.start(
    {
      listenPort: 0,
      listenHost: '127.0.0.1',
      targetHost: '127.0.0.1',
      targetPort: upstreamPort,
      targetScheme: 'http',
    },
    (cfg) => persistedConfigs.push(cfg),
  );

  const { port: proxyPort } = reverseProxy.address();

  // ── Test 1: Basic GET forwarding ───────────────────────────────────────────
  {
    const resp = await httpGet(proxyPort, '/ping');
    assert.equal(resp.status, 200, 'Reverse proxy should forward GET and relay 200');
    assert.equal(resp.body, 'pong', 'Response body should be relayed from upstream');
    assert.equal(resp.headers['x-upstream'], 'true', 'Upstream response headers should be preserved');
  }

  // ── Test 2: POST body forwarding ──────────────────────────────────────────
  {
    const resp = await httpPost(proxyPort, '/echo', 'hello-reverse');
    assert.equal(resp.status, 201, 'Reverse proxy should forward POST and relay 201');
    const json = JSON.parse(resp.body);
    assert.equal(json.received, 'hello-reverse', 'POST body should arrive at upstream');
  }

  // ── Test 3: Host header rewritten to target ───────────────────────────────
  {
    const resp = await httpGet(proxyPort, '/headers');
    const json = JSON.parse(resp.body);
    assert.match(json.host, /127\.0\.0\.1/, 'Host header should be rewritten to the target');
  }

  // ── Test 4: 404 from upstream is relayed ──────────────────────────────────
  {
    const resp = await httpGet(proxyPort, '/no-such-path');
    assert.equal(resp.status, 404, '404 from upstream should be relayed to client');
  }

  // ── Test 5: Request log populated ─────────────────────────────────────────
  {
    // Let async log entries settle
    await new Promise((r) => setTimeout(r, 50));
    assert(requestLogs.length >= 3, 'At least 3 requests should be logged');
    const pingLog = requestLogs.find((l) => l.path === '/ping');
    assert(pingLog, 'GET /ping should be in the request log');
    assert.equal(pingLog.method, 'GET');
    assert.equal(pingLog.statusCode, 200);
    assert(typeof pingLog.durationMs === 'number');
    assert(pingLog.id.startsWith('rev-'));
  }

  // ── Test 6: persistFn was called on start ─────────────────────────────────
  {
    assert.equal(persistedConfigs.length, 1, 'persistFn should be called once on start');
    assert.equal(persistedConfigs[0].targetHost, '127.0.0.1');
    assert.equal(persistedConfigs[0].targetPort, upstreamPort);
  }

  // ── Test 7: stop() shuts down the listener ────────────────────────────────
  {
    await reverseProxy.stop();
    reverseProxy = null;

    const failed = await httpGet(proxyPort, '/ping').catch((e) => e);
    assert(failed instanceof Error, 'Requests should fail after stop()');
  }

  await close(upstream);

  console.log('PASS traffic-reverse-mode');
} catch (err) {
  if (reverseProxy) await reverseProxy.stop().catch(() => undefined);
  if (upstream) await close(upstream).catch(() => undefined);
  console.error('FAIL traffic-reverse-mode:', err.message);
  process.exit(1);
}
