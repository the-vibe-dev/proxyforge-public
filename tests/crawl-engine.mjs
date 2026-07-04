import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';
import https from 'node:https';

const require = createRequire(import.meta.url);
const { CrawlEngine } = require('../dist-electron/crawlEngine.js');
const forge = require('node-forge');

const target = http.createServer((request, response) => {
  if (request.url === '/' || request.url === '/index.html') {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end([
      '<html><head><title>Shop Home</title></head><body>',
      '<a href="/orders?status=open">Orders</a>',
      '<a href="https://out-of-scope.invalid/admin">External</a>',
      '<script src="/assets/app.js"></script>',
      '<form method="post" action="/api/refunds">',
      '<input name="orderId">',
      '<input name="amount">',
      '<textarea name="reason"></textarea>',
      '</form>',
      '</body></html>',
    ].join(''));
    return;
  }

  if (request.url === '/orders?status=open') {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end('<html><title>Orders</title><a href="/orders/1234">Order detail</a></html>');
    return;
  }

  if (request.url === '/orders/1234') {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end('<html><title>Order 1234</title></html>');
    return;
  }

  if (request.url === '/assets/app.js') {
    response.writeHead(200, { 'content-type': 'application/javascript' });
    response.end('const routes=["/admin/orders","/api/refunds"];');
    return;
  }

  if (request.url === '/large') {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end(Buffer.alloc(2 * 1024 * 1024, 'a'));
    return;
  }

  response.writeHead(404, { 'content-type': 'text/plain' });
  response.end('not found');
});
const selfSignedTarget = https.createServer(createSelfSignedHttpsOptions(), (_request, response) => {
  response.writeHead(200, { 'content-type': 'text/html' });
  response.end('<html><title>TLS fixture</title></html>');
});

try {
  const port = await listen(target);
  const tlsPort = await listen(selfSignedTarget);
  const engine = new CrawlEngine();
  const startUrl = `http://127.0.0.1:${port}/`;

  const blocked = await engine.runCrawl({
    startUrl,
    scopeAllowlist: ['example.invalid'],
    maxDepth: 2,
    maxPages: 10,
    throttleMs: 0,
    userAgent: 'ProxyForge Test Crawler',
    includeForms: true,
  });
  assert.equal(blocked.blocked, true);
  assert.equal(blocked.totalRequests, 0);

  const summary = await engine.runCrawl({
    startUrl,
    scopeAllowlist: ['127.0.0.1'],
    maxDepth: 2,
    maxPages: 10,
    throttleMs: 0,
    userAgent: 'ProxyForge Test Crawler',
    includeForms: true,
  });

  assert.equal(summary.blocked, false);
  assert(summary.totalRequests >= 3);
  assert(summary.routes.some((route) => route.path === '/orders?status=open' && route.source === 'link'));
  assert(summary.routes.some((route) => route.path === '/assets/app.js' && route.source === 'script'));
  assert(summary.routes.some((route) => route.method === 'POST' && route.path === '/api/refunds' && route.source === 'form'));
  assert(summary.routes.every((route) => route.host === `127.0.0.1:${port}`));
  assert(summary.insertionPoints.some((point) => point.type === 'query' && point.name === 'status'));
  assert(summary.insertionPoints.some((point) => point.type === 'form' && point.name === 'orderId'));
  assert(summary.insertionPoints.some((point) => point.type === 'path' && point.name === 'segment-2'));
  assert(summary.exchanges.every((exchange) => exchange.source === 'crawler'));
  assert(summary.exchanges.every((exchange) => exchange.tags.includes('content-discovery')));

  const large = await engine.runCrawl({
    startUrl: `http://127.0.0.1:${port}/large`,
    scopeAllowlist: ['127.0.0.1'],
    maxDepth: 0,
    maxPages: 1,
    throttleMs: 0,
    userAgent: 'ProxyForge Test Crawler',
    includeForms: false,
  });
  const largeExchange = large.exchanges[0];
  assert.equal(largeExchange.length, 2 * 1024 * 1024, 'crawler should keep the true upstream response size');
  assert(largeExchange.responseRaw.length < 1.2 * 1024 * 1024, 'crawler should not retain the full large response body');
  assert(largeExchange.tags.includes('capture-truncated'), 'crawler should tag truncated response evidence');
  assert.match(largeExchange.notes, /truncated/i);

  const strictTls = await engine.runCrawl({
    startUrl: `https://127.0.0.1:${tlsPort}/`,
    scopeAllowlist: ['127.0.0.1'],
    maxDepth: 0,
    maxPages: 1,
    throttleMs: 0,
    userAgent: 'ProxyForge Test Crawler',
    includeForms: false,
  });
  assert.equal(strictTls.exchanges[0].status, 0, 'strict crawler TLS should reject a self-signed endpoint');
  assert.match(strictTls.exchanges[0].notes, /fetch failed/i);

  const relaxedEngine = new CrawlEngine({ upstreamTlsMode: () => 'relaxed' });
  const relaxedTls = await relaxedEngine.runCrawl({
    startUrl: `https://127.0.0.1:${tlsPort}/`,
    scopeAllowlist: ['127.0.0.1'],
    maxDepth: 0,
    maxPages: 1,
    throttleMs: 0,
    userAgent: 'ProxyForge Test Crawler',
    includeForms: false,
  });
  assert.equal(relaxedTls.exchanges[0].status, 200, 'relaxed crawler TLS should be explicit and auditable');
} finally {
  await close(target);
  await close(selfSignedTarget);
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function close(server) {
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}

function createSelfSignedHttpsOptions() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = '01';
  cert.validity.notBefore = new Date(Date.now() - 60_000);
  cert.validity.notAfter = new Date(Date.now() + 60 * 60 * 1000);
  cert.setSubject([{ name: 'commonName', value: '127.0.0.1' }]);
  cert.setIssuer([{ name: 'commonName', value: '127.0.0.1' }]);
  cert.setExtensions([{ name: 'subjectAltName', altNames: [{ type: 7, ip: '127.0.0.1' }] }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return {
    key: forge.pki.privateKeyToPem(keys.privateKey),
    cert: forge.pki.certificateToPem(cert),
  };
}
