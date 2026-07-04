import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const { ProxyEngine, buildProxyHttpListenerCapturePackage } = require('../dist-electron/proxyEngine.js');

const artifactRoot = path.resolve('.gitignored', 'test-artifacts');
const tempDir = path.join(artifactRoot, `proxyforge-listener-${Date.now()}-${process.pid}`);
const exchanges = [];
let releaseStreamEnd = () => undefined;
let streamEndGate = Promise.resolve();
let upstream;
let proxy;

try {
  await fs.mkdir(tempDir, { recursive: true });
  streamEndGate = new Promise((resolve) => {
    releaseStreamEnd = resolve;
  });
  upstream = http.createServer((request, response) => {
    const chunks = [];
    request.on('data', (chunk) => chunks.push(chunk));
    request.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      if (request.url.startsWith('/stream')) {
        response.writeHead(200, {
          'content-type': 'text/event-stream',
          'cache-control': 'no-store',
        });
        response.write('event: first\ndata: stream-one\n\n');
        streamEndGate.then(() => response.end('event: second\ndata: stream-two\n\n'));
        return;
      }
      if (request.url.startsWith('/submit')) {
        response.writeHead(201, {
          'content-type': 'text/html',
          'x-upstream-proof': 'listener-post',
        });
        response.end(`<html><body>captured ${body}</body></html>`);
        return;
      }
      response.writeHead(200, {
        'content-type': 'application/json',
        'cache-control': 'no-store',
      });
      response.end(JSON.stringify({ ok: true, path: request.url, auth: request.headers.authorization ?? null }));
    });
  });

  const upstreamPort = await listen(upstream);
  proxy = new ProxyEngine((exchange) => exchanges.push(exchange), new CertificateAuthorityManager(path.join(tempDir, 'certs')));
  const proxyPort = await freePort();
  await proxy.start(proxyPort);

  const getResponse = await requestViaProxy(proxyPort, upstreamPort, {
    method: 'GET',
    path: '/inventory?item=refund&role=agent',
    headers: {
      Authorization: 'Bearer listener-secret-token',
      Cookie: 'session=listener-secret-session',
      'X-API-Key': 'listener-secret-key',
    },
  });
  assert.equal(getResponse.statusCode, 200);
  assert.match(getResponse.body, /listener-secret-token/);

  const postResponse = await requestViaProxy(proxyPort, upstreamPort, {
    method: 'POST',
    path: '/submit',
    body: 'token=listener-body-token&amount=100',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: 'Bearer listener-post-secret',
    },
  });
  assert.equal(postResponse.statusCode, 201);
  assert.match(postResponse.body, /listener-body-token/);

  const stream = await openStreamViaProxy(proxyPort, upstreamPort);
  const firstStreamChunk = await withTimeout(stream.firstChunk, 1500, 'Timed out waiting for first streamed chunk before upstream end');
  assert.equal(firstStreamChunk.statusCode, 200);
  assert.match(firstStreamChunk.chunk, /stream-one/);
  releaseStreamEnd();
  const streamResponse = await stream.complete;
  assert.match(streamResponse.body, /stream-one[\s\S]*stream-two/);

  await waitFor(() => exchanges.length >= 3);
  assert(exchanges.some((exchange) => exchange.method === 'GET' && exchange.path === '/inventory?item=refund&role=agent'));
  assert(exchanges.some((exchange) => exchange.method === 'POST' && exchange.path === '/submit'));
  const streamedExchange = exchanges.find((exchange) => exchange.path === '/stream');
  assert(streamedExchange);
  assert(streamedExchange.tags.includes('streamed-response'));
  assert(streamedExchange.tags.includes('chunked-response'));
  assert.match(streamedExchange.notes, /streamed response capture/);
  assert.match(streamedExchange.responseRaw, /stream-one[\s\S]*stream-two/);
  assert(exchanges.some((exchange) => /Authorization: Bearer listener-secret-token/i.test(exchange.requestRaw)));
  assert(exchanges.some((exchange) => /Cookie: session=listener-secret-session/i.test(exchange.requestRaw)));
  assert(exchanges.some((exchange) => /X-API-Key: listener-secret-key/i.test(exchange.requestRaw)));
  assert(exchanges.some((exchange) => /token=listener-body-token/.test(exchange.requestRaw)));
  assert(exchanges.some((exchange) => /captured token=listener-body-token/.test(exchange.responseRaw)));

  const capturePackage = buildProxyHttpListenerCapturePackage(exchanges);
  assert.equal(capturePackage.kind, 'proxyforge-proxy-http-listener-capture-package');
  assert.equal(capturePackage.proxyExchangeCount, 3);
  assert.equal(capturePackage.requirements.loopbackProxyListenerCovered, true);
  assert.equal(capturePackage.requirements.historyRowsCaptured, true);
  assert.equal(capturePackage.requirements.multiMethodCaptureCovered, true);
  assert.equal(capturePackage.requirements.requestBodyCaptureCovered, true);
  assert.equal(capturePackage.requirements.responseBodyCaptureCovered, true);
  assert.equal(capturePackage.requirements.fullFidelityRawCovered, true);
  assert.equal(capturePackage.requirements.operationalSecretsPreserved, true);
  assert.equal(capturePackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.deepEqual(capturePackage.methodCounts, { GET: 2, POST: 1 });
  assert(capturePackage.operationalSecretSignals.includes('authorization-header'));
  assert(capturePackage.operationalSecretSignals.includes('cookie-header'));
  assert(capturePackage.operationalSecretSignals.includes('x-api-key-header'));
  assert.match(JSON.stringify(capturePackage.samples), /listener-secret-token|listener-body-token/);
  await fs.writeFile(path.join(tempDir, 'proxy-http-listener-capture-package.json'), JSON.stringify(capturePackage, null, 2), 'utf8');
} finally {
  releaseStreamEnd();
  if (proxy) await proxy.stop().catch(() => undefined);
  if (upstream?.listening) await close(upstream).catch(() => undefined);
}

function openStreamViaProxy(proxyPort, upstreamPort) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: '127.0.0.1',
        port: proxyPort,
        method: 'GET',
        agent: false,
        path: `http://127.0.0.1:${upstreamPort}/stream`,
        headers: {
          host: `127.0.0.1:${upstreamPort}`,
          connection: 'close',
          Authorization: 'Bearer listener-stream-secret',
        },
      },
      (response) => {
        const chunks = [];
        let firstChunkResolved = false;
        let resolveFirstChunk;
        const firstChunk = new Promise((resolveFirst) => {
          resolveFirstChunk = resolveFirst;
        });
        const complete = new Promise((resolveComplete, rejectComplete) => {
          response.on('data', (chunk) => {
            chunks.push(chunk);
            if (!firstChunkResolved) {
              firstChunkResolved = true;
              resolveFirstChunk({
                statusCode: response.statusCode,
                chunk: chunk.toString('utf8'),
              });
            }
          });
          response.on('end', () => {
            resolveComplete({
              statusCode: response.statusCode,
              body: Buffer.concat(chunks).toString('utf8'),
            });
          });
          response.on('error', rejectComplete);
        });
        resolve({ firstChunk, complete });
      },
    );
    request.on('error', reject);
    request.end();
  });
}

function requestViaProxy(proxyPort, upstreamPort, options) {
  const body = options.body ? Buffer.from(options.body, 'utf8') : undefined;
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: '127.0.0.1',
        port: proxyPort,
        method: options.method,
        agent: false,
        path: `http://127.0.0.1:${upstreamPort}${options.path}`,
        headers: {
          host: `127.0.0.1:${upstreamPort}`,
          connection: 'close',
          ...(body ? { 'content-length': body.length } : {}),
          ...(options.headers ?? {}),
        },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          resolve({
            statusCode: response.statusCode,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
}

function withTimeout(promise, ms, message) {
  return Promise.race([
    promise,
    new Promise((_, reject) => setTimeout(() => reject(new Error(message)), ms)),
  ]);
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

async function freePort() {
  const server = http.createServer();
  const port = await listen(server);
  await close(server);
  return port;
}

async function waitFor(predicate) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for proxy listener history capture');
}
