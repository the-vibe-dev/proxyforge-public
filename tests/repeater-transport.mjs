import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const { ProxyEngine } = require('../dist-electron/proxyEngine.js');

const seen = [];
const upstream = http.createServer((request, response) => {
  seen.push({
    url: request.url,
    connection: request.headers.connection,
    host: request.headers.host,
  });

  if (request.url === '/redirect') {
    response.writeHead(302, { location: '/final', 'content-type': 'text/plain' });
    response.end('redirecting');
    return;
  }

  if (request.url === '/final') {
    response.writeHead(200, { 'content-type': 'text/plain' });
    response.end('final destination');
    return;
  }

  if (request.url === '/slow') {
    setTimeout(() => {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('too slow');
    }, 1500);
    return;
  }

  response.writeHead(200, { 'content-type': 'application/json' });
  response.end(JSON.stringify({ path: request.url, connection: request.headers.connection }));
});

try {
  const upstreamPort = await listen(upstream);
  const proxy = new ProxyEngine(
    () => undefined,
    new CertificateAuthorityManager(path.join(process.cwd(), '.gitignored', 'repeater-transport-certs')),
  );

  const redirectRawRequest = [
    'GET /redirect HTTP/1.1',
    `Host: 127.0.0.1:${upstreamPort}`,
    'Connection: close',
    '',
    '',
  ].join('\r\n');

  const manualRedirect = await proxy.replay({
    rawRequest: redirectRawRequest,
    targetUrl: `http://127.0.0.1:${upstreamPort}/redirect`,
    scopeAllowlist: ['127.0.0.1'],
    settings: {
      redirectMode: 'manual',
      maxRedirects: 5,
      connectionMode: 'default',
      timeoutMs: 1000,
    },
  });

  assert.equal(manualRedirect.status, 302);
  assert.equal(seen.at(-1).url, '/redirect');
  assert(!seen.some((entry) => entry.url === '/final'));
  assert(manualRedirect.tags.includes('redirect:manual'));

  const followedRedirect = await proxy.replay({
    rawRequest: redirectRawRequest,
    targetUrl: `http://127.0.0.1:${upstreamPort}/redirect`,
    scopeAllowlist: ['127.0.0.1'],
    settings: {
      redirectMode: 'follow',
      maxRedirects: 5,
      connectionMode: 'keep-alive',
      timeoutMs: 1000,
    },
  });

  assert.equal(followedRedirect.status, 200);
  assert.equal(followedRedirect.path, '/final');
  assert.match(followedRedirect.responseRaw, /final destination/);
  assert.match(followedRedirect.notes, /redirects follow \(1 followed\); connection keep-alive/);
  assert.deepEqual(seen.slice(-2).map((entry) => entry.url), ['/redirect', '/final']);
  assert(seen.slice(-2).every((entry) => entry.connection === 'keep-alive'));
  assert(followedRedirect.tags.includes('redirect:follow'));
  assert(followedRedirect.tags.includes('connection:keep-alive'));

  const closeConnection = await proxy.replay({
    rawRequest: [
      'GET /connection HTTP/1.1',
      `Host: 127.0.0.1:${upstreamPort}`,
      '',
      '',
    ].join('\r\n'),
    targetUrl: `http://127.0.0.1:${upstreamPort}/connection`,
    scopeAllowlist: ['127.0.0.1'],
    settings: {
      redirectMode: 'manual',
      maxRedirects: 0,
      connectionMode: 'close',
      timeoutMs: 1000,
    },
  });

  assert.equal(closeConnection.status, 200);
  assert.equal(seen.at(-1).url, '/connection');
  assert.equal(seen.at(-1).connection, 'close');
  assert(closeConnection.tags.includes('connection:close'));

  const timeoutResult = await proxy.replay({
    rawRequest: [
      'GET /slow HTTP/1.1',
      `Host: 127.0.0.1:${upstreamPort}`,
      '',
      '',
    ].join('\r\n'),
    targetUrl: `http://127.0.0.1:${upstreamPort}/slow`,
    scopeAllowlist: ['127.0.0.1'],
    settings: {
      redirectMode: 'manual',
      maxRedirects: 0,
      connectionMode: 'default',
      timeoutMs: 1000,
    },
  });

  assert.equal(timeoutResult.status, 0);
  assert.equal(timeoutResult.mime, 'error');
  assert.match(timeoutResult.notes, /Replay error: Replay timed out after 1000 ms/);
  assert(timeoutResult.tags.includes('network-error'));
} finally {
  await close(upstream);
}

async function listen(server) {
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return server.address().port;
}

async function close(server) {
  if (!server.listening) return;
  await new Promise((resolve, reject) => {
    server.close((error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
