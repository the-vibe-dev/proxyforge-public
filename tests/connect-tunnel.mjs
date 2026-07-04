import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';
import net from 'node:net';

const require = createRequire(import.meta.url);
const { ProxyEngine } = require('../dist-electron/proxyEngine.js');

const exchanges = [];
const upstream = net.createServer((socket) => {
  socket.on('data', (chunk) => {
    socket.write(`pong:${chunk.toString('utf8')}`);
  });
});
const upstreamProxyObservations = {
  requests: [],
  connects: [],
};
const upstreamProxy = http.createServer((request, response) => {
  upstreamProxyObservations.requests.push({
    method: request.method,
    url: request.url,
    proxyAuthorization: request.headers['proxy-authorization'],
    host: request.headers.host,
  });
  response.writeHead(203, {
    'content-type': 'text/plain',
    'x-upstream-proxy': 'observed',
  });
  response.end('proxied-http-body');
});
upstreamProxy.on('connect', (request, clientSocket, head) => {
  upstreamProxyObservations.connects.push({
    url: request.url,
    proxyAuthorization: request.headers['proxy-authorization'],
  });
  const [targetHost, targetPort] = String(request.url ?? '').split(':');
  const targetSocket = net.connect(Number(targetPort), targetHost, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.length > 0) targetSocket.write(head);
    targetSocket.pipe(clientSocket);
    clientSocket.pipe(targetSocket);
  });
  targetSocket.on('error', (error) => {
    clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nupstream proxy connect error: ${error.message}`);
  });
});

const proxy = new ProxyEngine((exchange) => exchanges.push(exchange));

try {
  const upstreamPort = await listen(upstream);
  const upstreamProxyPort = await listen(upstreamProxy);
  const proxyPort = await freePort();
  await proxy.start(proxyPort);
  const inspection = proxy.setHttpsInspection(false);
  assert.equal(inspection.enabled, false);

  const tunnel = net.connect(proxyPort, '127.0.0.1');
  await once(tunnel, 'connect');
  tunnel.write(`CONNECT localhost:${upstreamPort} HTTP/1.1\r\nHost: localhost:${upstreamPort}\r\n\r\n`);
  const connectResponse = await readUntil(tunnel, '\r\n\r\n');
  assert.match(connectResponse.toString('utf8'), /200 Connection Established/);

  const firstPayload = 'hello-through-tunnel';
  const secondPayload = 'second-through-tunnel';
  tunnel.write(firstPayload);
  tunnel.write(secondPayload);
  const tunneledResponse = await readUntil(tunnel, secondPayload);
  assert.match(tunneledResponse.toString('utf8'), /pong:.*hello-through-tunnel/);
  assert.match(tunneledResponse.toString('utf8'), /second-through-tunnel/);
  tunnel.destroy();

  await waitFor(() => exchanges.some((exchange) => exchange.method === 'CONNECT' && exchange.status === 200));
  const successfulTunnel = exchanges.find((exchange) => exchange.method === 'CONNECT' && exchange.status === 200);
  assert.equal(successfulTunnel.mime, 'tunnel');
  assert.match(successfulTunnel.notes, /CONNECT tunnel metadata captured with pass-through byte accounting/);
  assert.match(successfulTunnel.notes, /clientToServerBytes=/);
  assert.match(successfulTunnel.notes, /serverToClientBytes=/);
  assert.match(successfulTunnel.notes, /totalTunnelBytes=/);
  assert.match(successfulTunnel.notes, /tunnelDurationMs=/);
  assert.match(successfulTunnel.requestRaw, new RegExp(`CONNECT localhost:${upstreamPort}`));
  assert.match(successfulTunnel.responseRaw, /200 Connection Established/);
  assert.match(successfulTunnel.responseRaw, /ProxyForge-Tunnel-Client-Bytes:/);
  assert.match(successfulTunnel.responseRaw, /ProxyForge-Tunnel-Server-Bytes:/);
  assert(successfulTunnel.length >= firstPayload.length + secondPayload.length);
  assert(successfulTunnel.tags.includes('tunnel'));
  assert(successfulTunnel.tags.includes('https'));
  assert(successfulTunnel.tags.includes('byte-accounting'));

  const refusedPort = await freePort();
  const refusedTunnel = net.connect(proxyPort, '127.0.0.1');
  await once(refusedTunnel, 'connect');
  refusedTunnel.write(`CONNECT localhost:${refusedPort} HTTP/1.1\r\nHost: localhost:${refusedPort}\r\n\r\n`);
  const refusedResponse = await readUntil(refusedTunnel, 'ProxyForge CONNECT tunnel error');
  assert.match(refusedResponse.toString('utf8'), /502 Bad Gateway/);
  assert.match(refusedResponse.toString('utf8'), /ProxyForge CONNECT tunnel error/);
  refusedTunnel.destroy();

  await waitFor(() => exchanges.some((exchange) => exchange.method === 'CONNECT' && exchange.status === 502));
  const failedTunnel = exchanges.find((exchange) => exchange.method === 'CONNECT' && exchange.status === 502);
  assert.equal(failedTunnel.mime, 'text/plain');
  assert.match(failedTunnel.notes, /CONNECT tunnel failed/);
  assert.match(failedTunnel.requestRaw, new RegExp(`CONNECT localhost:${refusedPort}`));
  assert.match(failedTunnel.responseRaw, /502 Bad Gateway/);
  assert(failedTunnel.tags.includes('upstream-error'));

  const upstreamProxyStatus = proxy.setUpstreamProxy({
    url: `http://127.0.0.1:${upstreamProxyPort}`,
    authorization: 'Bearer upstream-chain-secret',
    noProxy: ['metadata.local'],
  });
  assert.equal(upstreamProxyStatus.enabled, true);
  assert.match(upstreamProxyStatus.message, /Upstream proxy chaining/);

  const httpClient = net.connect(proxyPort, '127.0.0.1');
  await once(httpClient, 'connect');
  httpClient.write([
    `GET http://127.0.0.1:${upstreamPort}/proxy-chain?x=1 HTTP/1.1`,
    `Host: 127.0.0.1:${upstreamPort}`,
    'Authorization: Bearer client-secret-through-chain',
    '',
    '',
  ].join('\r\n'));
  const httpProxyResponse = await readUntil(httpClient, 'proxied-http-body');
  assert.match(httpProxyResponse.toString('utf8'), /203 Non-Authoritative Information/);
  assert.match(httpProxyResponse.toString('utf8'), /x-upstream-proxy: observed/i);
  httpClient.destroy();

  await waitFor(() => exchanges.some((exchange) => exchange.method === 'GET' && exchange.tags.includes('proxy-chain') && exchange.status === 203));
  const chainedHttp = exchanges.find((exchange) => exchange.method === 'GET' && exchange.tags.includes('proxy-chain') && exchange.status === 203);
  assert.match(chainedHttp.notes, /upstream proxy/);
  assert.match(chainedHttp.requestRaw, new RegExp(`GET http://127\\.0\\.0\\.1:${upstreamPort}/proxy-chain\\?x=1 HTTP/1\\.1`));
  assert.match(chainedHttp.requestRaw, /Authorization: Bearer client-secret-through-chain/i);
  assert.match(chainedHttp.requestRaw, /Proxy-Authorization: Bearer upstream-chain-secret/i);
  assert(chainedHttp.tags.includes(`upstream-proxy:127.0.0.1:${upstreamProxyPort}`));
  assert.equal(upstreamProxyObservations.requests.length, 1);
  assert.equal(upstreamProxyObservations.requests[0].url, `http://127.0.0.1:${upstreamPort}/proxy-chain?x=1`);
  assert.equal(upstreamProxyObservations.requests[0].proxyAuthorization, 'Bearer upstream-chain-secret');

  const chainedTunnel = net.connect(proxyPort, '127.0.0.1');
  await once(chainedTunnel, 'connect');
  chainedTunnel.write(`CONNECT localhost:${upstreamPort} HTTP/1.1\r\nHost: localhost:${upstreamPort}\r\n\r\n`);
  const chainedConnectResponse = await readUntil(chainedTunnel, '\r\n\r\n');
  assert.match(chainedConnectResponse.toString('utf8'), /200 Connection Established/);
  chainedTunnel.write('chain-one');
  chainedTunnel.write('chain-two');
  const chainedTunnelResponse = await readUntil(chainedTunnel, 'chain-two');
  assert.match(chainedTunnelResponse.toString('utf8'), /pong:.*chain-one/);
  assert.match(chainedTunnelResponse.toString('utf8'), /chain-two/);
  chainedTunnel.destroy();

  await waitFor(() => exchanges.some((exchange) => exchange.method === 'CONNECT' && exchange.tags.includes('proxy-chain') && exchange.status === 200));
  const chainedConnect = exchanges.find((exchange) => exchange.method === 'CONNECT' && exchange.tags.includes('proxy-chain') && exchange.status === 200);
  assert.match(chainedConnect.notes, /through upstream proxy/);
  assert.match(chainedConnect.requestRaw, /Proxy-Authorization: Bearer upstream-chain-secret/i);
  assert.match(chainedConnect.responseRaw, /ProxyForge-Upstream-Proxy:/);
  assert(chainedConnect.tags.includes('byte-accounting'));
  assert.equal(upstreamProxyObservations.connects.length, 1);
  assert.equal(upstreamProxyObservations.connects[0].url, `localhost:${upstreamPort}`);
  assert.equal(upstreamProxyObservations.connects[0].proxyAuthorization, 'Bearer upstream-chain-secret');

  await proxy.stop();
  await close(upstream);
  await close(upstreamProxy);
} finally {
  await proxy.stop().catch(() => undefined);
  await close(upstream).catch(() => undefined);
  await close(upstreamProxy).catch(() => undefined);
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
      if (error && error.code !== 'ERR_SERVER_NOT_RUNNING') reject(error);
      else resolve();
    });
  });
}

async function freePort() {
  const server = net.createServer();
  const port = await listen(server);
  await close(server);
  return port;
}

function once(emitter, event) {
  return new Promise((resolve, reject) => {
    emitter.once(event, resolve);
    emitter.once('error', reject);
  });
}

function readUntil(stream, needle) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const onData = (chunk) => {
      chunks.push(chunk);
      const buffer = Buffer.concat(chunks);
      if (buffer.toString('utf8').includes(needle)) {
        cleanup();
        resolve(buffer);
      }
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const onEnd = () => {
      cleanup();
      resolve(Buffer.concat(chunks));
    };
    const cleanup = () => {
      stream.off('data', onData);
      stream.off('error', onError);
      stream.off('end', onEnd);
    };
    stream.on('data', onData);
    stream.once('error', onError);
    stream.once('end', onEnd);
  });
}

async function waitFor(predicate) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for CONNECT tunnel exchange');
}
