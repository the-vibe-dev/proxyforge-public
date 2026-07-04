import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';
import { startVulnerableApp } from './fixtures/vulnerable-app/server.mjs';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const { ProxyEngine } = require('../dist-electron/proxyEngine.js');
const { ProjectStore, ProjectStoreProxyRecorder } = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/proxy-project-store-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'captured-workflow.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

const app = await startVulnerableApp();
const exchanges = [];
const recorder = new ProjectStoreProxyRecorder(projectDir, {
  projectName: 'Proxy Capture Store Workflow',
  projectId: 'proxy-capture-store-workflow',
});
let proxy;
let persistedStore;

try {
  proxy = new ProxyEngine((exchange) => {
    exchanges.push(exchange);
    recorder.capture(exchange);
  }, new CertificateAuthorityManager(path.join(artifactRoot, 'certs')));
  const proxyPort = await freePort();
  await proxy.start(proxyPort);

  const login = await requestViaProxy(proxyPort, `${app.httpUrl}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=store&role=admin',
  });
  assert.equal(login.statusCode, 200);
  const cookies = cookieHeader(login.headers['set-cookie']);
  assert.match(cookies, /pf_session=/);

  const profile = await requestViaProxy(proxyPort, `${app.httpUrl}/api/profile`, {
    method: 'GET',
    headers: {
      cookie: cookies,
      authorization: 'Bearer proxy-store-secret-token',
      'x-api-key': 'proxy-store-secret-key',
    },
  });
  assert.equal(profile.statusCode, 200);
  assert.match(profile.body, /fixture-token-/);

  await waitFor(() => exchanges.length >= 2);
  await recorder.flush();
  const recorderStats = recorder.stats();
  assert.equal(recorderStats.failedCount, 0);
  assert.equal(recorderStats.pendingCount, 0);
  assert(recorderStats.persistedCount >= 2);

  await recorder.close();
  persistedStore = await ProjectStore.open(projectDir);
  const storeStats = persistedStore.stats();
  assert.equal(storeStats.exchangeCount, exchanges.length);
  assert(storeStats.requestBytes > 0);
  assert(storeStats.responseBytes > 0);

  const profileRows = persistedStore.searchHttpExchanges({
    text: 'proxy-store-secret-token',
    limit: 5,
  });
  assert.equal(profileRows.length, 1);
  const persistedProfile = persistedStore.getHttpExchange(profileRows[0].id);
  assert(persistedProfile);

  const capturedProfile = exchanges.find((exchange) => exchange.id === persistedProfile.id);
  assert(capturedProfile);
  assert.equal(persistedProfile.requestRaw.toString('utf8'), capturedProfile.requestRaw);
  assert.equal(persistedProfile.responseRaw.toString('utf8'), capturedProfile.responseRaw);
  assert.match(persistedProfile.requestRaw.toString('utf8'), /Authorization: Bearer proxy-store-secret-token/i);
  assert.match(persistedProfile.requestRaw.toString('utf8'), /X-API-Key: proxy-store-secret-key/i);
  assert.match(persistedProfile.responseRaw.toString('utf8'), /fixture-token-/);

  const replayed = await proxy.replay({
    rawRequest: persistedProfile.requestRaw.toString('utf8'),
    targetUrl: persistedProfile.url,
    scopeAllowlist: ['127.0.0.1'],
    settings: {
      redirectMode: 'manual',
      maxRedirects: 0,
      connectionMode: 'close',
      timeoutMs: 1500,
    },
  });
  assert.equal(replayed.status, 200);
  assert.match(replayed.responseRaw, /fixture-token-/);
  assert.match(replayed.requestRaw, /proxy-store-secret-token/);

  console.log(`proxy-project-store-workflow: captured ${exchanges.length} exchange(s), persisted exact raw bytes, reopened store, and replayed profile request from ${projectDir}`);
} finally {
  persistedStore?.close();
  if (proxy) await proxy.stop().catch(() => undefined);
  await recorder.close().catch(() => undefined);
  await app.close();
}

function requestViaProxy(proxyPort, urlString, options) {
  const url = new URL(urlString);
  const body = options.body ? Buffer.from(options.body, 'utf8') : undefined;
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: '127.0.0.1',
        port: proxyPort,
        method: options.method,
        agent: false,
        path: url.toString(),
        headers: {
          host: url.host,
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
            headers: response.headers,
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

function cookieHeader(setCookieHeaders = []) {
  return setCookieHeaders.map((value) => value.split(';')[0]).join('; ');
}

async function freePort() {
  const server = http.createServer();
  const port = await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve(server.address().port));
  });
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  return port;
}

async function waitFor(predicate, timeoutMs = 3000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for proxy Project Store capture');
}
