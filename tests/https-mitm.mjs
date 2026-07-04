import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import https from 'node:https';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const { ProxyEngine, buildHttpsMitmEvidencePackage } = require('../dist-electron/proxyEngine.js');

const artifactRoot = path.resolve('.gitignored', 'test-artifacts');
const tempDir = path.join(artifactRoot, `proxyforge-mitm-${Date.now()}-${process.pid}`);
const exchanges = [];
let upstream;
let proxy;

try {
  await fs.mkdir(tempDir, { recursive: true });
  const caManager = new CertificateAuthorityManager(path.join(tempDir, 'certs'));
  const root = await caManager.exportRootPem();
  assert.match(root.fingerprintSha256, /^[0-9a-f:]{95}$/i, 'root CA fingerprint should be recorded for trust workflow evidence');
  await caManager.secureContextForHost('localhost');
  const initialCaStatus = await caManager.status();
  assert.equal(initialCaStatus.ready, true);
  assert.equal(initialCaStatus.hostCertificateCount, 1);
  assert.equal(initialCaStatus.fingerprintSha256, root.fingerprintSha256);

  const hostCert = await fs.readFile(path.join(tempDir, 'certs', 'projects', 'default-project', 'hosts', 'localhost.pem'), 'utf8');
  const hostKey = await fs.readFile(path.join(tempDir, 'certs', 'projects', 'default-project', 'hosts', 'localhost.key.pem'), 'utf8');
  upstream = https.createServer({ cert: hostCert, key: hostKey }, (request, response) => {
    response.writeHead(200, {
      'content-type': 'application/json',
      'cache-control': 'no-store',
    });
    response.end(JSON.stringify({ ok: true, via: 'upstream', path: request.url }));
  });

  const upstreamPort = await listen(upstream);
  proxy = new ProxyEngine((exchange) => exchanges.push(exchange), caManager);
  const proxyPort = await freePort();
  await proxy.start(proxyPort);
  assert.equal(proxy.httpsInspectionStatus().upstreamTlsMode, 'strict');
  proxy.setUpstreamTlsValidation('relaxed');

  const response = await getThroughMitm(proxyPort, upstreamPort, root.pem, '/secret');
  assert.match(response, /"ok":true/);
  assert.match(response, /"path":"\/secret"/);

  await waitFor(() => exchanges.some((exchange) => exchange.path === '/secret' && exchange.notes.includes('Captured by HTTPS inspection')));
  const inspected = exchanges.find((exchange) => exchange.path === '/secret');
  assert.equal(inspected.status, 200);
  assert.equal(inspected.mime, 'application/json');
  assert.match(inspected.requestRaw, /GET \/secret/);
  assert.match(inspected.responseRaw, /"via":"upstream"/);
  assert.match(inspected.notes, /upstream TLS relaxed/);
  assert(inspected.tags.includes('https'));
  assert(inspected.tags.includes('captured'));

  const secondResponse = await getThroughMitm(proxyPort, upstreamPort, root.pem, '/secret?round=2');
  assert.match(secondResponse, /"path":"\/secret\?round=2"/);
  await waitFor(() => exchanges.some((exchange) => exchange.path === '/secret?round=2' && exchange.notes.includes('Captured by HTTPS inspection')));
  const reusedCaStatus = await caManager.status();
  assert.equal(reusedCaStatus.hostCertificateCount, 1, 'repeated localhost MITM traffic should reuse the generated host certificate');

  const strictStatus = proxy.setUpstreamTlsValidation('strict');
  assert.equal(strictStatus.upstreamTlsMode, 'strict');

  const strictResponse = await getThroughMitm(proxyPort, upstreamPort, root.pem, '/strict', 'ProxyForge upstream error');
  assert.match(strictResponse, /ProxyForge upstream error/);
  await waitFor(() => exchanges.some((exchange) => exchange.path === '/strict' && exchange.status === 502));
  const strictFailure = exchanges.find((exchange) => exchange.path === '/strict' && exchange.status === 502);
  assert.equal(strictFailure.mime, 'text/plain');
  assert.match(strictFailure.notes, /upstream TLS strict/);
  assert.match(strictFailure.notes, /upstream error/);
  assert.match(strictFailure.requestRaw, /GET \/strict/);
  assert.match(strictFailure.responseRaw, /502 Bad Gateway/);
  assert(strictFailure.tags.includes('strict-upstream-tls'));

  const finalCaStatus = await caManager.status();
  const evidencePackage = buildHttpsMitmEvidencePackage(exchanges, {
    certificate: finalCaStatus,
    trustMode: 'project-ca',
  });
  assert.equal(evidencePackage.kind, 'proxyforge-https-mitm-evidence-package');
  assert.equal(evidencePackage.capturedHttpsExchangeCount >= 2, true);
  assert.equal(evidencePackage.mitmTunnelCount >= 2, true);
  assert.equal(evidencePackage.strictUpstreamFailureCount, 1);
  assert.equal(evidencePackage.requirements.projectCaGenerated, true);
  assert.equal(evidencePackage.requirements.hostCertificateReused, true);
  assert.equal(evidencePackage.requirements.decryptedTrafficCaptured, true);
  assert.equal(evidencePackage.requirements.strictUpstreamFailureCaptured, true);
  assert.equal(evidencePackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.match(JSON.stringify(evidencePackage.samples), /GET \/secret|GET \/strict/);
  await fs.writeFile(path.join(tempDir, 'https-mitm-evidence-package.json'), JSON.stringify(evidencePackage, null, 2), 'utf8');

} finally {
  if (proxy) await proxy.stop().catch(() => undefined);
  if (upstream?.listening) await close(upstream).catch(() => undefined);
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

async function getThroughMitm(proxyPort, upstreamPort, caPem, requestPath, needle = 'upstream') {
  const socket = net.connect(proxyPort, '127.0.0.1');
  await once(socket, 'connect');
  socket.write(`CONNECT localhost:${upstreamPort} HTTP/1.1\r\nHost: localhost:${upstreamPort}\r\n\r\n`);
  const connectResponse = await readUntil(socket, '\r\n\r\n');
  assert.match(connectResponse.toString('utf8'), /200 Connection Established/);

  const tlsSocket = tls.connect({
    socket,
    servername: 'localhost',
    ca: caPem,
    rejectUnauthorized: true,
  });
  await once(tlsSocket, 'secureConnect');
  tlsSocket.write(`GET ${requestPath} HTTP/1.1\r\nHost: localhost:${upstreamPort}\r\nConnection: close\r\n\r\n`);
  const response = await readUntil(tlsSocket, needle);
  tlsSocket.destroy();
  return response.toString('utf8');
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
  throw new Error('Timed out waiting for intercepted HTTPS exchange');
}
