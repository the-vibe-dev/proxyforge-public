import { strict as assert } from 'node:assert';
import dgram from 'node:dgram';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CallbackListenerService } = require('../dist-electron/callbackListenerService.js');
const {
  ProjectStore,
  ProjectStoreCallbackRecorder,
  verifyProjectStoreCallbackEvidencePackage,
} = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-oast-signed-evidence', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'signed-oast.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

const signingSecret = 'signed-oast-regression-secret';
const seedStore = await ProjectStore.create(projectDir, {
  projectName: 'Project Store Signed OAST Evidence',
  projectId: 'project-store-oast-signed-evidence',
});
await seedStore.addHttpExchange({
  id: 'hx-signed-oast-source',
  method: 'POST',
  url: 'https://fixture.local/api/import',
  host: 'fixture.local',
  path: '/api/import',
  status: 202,
  source: 'repeater',
  tags: ['oast', 'signed-evidence-source'],
  notes: 'Source request for signed persisted OAST evidence.',
  requestRaw: [
    'POST /api/import HTTP/1.1',
    'Host: fixture.local',
    'Authorization: Bearer signed-oast-source-token',
    'Cookie: session=signed-oast-source-cookie',
    'X-API-Key: signed-oast-source-key',
    'Content-Type: application/json',
    '',
    '{"url":"https://pf-http-signed.oast.local/probe"}',
  ].join('\r\n'),
  responseRaw: 'HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n\r\n{"queued":true}',
});
seedStore.close();

const recorder = new ProjectStoreCallbackRecorder(projectDir, {
  projectName: 'Project Store Signed OAST Evidence',
  projectId: 'project-store-oast-signed-evidence',
});
const service = new CallbackListenerService({
  payloads: (_profile, payloads) => recorder.capturePayloads(payloads),
  interaction: (_profile, interaction) => recorder.captureInteraction(interaction),
});
let reopened;

const profile = {
  id: 'signed-oast-runtime',
  name: 'Signed OAST runtime',
  createdAt: '2026-05-25T23:30:00.000Z',
  mode: 'hybrid-local',
  status: 'planned',
  host: '127.0.0.1',
  publicBaseUrl: 'oast.local',
  protocols: ['dns', 'http'],
  httpPort: 0,
  dnsPort: 0,
  smtpPort: 0,
  pollIntervalSeconds: 2,
  retentionHours: 24,
  signingKeyId: 'signed-oast-key',
  ciCommand: 'proxyforge oast poll --listener signed-oast-runtime',
  healthChecks: [],
  summary: 'Signed OAST evidence regression profile',
  content: '{}',
};
const payloads = [
  callbackPayload('cb-http-signed', 'pf-http-signed', 'http', 'https://pf-http-signed.oast.local/probe'),
  callbackPayload('cb-dns-signed', 'pf-dns-signed', 'dns', 'pf-dns-signed.oast.local'),
];

try {
  const status = await service.start(profile, payloads);
  await recorder.flush();
  assert.equal(status.running, true);
  assert.ok(status.ports.http > 0);
  assert.ok(status.ports.dns > 0);

  await sendHttpCallback(status.ports.http, 'pf-http-signed');
  await sendDnsCallback(status.ports.dns, 'pf-dns-signed.oast.local');
  await delay(100);
  const poll = service.poll(profile.id, payloads);
  assert.equal(poll.newInteractionIds.length, 2);

  await recorder.flush();
  await service.stopAll();
  await recorder.close();

  reopened = await ProjectStore.open(projectDir);
  const packageResult = reopened.exportSignedCallbackEvidence({
    signerName: 'Signed OAST Regression',
    keyId: 'signed-oast-test-key',
    signingSecret,
    generatedAt: '2026-05-25T23:35:00.000Z',
    limit: 20,
  });
  assert.equal(packageResult.kind, 'proxyforge-project-store-callback-evidence-package');
  assert.equal(packageResult.stats.payloadCount, 2);
  assert.equal(packageResult.stats.interactionCount, 2);
  assert.equal(packageResult.stats.sourceExchangeCount, 1);
  assert.equal(packageResult.requirements.payloadsIncluded, true);
  assert.equal(packageResult.requirements.interactionsIncluded, true);
  assert.equal(packageResult.requirements.rawInteractionsPreserved, true);
  assert.equal(packageResult.requirements.sourceExchangesLinked, true);
  assert.equal(packageResult.requirements.hmacSignatureCovered, true);
  assert.equal(packageResult.requirements.operationalSecretsPreserved, true);
  assert.equal(packageResult.reportRedactionBoundary, 'redact-only-during-report-export');
  assert.match(packageResult.signature.signature, /^[a-f0-9]{64}$/);
  assert.match(packageResult.content, /Bearer signed-oast-source-token|session=signed-oast-source-cookie|signed-oast-source-key|authorization: Bearer signed-oast-http-token|pf-dns-signed/);

  const verified = verifyProjectStoreCallbackEvidencePackage(packageResult.content, signingSecret);
  assert.equal(verified.valid, true);
  assert.equal(verified.signatureMatches, true);
  assert.equal(verified.digestMatches, true);
  assert.equal(verified.keyId, 'signed-oast-test-key');

  const tampered = verifyProjectStoreCallbackEvidencePackage(packageResult.content.replace('pf-http-signed', 'pf-http-tampered'), signingSecret);
  assert.equal(tampered.valid, false);
  assert.equal(tampered.signatureMatches, false);
  assert.equal(tampered.digestMatches, false);

  await fs.writeFile(path.join(artifactRoot, 'project-store-signed-oast-evidence-package.json'), packageResult.content, 'utf8');
  console.log(`project-store-oast-signed-evidence: signed ${packageResult.stats.interactionCount} raw callback interaction(s) and verified tamper detection in ${projectDir}`);
} finally {
  reopened?.close();
  await service.stopAll().catch(() => undefined);
  await recorder.close().catch(() => undefined);
}

function callbackPayload(id, token, protocol, endpoint) {
  return {
    id,
    token,
    label: `${protocol} signed callback`,
    protocol,
    endpoint,
    createdAt: '2026-05-25T23:30:01.000Z',
    status: 'waiting',
    sourceExchangeId: 'hx-signed-oast-source',
    sourceHost: 'fixture.local',
    sourcePath: '/api/import',
    notes: 'Signed OAST evidence regression payload',
  };
}

function sendHttpCallback(port, token) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      method: 'POST',
      path: `/probe?token=${token}`,
      headers: {
        Host: `${token}.oast.local`,
        Authorization: 'Bearer signed-oast-http-token',
        'X-API-Key': 'signed-oast-http-key',
        'User-Agent': 'project-store-signed-oast-test',
        'Content-Type': 'text/plain',
      },
    }, (response) => {
      response.resume();
      response.on('end', resolve);
    });
    request.on('error', reject);
    request.end(`runtime=http&token=${token}`);
  });
}

function sendDnsCallback(port, name) {
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    const query = buildDnsQuery(name);
    const timer = setTimeout(() => {
      socket.close();
      reject(new Error('Timed out waiting for DNS callback response'));
    }, 2000);
    socket.on('message', () => {
      clearTimeout(timer);
      socket.close();
      resolve();
    });
    socket.on('error', (error) => {
      clearTimeout(timer);
      socket.close();
      reject(error);
    });
    socket.send(query, port, '127.0.0.1');
  });
}

function buildDnsQuery(name) {
  const labels = name.split('.');
  const labelBytes = labels.flatMap((label) => [label.length, ...Buffer.from(label, 'ascii')]);
  return Buffer.from([
    0x12, 0x34,
    0x01, 0x00,
    0x00, 0x01,
    0x00, 0x00,
    0x00, 0x00,
    0x00, 0x00,
    ...labelBytes,
    0x00,
    0x00, 0x01,
    0x00, 0x01,
  ]);
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
