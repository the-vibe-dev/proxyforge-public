import { strict as assert } from 'node:assert';
import dgram from 'node:dgram';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CallbackListenerService } = require('../dist-electron/callbackListenerService.js');
const { ProjectStore, ProjectStoreCallbackRecorder } = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-oast-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'oast-workflow.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

const seedStore = await ProjectStore.create(projectDir, {
  projectName: 'Project Store OAST Workflow',
  projectId: 'project-store-oast-workflow',
});
await seedStore.addHttpExchange({
  id: 'hx-oast-source',
  method: 'POST',
  url: 'https://fixture.local/api/import',
  host: 'fixture.local',
  path: '/api/import',
  status: 202,
  source: 'repeater',
  tags: ['oast', 'ssrf-candidate'],
  notes: 'Source request used to mint durable callback payloads.',
  requestRaw: [
    'POST /api/import HTTP/1.1',
    'Host: fixture.local',
    'Authorization: Bearer oast-source-token',
    'Content-Type: application/json',
    '',
    '{"url":"https://pf-http-store.oast.local/probe"}',
  ].join('\r\n'),
  responseRaw: 'HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\n\r\n{"queued":true}',
});
seedStore.close();

const recorder = new ProjectStoreCallbackRecorder(projectDir, {
  projectName: 'Project Store OAST Workflow',
  projectId: 'project-store-oast-workflow',
});
const service = new CallbackListenerService({
  payloads: (_profile, payloads) => recorder.capturePayloads(payloads),
  interaction: (_profile, interaction) => recorder.captureInteraction(interaction),
});
let reopened;

const profile = {
  id: 'oast-store-runtime',
  name: 'OAST store runtime',
  createdAt: '2026-05-25T21:00:00.000Z',
  mode: 'hybrid-local',
  status: 'planned',
  host: '127.0.0.1',
  publicBaseUrl: 'oast.local',
  protocols: ['dns', 'http', 'smtp'],
  httpPort: 0,
  dnsPort: 0,
  smtpPort: 0,
  pollIntervalSeconds: 5,
  retentionHours: 24,
  signingKeyId: 'oast-store-key',
  ciCommand: 'proxyforge oast poll --listener oast-store-runtime',
  healthChecks: [],
  summary: 'OAST store regression profile',
  content: '{}',
};
const payloads = [
  callbackPayload('cb-http-store', 'pf-http-store', 'http', 'https://pf-http-store.oast.local/probe'),
  callbackPayload('cb-dns-store', 'pf-dns-store', 'dns', 'pf-dns-store.oast.local'),
  callbackPayload('cb-smtp-store', 'pf-mail-store', 'smtp', 'pf-mail-store@oast.local'),
];

try {
  const status = await service.start(profile, payloads);
  await recorder.flush();
  assert.equal(status.running, true);
  assert.ok(status.ports.http > 0);
  assert.ok(status.ports.dns > 0);
  assert.ok(status.ports.smtp > 0);

  await sendHttpCallback(status.ports.http, 'pf-http-store');
  await sendDnsCallback(status.ports.dns, 'pf-dns-store.oast.local');
  await sendSmtpCallback(status.ports.smtp, 'pf-mail-store@oast.local');
  await delay(100);

  const poll = service.poll(profile.id, payloads);
  assert.equal(poll.newInteractionIds.length, 3);
  assert.match(JSON.stringify(poll.interactions), /pf-http-store|pf-dns-store|pf-mail-store/);

  await recorder.flush();
  const recorderStats = recorder.stats();
  assert.equal(recorderStats.failedCount, 0);
  assert.equal(recorderStats.pendingCount, 0);
  assert.equal(recorderStats.persistedPayloadCount, 3);
  assert.equal(recorderStats.persistedInteractionCount, 3);

  await service.stopAll();
  await recorder.close();
  reopened = await ProjectStore.open(projectDir);
  const stats = reopened.stats();
  assert.equal(stats.exchangeCount, 1);
  assert.equal(stats.callbackPayloadCount, 3);
  assert.equal(stats.callbackInteractionCount, 3);
  assert(stats.callbackBytes > 0);

  const storedPayloads = reopened.listCallbackPayloads({ text: 'pf-http-store', limit: 5 });
  assert.equal(storedPayloads.length, 1);
  assert.equal(storedPayloads[0].sourceExchangeId, 'hx-oast-source');
  assert.equal(storedPayloads[0].status, 'observed');
  assert.equal(storedPayloads[0].interactionCount, 1);
  assert.match(storedPayloads[0].endpoint, /pf-http-store/);

  const storedInteractions = reopened.listCallbackInteractions({ text: 'pf-http-store', limit: 5 });
  assert.equal(storedInteractions.length, 1);
  const httpInteraction = reopened.getCallbackInteraction(storedInteractions[0].id);
  assert(httpInteraction);
  assert.equal(httpInteraction.payloadId, 'cb-http-store');
  assert.equal(httpInteraction.protocol, 'http');
  assert.match(httpInteraction.raw.toString('utf8'), /authorization: Bearer oast-store-secret-token/i);
  assert.match(httpInteraction.raw.toString('utf8'), /pf-http-store/);

  const dnsRows = reopened.listCallbackInteractions({ protocol: 'dns', text: 'pf-dns-store', limit: 5 });
  assert.equal(dnsRows.length, 1);
  assert.match(reopened.getCallbackInteraction(dnsRows[0].id).raw.toString('utf8'), /pf-dns-store/);

  const smtpRows = reopened.listCallbackInteractions({ protocol: 'smtp', text: 'pf-mail-store', limit: 5 });
  assert.equal(smtpRows.length, 1);
  assert.match(reopened.getCallbackInteraction(smtpRows[0].id).raw.toString('utf8'), /pf-mail-store/);

  console.log(`project-store-oast-workflow: persisted ${stats.callbackPayloadCount} callback payloads and ${stats.callbackInteractionCount} raw OAST interactions in ${projectDir}`);
} finally {
  reopened?.close();
  await service.stopAll().catch(() => undefined);
  await recorder.close().catch(() => undefined);
}

function callbackPayload(id, token, protocol, endpoint) {
  return {
    id,
    token,
    label: `${protocol} durable callback`,
    protocol,
    endpoint,
    createdAt: '2026-05-25T21:00:01.000Z',
    status: 'waiting',
    sourceExchangeId: 'hx-oast-source',
    sourceHost: 'fixture.local',
    sourcePath: '/api/import',
    notes: 'Durable OAST regression payload',
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
        Authorization: 'Bearer oast-store-secret-token',
        'X-API-Key': 'oast-store-secret-key',
        'User-Agent': 'project-store-oast-test',
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

function sendSmtpCallback(port, recipient) {
  return new Promise((resolve, reject) => {
    const socket = net.createConnection({ host: '127.0.0.1', port });
    let settled = false;
    const timer = setTimeout(() => {
      socket.destroy();
      reject(new Error('Timed out waiting for SMTP callback'));
    }, 2000);
    const settle = () => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.end();
      resolve();
    };
    socket.on('connect', () => {
      socket.write([
        'EHLO worker.local',
        'MAIL FROM:<worker@app.local>',
        `RCPT TO:<${recipient}>`,
        'DATA',
        'Subject: durable callback',
        '',
        'runtime=smtp',
        '.',
        'QUIT',
        '',
      ].join('\r\n'));
    });
    socket.on('data', (chunk) => {
      if (chunk.toString('utf8').includes('221')) settle();
    });
    socket.on('close', () => settle());
    socket.on('error', (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(error);
    });
  });
}

function buildDnsQuery(name) {
  const labels = name.split('.');
  const questionLength = labels.reduce((total, label) => total + 1 + Buffer.byteLength(label), 0) + 1 + 4;
  const query = Buffer.alloc(12 + questionLength);
  query.writeUInt16BE(0x1234, 0);
  query.writeUInt16BE(0x0100, 2);
  query.writeUInt16BE(1, 4);
  let offset = 12;
  for (const label of labels) {
    query[offset] = Buffer.byteLength(label);
    offset += 1;
    query.write(label, offset, 'ascii');
    offset += Buffer.byteLength(label);
  }
  query[offset] = 0;
  offset += 1;
  query.writeUInt16BE(1, offset);
  offset += 2;
  query.writeUInt16BE(1, offset);
  return query;
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
