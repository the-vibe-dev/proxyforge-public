import { strict as assert } from 'node:assert';
import dgram from 'node:dgram';
import http from 'node:http';
import { createRequire } from 'node:module';
import net from 'node:net';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const servicePath = path.resolve('electron/callbackListenerService.ts');
const { CallbackListenerService } = await loadService(servicePath);
assert.equal(typeof CallbackListenerService, 'function', 'CallbackListenerService should be exported');

const service = new CallbackListenerService();
const profile = {
  id: 'callback-listener-runtime-test',
  name: 'Runtime callback listener test',
  createdAt: '2026-05-24T18:15:00.000Z',
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
  signingKeyId: 'runtime-test-key',
  ciCommand: 'proxyforge oast poll --listener callback-listener-runtime-test',
  healthChecks: [],
  summary: 'Runtime listener test profile',
  content: '{}',
};
const payloads = [
  callbackPayload('cb-http-runtime', 'pf-http-runtime', 'http', 'https://pf-http-runtime.oast.local/probe'),
  callbackPayload('cb-dns-runtime', 'pf-dns-runtime', 'dns', 'pf-dns-runtime.oast.local'),
  callbackPayload('cb-smtp-runtime', 'pf-mail-runtime', 'smtp', 'pf-mail-runtime@oast.local'),
];

try {
  const startStatus = await service.start(profile, payloads);
  assert.equal(startStatus.running, true, 'listener should start');
  assert.ok(startStatus.ports.http > 0, 'HTTP listener should bind an ephemeral port');
  assert.ok(startStatus.ports.dns > 0, 'DNS listener should bind an ephemeral port');
  assert.ok(startStatus.ports.smtp > 0, 'SMTP listener should bind an ephemeral port');
  assert.equal(startStatus.retentionHours, 24, 'listener status should expose retention hours');
  assert.equal(startStatus.retentionPrunedCount, 0, 'fresh listener should start with no retention-pruned interactions');

  await sendHttpCallback(startStatus.ports.http, 'pf-http-runtime');
  await sendMalformedDnsDatagrams(startStatus.ports.dns);
  await sendDnsCallback(startStatus.ports.dns, 'pf-dns-runtime.oast.local');
  await sendSmtpCallback(startStatus.ports.smtp, 'pf-mail-runtime@oast.local');

  await delay(100);
  const poll = service.poll(profile.id, payloads);
  assert.equal(poll.newInteractionIds.length, 3, 'first poll should return HTTP, DNS, and SMTP interactions');
  assert.equal(poll.status.retentionHours, 24, 'poll status should preserve retention hours');
  assert.equal(poll.status.retentionPrunedCount, 0, 'fresh socket interactions should not be retention-pruned');
  assert.deepEqual(new Set(poll.interactions.map((interaction) => interaction.protocol)), new Set(['http', 'dns', 'smtp']));
  assert.deepEqual(new Set(poll.interactions.map((interaction) => interaction.payloadId)), new Set(payloads.map((payload) => payload.id)));
  assert.ok(poll.interactions.every((interaction) => interaction.tags.includes('local-listener')), 'interactions should be tagged as local-listener evidence');
  assert.match(JSON.stringify(poll), /pf-http-runtime|pf-dns-runtime|pf-mail-runtime/, 'raw interactions should preserve callback tokens');

  const secondPoll = service.poll(profile.id, payloads);
  assert.equal(secondPoll.newInteractionIds.length, 0, 'second poll should not replay already-polled interactions as new');

  const stopStatus = await service.stop(profile.id);
  assert.equal(stopStatus.running, false, 'listener should stop cleanly');
  assert.equal(service.poll(profile.id, payloads).status.running, false, 'stopped listener should report not running');
} finally {
  await service.stopAll();
}

console.log('callback-listener-service: captured HTTP, DNS, and SMTP interactions through real local sockets');

async function loadService(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: filePath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    Buffer,
    console,
    require,
    setTimeout,
    clearTimeout,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: filePath });
  return module.exports;
}

function callbackPayload(id, token, protocol, endpoint) {
  return {
    id,
    token,
    label: `${protocol} runtime callback`,
    protocol,
    endpoint,
    createdAt: '18:15:01',
    status: 'waiting',
    sourceHost: 'app.local',
    sourcePath: '/callback-test',
    notes: 'Runtime listener smoke payload',
  };
}

function sendHttpCallback(port, token) {
  return new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port,
      path: `/probe?token=${token}`,
      headers: {
        Host: `${token}.oast.local`,
        'User-Agent': 'callback-listener-test',
      },
    }, (response) => {
      response.resume();
      response.on('end', resolve);
    });
    request.on('error', reject);
    request.end('runtime=http');
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

function sendMalformedDnsDatagrams(port) {
  const corpus = [
    Buffer.alloc(0),
    Buffer.from([0x00]),
    Buffer.alloc(11),
    Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0x20]),
    Buffer.from([0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c]),
  ];
  return new Promise((resolve, reject) => {
    const socket = dgram.createSocket('udp4');
    socket.on('error', reject);
    for (const message of corpus) socket.send(message, port, '127.0.0.1');
    setTimeout(() => {
      socket.close();
      resolve();
    }, 50);
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
        'Subject: callback',
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
    socket.on('close', () => {
      settle();
    });
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
