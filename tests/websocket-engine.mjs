import { strict as assert } from 'node:assert';
import { createHash, randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import http from 'node:http';
import net from 'node:net';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const {
  ProxyEngine,
  buildWebSocketCaptureEvidencePackage,
  buildWebSocketInterceptReplayEvidencePackage,
  buildWebSocketStateTranscriptEvidencePackage,
} = require('../dist-electron/proxyEngine.js');

const artifactRoot = path.resolve('.gitignored', 'test-artifacts');
await fs.mkdir(artifactRoot, { recursive: true });
const tempDir = path.join(artifactRoot, `proxyforge-websocket-${Date.now()}-${process.pid}`);
await fs.mkdir(tempDir, { recursive: true });
const messages = [];
const savedReplays = [];
let rewriteRules = [];
let pendingFrames = [];
const exchanges = [];
const upstreamSockets = new Set();
let proxy;
let upstream;
let client;

try {
  upstream = http.createServer();
  upstream.on('upgrade', (request, socket) => {
    upstreamSockets.add(socket);
    socket.once('close', () => upstreamSockets.delete(socket));
    assert.equal(request.url, '/socket?room=orders');
    socket.write(renderWebSocketAccept(request.headers['sec-websocket-key']));
    socket.on('data', (chunk) => {
      const frame = decodeFrame(chunk);
      socket.write(encodeFrame(`echo:${frame.payload}`));
    });
  });
  const upstreamPort = await listen(upstream);

  proxy = new ProxyEngine(
    (exchange) => exchanges.push(exchange),
    new CertificateAuthorityManager(path.join(tempDir, 'certs')),
    undefined,
    (message) => messages.push(message),
    (pending) => {
      pendingFrames = pending;
    },
  );
  const proxyPort = await freePort();
  await proxy.start(proxyPort);
  const interceptStatus = proxy.setWebSocketIntercept({ enabled: true, clientEnabled: true, serverEnabled: false });
  assert.equal(interceptStatus.enabled, true);
  assert.equal(interceptStatus.clientEnabled, true);
  assert.equal(interceptStatus.serverEnabled, false);

  client = net.connect(proxyPort, '127.0.0.1');
  await once(client, 'connect');
  const key = randomBytes(16).toString('base64');
  client.write([
    `GET ws://127.0.0.1:${upstreamPort}/socket?room=orders HTTP/1.1`,
    `Host: 127.0.0.1:${upstreamPort}`,
    'Connection: Upgrade',
    'Upgrade: websocket',
    'Sec-WebSocket-Version: 13',
    `Sec-WebSocket-Key: ${key}`,
    '',
    '',
  ].join('\r\n'));

  const handshake = await readUntil(client, '\r\n\r\n');
  assert.match(handshake.toString('utf8'), /101 Switching Protocols/);
  const clientOnlyEchoFrame = readFrame(client);
  client.write(encodeFrame('client-only session=live-token-abc123', true));
  await waitFor(() => pendingFrames.some((message) => message.direction === 'client' && message.payload === 'client-only session=live-token-abc123'));
  const heldClientOnly = pendingFrames.find((message) => message.direction === 'client' && message.payload === 'client-only session=live-token-abc123');
  assert(heldClientOnly);
  proxy.resolveWebSocketIntercept({
    id: heldClientOnly.id,
    action: 'forward',
    payload: 'client-only-edited session=live-token-abc123',
  });
  const clientOnlyEcho = decodeFrame(await clientOnlyEchoFrame);
  assert.equal(clientOnlyEcho.payload, 'echo:client-only-edited session=live-token-abc123');
  assert(!pendingFrames.some((message) => message.direction === 'server' && message.payload === 'echo:client-only-edited session=live-token-abc123'));

  const bothDirectionsStatus = proxy.setWebSocketIntercept({ enabled: true, clientEnabled: true, serverEnabled: true });
  assert.equal(bothDirectionsStatus.clientEnabled, true);
  assert.equal(bothDirectionsStatus.serverEnabled, true);
  client.write(encodeFrame(Buffer.from([0, 1, 2, 255]), true, 2));
  await waitFor(() => pendingFrames.some((message) => message.direction === 'client' && message.type === 'binary'));
  const heldBinary = pendingFrames.find((message) => message.direction === 'client' && message.type === 'binary');
  assert(heldBinary);
  assert.equal(heldBinary.payload, '000102ff');
  assert.equal(heldBinary.payloadEncoding, 'hex');
  proxy.resolveWebSocketIntercept({
    id: heldBinary.id,
    action: 'drop',
  });

  const echoFrame = readFrame(client);
  client.write(encodeFrame('probe-order', true));
  await waitFor(() => pendingFrames.some((message) => message.direction === 'client' && message.payload === 'probe-order'));
  const held = pendingFrames.find((message) => message.direction === 'client' && message.payload === 'probe-order');
  assert(held);
  assert.equal(held.type, 'text');
  const forwardedStatus = proxy.resolveWebSocketIntercept({
    id: held.id,
    action: 'forward',
    payload: 'edited-order',
  });
  assert.equal(forwardedStatus.pendingCount, 0);
  await waitFor(() => pendingFrames.some((message) => message.direction === 'server' && message.payload === 'echo:edited-order'));
  const heldEcho = pendingFrames.find((message) => message.direction === 'server' && message.payload === 'echo:edited-order');
  assert(heldEcho);
  proxy.resolveWebSocketIntercept({
    id: heldEcho.id,
    action: 'forward',
  });
  const echo = decodeFrame(await echoFrame);
  assert.equal(echo.payload, 'echo:edited-order');

  await waitFor(() => messages.some((message) => message.direction === 'client' && message.payload === 'edited-order' && message.tags.includes('edited')));
  await waitFor(() => messages.some((message) => message.direction === 'server' && message.payload === 'echo:edited-order'));
  const replayEchoFrame = readFrame(client);
  const replayed = proxy.replayWebSocketFrame({
    connectionId: held.connectionId,
    direction: 'client',
    payload: 'replay-order',
    opcode: 1,
  });
  assert.equal(replayed.payload, 'replay-order');
  assert(replayed.tags.includes('replayed'));
  await waitFor(() => pendingFrames.some((message) => message.direction === 'server' && message.payload === 'echo:replay-order'));
  const heldReplayEcho = pendingFrames.find((message) => message.direction === 'server' && message.payload === 'echo:replay-order');
  assert(heldReplayEcho);
  proxy.resolveWebSocketIntercept({
    id: heldReplayEcho.id,
    action: 'forward',
  });
  const replayEcho = decodeFrame(await replayEchoFrame);
  assert.equal(replayEcho.payload, 'echo:replay-order');
  await waitFor(() => messages.some((message) => message.direction === 'server' && message.payload === 'echo:replay-order'));
  savedReplays.push({
    id: 'saved-ws-replay-order-validation',
    name: 'Order replay validation',
    connectionId: held.connectionId,
    direction: 'client',
    host: `127.0.0.1:${upstreamPort}`,
    path: '/socket?room=orders',
    url: `ws://127.0.0.1:${upstreamPort}/socket?room=orders`,
    opcode: 1,
    type: 'text',
    payload: 'replay-order session=live-token-abc123',
    payloadEncoding: 'text',
    createdAt: new Date().toISOString(),
    tags: ['operator-reviewed', 'full-fidelity'],
  });

  rewriteRules = proxy.setWebSocketFrameRewriteRules([{
    id: 'ws-test-rule',
    name: 'Rewrite replay scope',
    enabled: true,
    direction: 'client',
    frameType: 'text',
    match: 'scope=mine',
    replace: 'scope=support_admin',
    isRegex: false,
    caseSensitive: true,
  }]);
  assert.equal(rewriteRules.length, 1);
  const rewriteEchoFrame = readFrame(client);
  const rewrittenReplay = proxy.replayWebSocketFrame({
    connectionId: held.connectionId,
    direction: 'client',
    payload: 'scope=mine',
    opcode: 1,
  });
  assert.equal(rewrittenReplay.payload, 'scope=support_admin');
  assert(rewrittenReplay.tags.includes('rewritten'));
  await waitFor(() => pendingFrames.some((message) => message.direction === 'server' && message.payload === 'echo:scope=support_admin'));
  const heldRewriteEcho = pendingFrames.find((message) => message.direction === 'server' && message.payload === 'echo:scope=support_admin');
  assert(heldRewriteEcho);
  proxy.resolveWebSocketIntercept({
    id: heldRewriteEcho.id,
    action: 'forward',
  });
  const rewriteEcho = decodeFrame(await rewriteEchoFrame);
  assert.equal(rewriteEcho.payload, 'echo:scope=support_admin');

  assert(messages.every((message) => message.host === `127.0.0.1:${upstreamPort}`));
  assert(exchanges.some((exchange) => exchange.method === 'WEBSOCKET' && exchange.status === 101));

  const evidencePackage = buildWebSocketCaptureEvidencePackage(messages, { exchanges });
  assert.equal(evidencePackage.kind, 'proxyforge-websocket-capture-evidence-package');
  assert.equal(evidencePackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.equal(evidencePackage.reportRedactionBoundary, 'redact-only-during-report-export');
  assert.equal(evidencePackage.requirements.upgradeCaptureCovered, true);
  assert.equal(evidencePackage.requirements.bidirectionalFramesCovered, true);
  assert.equal(evidencePackage.requirements.textAndBinaryFramesCovered, true);
  assert.equal(evidencePackage.requirements.payloadBytesAccounted, true);
  assert.equal(evidencePackage.requirements.connectionGroupingCovered, true);
  assert.equal(evidencePackage.requirements.fullFidelityPayloadsPreserved, true);
  assert.equal(evidencePackage.requirements.operationalSecretsPreserved, true);
  assert.equal(evidencePackage.requirements.reportPhaseOnlyRedaction, true);
  assert.equal(evidencePackage.connectionCount, 1);
  assert.equal(evidencePackage.clientFrameCount >= 3, true);
  assert.equal(evidencePackage.serverFrameCount >= 3, true);
  assert(evidencePackage.binaryFrameCount >= 1);
  assert(evidencePackage.operationalSecretSignals.includes('secret-like-material'));
  assert(evidencePackage.connectionSummaries.some((summary) => (
    summary.host === `127.0.0.1:${upstreamPort}`
    && summary.fullPayloadSamples.some((sample) => sample.payload === 'client-only-edited session=live-token-abc123')
  )));
  const serializedEvidence = JSON.stringify(evidencePackage, null, 2);
  assert.match(serializedEvidence, /client-only-edited session=live-token-abc123|scope=support_admin|reportPhaseOnlyRedaction/i);
  await fs.writeFile(path.join(tempDir, 'websocket-capture-evidence-package.json'), serializedEvidence);

  const interceptReplayPackage = buildWebSocketInterceptReplayEvidencePackage(messages, {
    rewriteRules,
    savedReplays,
  });
  assert.equal(interceptReplayPackage.kind, 'proxyforge-websocket-intercept-rewrite-replay-evidence-package');
  assert.equal(interceptReplayPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.equal(interceptReplayPackage.reportRedactionBoundary, 'redact-only-during-report-export');
  assert.equal(interceptReplayPackage.requirements.clientInterceptCovered, true);
  assert.equal(interceptReplayPackage.requirements.serverInterceptCovered, true);
  assert.equal(interceptReplayPackage.requirements.editForwardCovered, true);
  assert.equal(interceptReplayPackage.requirements.dropCovered, true);
  assert.equal(interceptReplayPackage.requirements.liveReplayCovered, true);
  assert.equal(interceptReplayPackage.requirements.savedReplayCovered, true);
  assert.equal(interceptReplayPackage.requirements.rewriteRulesCovered, true);
  assert.equal(interceptReplayPackage.requirements.rewrittenReplayCovered, true);
  assert.equal(interceptReplayPackage.requirements.fullFidelityPayloadsPreserved, true);
  assert.equal(interceptReplayPackage.requirements.operationalSecretsPreserved, true);
  assert.equal(interceptReplayPackage.requirements.reportPhaseOnlyRedaction, true);
  assert.equal(interceptReplayPackage.savedReplayCount, 1);
  assert.equal(interceptReplayPackage.activeRewriteRuleCount, 1);
  assert(interceptReplayPackage.droppedFrameCount >= 1);
  assert(interceptReplayPackage.replayedFrameCount >= 2);
  assert(interceptReplayPackage.rewrittenFrameCount >= 1);
  assert(interceptReplayPackage.decisions.some((decision) => decision.action === 'drop' && decision.type === 'binary'));
  assert(interceptReplayPackage.decisions.some((decision) => decision.action === 'replay' && decision.payload === 'scope=support_admin'));
  const serializedInterceptReplay = JSON.stringify(interceptReplayPackage, null, 2);
  assert.match(serializedInterceptReplay, /proxyforge-websocket-intercept-rewrite-replay-evidence-package|client-only-edited session=live-token-abc123|replay-order session=live-token-abc123|scope=support_admin|reportPhaseOnlyRedaction/i);
  await fs.writeFile(path.join(tempDir, 'websocket-intercept-rewrite-replay-evidence-package.json'), serializedInterceptReplay);

  const stateTranscriptFixtures = buildStateTranscriptFixtures(messages, held.connectionId, upstreamPort);
  const stateTranscriptPackage = buildWebSocketStateTranscriptEvidencePackage(stateTranscriptFixtures);
  assert.equal(stateTranscriptPackage.kind, 'proxyforge-websocket-state-transcript-evidence-package');
  assert.equal(stateTranscriptPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.equal(stateTranscriptPackage.reportRedactionBoundary, 'redact-only-during-report-export');
  assert.equal(stateTranscriptPackage.requirements.stateGraphCovered, true);
  assert.equal(stateTranscriptPackage.requirements.graphFilterCovered, true);
  assert.equal(stateTranscriptPackage.requirements.graphExportCovered, true);
  assert.equal(stateTranscriptPackage.requirements.truncationMetadataCovered, true);
  assert.equal(stateTranscriptPackage.requirements.connectionClusteringCovered, true);
  assert.equal(stateTranscriptPackage.requirements.transcriptJsonExportCovered, true);
  assert.equal(stateTranscriptPackage.requirements.transcriptMarkdownExportCovered, true);
  assert.equal(stateTranscriptPackage.requirements.transcriptImportRestoreCovered, true);
  assert.equal(stateTranscriptPackage.requirements.largeTranscriptRestoreCovered, true);
  assert.equal(stateTranscriptPackage.requirements.fullFidelityPayloadsPreserved, true);
  assert.equal(stateTranscriptPackage.requirements.operationalSecretsPreserved, true);
  assert.equal(stateTranscriptPackage.requirements.reportPhaseOnlyRedaction, true);
  assert.equal(stateTranscriptPackage.restoredFrameCount >= 72, true);
  assert.equal(stateTranscriptPackage.stateGraphSummaries.some((graph) => graph.truncatedNodeCount > 0 && graph.truncatedEdgeCount > 0), true);
  assert.equal(stateTranscriptPackage.transcriptExports.some((transcript) => transcript.format === 'json'), true);
  assert.equal(stateTranscriptPackage.transcriptExports.some((transcript) => transcript.format === 'markdown'), true);
  assert(stateTranscriptPackage.connectionClusters.some((cluster) => cluster.connectionCount >= 2 && cluster.privilegedHints.includes('support_admin')));
  const serializedStateTranscript = JSON.stringify(stateTranscriptPackage, null, 2);
  assert.match(serializedStateTranscript, /proxyforge-websocket-state-transcript-evidence-package|support_admin|session=live-token-abc123|restored-frame-history|large-restored-071|truncatedNodeCount|reportPhaseOnlyRedaction/i);
  await fs.writeFile(path.join(tempDir, 'websocket-state-transcript-evidence-package.json'), serializedStateTranscript);
  console.log(`websocket-engine: wrote ${path.join(tempDir, 'websocket-capture-evidence-package.json')}`);
  console.log(`websocket-engine: wrote ${path.join(tempDir, 'websocket-intercept-rewrite-replay-evidence-package.json')}`);
  console.log(`websocket-engine: wrote ${path.join(tempDir, 'websocket-state-transcript-evidence-package.json')}`);
} finally {
  client?.destroy();
  if (proxy) await proxy.stop().catch(() => undefined);
  for (const socket of upstreamSockets) socket.destroy();
  if (upstream?.listening) await close(upstream).catch(() => undefined);
}

function renderWebSocketAccept(key) {
  const accept = createHash('sha1')
    .update(`${key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`)
    .digest('base64');
  return [
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${accept}`,
    '',
    '',
  ].join('\r\n');
}

function encodeFrame(payload, masked = false, opcode = 1) {
  const body = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  const header = [];
  header.push(0x80 | opcode);
  if (body.length < 126) {
    header.push((masked ? 0x80 : 0) | body.length);
  } else {
    throw new Error('Test payload too large');
  }

  if (!masked) return Buffer.concat([Buffer.from(header), body]);

  const mask = randomBytes(4);
  const encoded = Buffer.from(body);
  for (let index = 0; index < encoded.length; index += 1) {
    encoded[index] ^= mask[index % 4];
  }
  return Buffer.concat([Buffer.from(header), mask, encoded]);
}

function decodeFrame(frame) {
  const masked = Boolean(frame[1] & 0x80);
  const length = frame[1] & 0x7f;
  let offset = 2;
  const mask = masked ? frame.subarray(offset, offset + 4) : undefined;
  offset += masked ? 4 : 0;
  const payload = Buffer.from(frame.subarray(offset, offset + length));
  if (mask) {
    for (let index = 0; index < payload.length; index += 1) {
      payload[index] ^= mask[index % 4];
    }
  }
  return { payload: payload.toString('utf8') };
}

function readFrame(socket) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const onData = (chunk) => {
      chunks.push(chunk);
      const buffer = Buffer.concat(chunks);
      if (buffer.length < 2) return;
      const masked = Boolean(buffer[1] & 0x80);
      const length = buffer[1] & 0x7f;
      const expected = 2 + (masked ? 4 : 0) + length;
      if (buffer.length < expected) return;
      cleanup();
      resolve(buffer.subarray(0, expected));
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      socket.off('data', onData);
      socket.off('error', onError);
    };
    socket.on('data', onData);
    socket.on('error', onError);
  });
}

function readUntil(socket, marker) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    const onData = (chunk) => {
      chunks.push(chunk);
      const buffer = Buffer.concat(chunks);
      if (!buffer.includes(marker)) return;
      cleanup();
      resolve(buffer);
    };
    const onError = (error) => {
      cleanup();
      reject(error);
    };
    const cleanup = () => {
      socket.off('data', onData);
      socket.off('error', onError);
    };
    socket.on('data', onData);
    socket.on('error', onError);
  });
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

function once(emitter, event) {
  return new Promise((resolve) => emitter.once(event, resolve));
}

async function waitFor(predicate) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for WebSocket capture');
}

function buildStateTranscriptFixtures(messages, connectionId, upstreamPort) {
  const now = new Date().toISOString();
  const host = `127.0.0.1:${upstreamPort}`;
  const pathName = '/socket?room=orders';
  const url = `ws://${host}${pathName}`;
  const nodes = Array.from({ length: 24 }, (_unused, index) => ({
    id: `state-${index}`,
    label: index === 5 ? 'privileged:support_admin' : index === 23 ? 'close:1008' : `orders-state-${index}`,
    kind: index === 5 ? 'privileged' : index === 23 ? 'close' : index < 3 ? 'baseline' : 'observed',
    count: index + 1,
    frameIds: messages.slice(0, 4).map((message) => message.id),
  }));
  const edges = Array.from({ length: 32 }, (_unused, index) => ({
    id: `edge-${index}`,
    from: `state-${index % nodes.length}`,
    to: `state-${(index + 1) % nodes.length}`,
    label: index === 7 ? 'orders-state-7 -> privileged:support_admin' : index === 30 ? 'orders-state-30 -> close:1008' : `orders-state-${index} -> orders-state-${index + 1}`,
    kind: index === 7 ? 'privileged' : index < 4 ? 'baseline' : index % 11 === 0 ? 'missing' : 'added',
    count: 1,
    frameIds: messages.slice(0, 4).map((message) => message.id),
  }));
  const graph = {
    id: 'ws-graph-orders-state',
    connectionId,
    host,
    path: pathName,
    nodes,
    edges,
    totalNodeCount: 31,
    totalEdgeCount: 45,
    truncatedNodeCount: 7,
    truncatedEdgeCount: 13,
    summary: '24/31 states and 32/45 transitions shown; privileged and close filters available; preview is truncated.',
  };
  const graphExport = {
    id: 'ws-graph-export-orders-state',
    title: `${host}${pathName} state graph image`,
    fileName: 'orders-state-graph-privileged.svg',
    filePath: `browser-preview://websocket-graphs/orders-state-graph-privileged.svg`,
    createdAt: now,
    graphId: graph.id,
    connectionId,
    host,
    path: pathName,
    format: 'svg',
    nodeCount: 24,
    edgeCount: 32,
    totalNodeCount: 31,
    totalEdgeCount: 45,
    truncatedNodeCount: 7,
    truncatedEdgeCount: 13,
    frameCount: 4,
    sizeBytes: 318,
    content: '<svg role="img"><text>support_admin state graph filtered transitions</text></svg>',
  };
  const jsonTranscriptPayload = {
    version: 1,
    kind: 'proxyforge-websocket-transcript',
    projectName: 'ProxyForge WebSocket parity',
    exportedAt: now,
    id: 'payload-orders-transcript',
    title: `${host}${pathName} WebSocket transcript`,
    fileName: 'orders.proxyforge-ws.json',
    format: 'json',
    frameCount: messages.length,
    fuzzRunIds: ['ws-fuzz-orders'],
    stateDiffIds: ['ws-state-diff-orders'],
    closeCodeCount: 1,
    connectionId,
    host,
    path: pathName,
    url,
    frames: messages,
    fuzzRuns: [{ id: 'ws-fuzz-orders', summary: 'Role escalation probe produced support_admin state drift.' }],
    stateDiffs: [{ id: 'ws-state-diff-orders', summary: 'Privileged transition preserved with restored transcript.' }],
    closeCodeInsights: [{ id: 'ws-close-orders-1008', code: 1008, reason: 'policy close' }],
  };
  const jsonTranscript = {
    id: 'ws-transcript-orders-json',
    title: jsonTranscriptPayload.title,
    fileName: 'orders.proxyforge-ws.json',
    filePath: 'browser-preview',
    createdAt: now,
    connectionId,
    host,
    path: pathName,
    format: 'json',
    frameCount: messages.length,
    fuzzRunIds: ['ws-fuzz-orders'],
    stateDiffIds: ['ws-state-diff-orders'],
    closeCodeCount: 1,
    sizeBytes: Buffer.byteLength(JSON.stringify(jsonTranscriptPayload)),
    content: JSON.stringify(jsonTranscriptPayload, null, 2),
  };
  const markdownTranscript = {
    id: 'ws-transcript-orders-markdown',
    title: jsonTranscriptPayload.title,
    fileName: 'orders.md',
    filePath: 'browser-preview',
    createdAt: now,
    connectionId,
    host,
    path: pathName,
    format: 'markdown',
    frameCount: messages.length,
    fuzzRunIds: ['ws-fuzz-orders'],
    stateDiffIds: ['ws-state-diff-orders'],
    closeCodeCount: 1,
    sizeBytes: 280,
    content: `# ${jsonTranscriptPayload.title}\n\nsession=live-token-abc123\n\n## Frames\n\n- support_admin replay state preserved\n`,
  };
  const largeTranscriptId = 'ws-transcript-large-json';
  const largeFrames = Array.from({ length: 72 }, (_unused, index) => {
    const type = index % 17 === 0 ? 'binary' : index === 71 ? 'close' : 'text';
    const payload = type === 'binary'
      ? `6c617267652d726573746f7265642d${String(index).padStart(3, '0')}`
      : type === 'close'
        ? '1008: large-restored-071 policy close session=live-token-abc123'
        : JSON.stringify({
            event: `large-restored-${String(index).padStart(3, '0')}`,
            scope: index % 9 === 0 ? 'support_admin' : 'viewer',
            session: index === 0 ? 'live-token-abc123' : 'continuation',
            sequence: index,
          });
    return {
      id: `ws-restored-large-frame-${index}`,
      transcriptId: largeTranscriptId,
      originalFrameId: `ws-large-frame-${index}`,
      restoredAt: now,
      sourceFormat: 'json',
      connectionId: 'ws-restored-large-connection',
      time: `14:${String(Math.floor(index / 60)).padStart(2, '0')}:${String(index % 60).padStart(2, '0')}`,
      direction: index % 2 === 0 ? 'client' : 'server',
      host: 'large.ws.local',
      path: '/socket/large',
      url: 'wss://large.ws.local/socket/large',
      opcode: type === 'close' ? 8 : type === 'binary' ? 2 : 1,
      type,
      payload,
      payloadEncoding: type === 'binary' ? 'hex' : 'text',
      length: payload.length,
      tags: ['websocket', 'restored-transcript', index % 10 === 0 ? 'fuzz-large' : 'large-session'].filter(Boolean),
    };
  });
  const largeTranscript = {
    id: largeTranscriptId,
    title: 'large.ws.local/socket/large WebSocket transcript',
    fileName: 'large.proxyforge-ws.json',
    filePath: 'browser-preview',
    createdAt: now,
    connectionId: 'ws-restored-large-connection',
    host: 'large.ws.local',
    path: '/socket/large',
    format: 'json',
    frameCount: largeFrames.length,
    fuzzRunIds: ['ws-fuzz-large'],
    stateDiffIds: ['ws-state-diff-large'],
    closeCodeCount: 1,
    sizeBytes: largeFrames.reduce((total, frame) => total + frame.length, 0),
    content: JSON.stringify({ kind: 'proxyforge-websocket-transcript', frames: largeFrames }, null, 2),
  };
  const cluster = {
    id: 'ws-connection-cluster-orders',
    createdAt: now,
    title: `${host}${pathName} connection cluster`,
    severity: 'medium',
    confidence: 'firm',
    hosts: [host, 'large.ws.local'],
    paths: [pathName, '/socket/large'],
    connectionIds: [connectionId, 'ws-restored-large-connection'],
    frameIds: [...messages.map((message) => message.id), ...largeFrames.map((frame) => frame.id)],
    connectionCount: 2,
    frameCount: messages.length + largeFrames.length,
    clientFrames: messages.filter((message) => message.direction === 'client').length + largeFrames.filter((frame) => frame.direction === 'client').length,
    serverFrames: messages.filter((message) => message.direction === 'server').length + largeFrames.filter((frame) => frame.direction === 'server').length,
    binaryFrames: largeFrames.filter((frame) => frame.type === 'binary').length,
    replayFrames: messages.filter((message) => message.tags.includes('replayed')).length,
    rewrittenFrames: messages.filter((message) => message.tags.includes('rewritten')).length,
    closeFrames: 1,
    privilegedHints: ['support_admin'],
    sharedStates: ['orders-state-7', 'privileged:support_admin', 'close:1008'],
    summary: 'Cluster includes live and restored WebSocket state transitions with privileged hints.',
    recommendation: 'Compare shared states, preserve the graph image, and carry restored transcript frames into reports.',
  };

  return {
    graphs: [graph],
    graphExports: [graphExport],
    clusters: [cluster],
    transcripts: [jsonTranscript, markdownTranscript, largeTranscript],
    restoredFrames: largeFrames,
    filtersApplied: ['all', 'privileged', 'close'],
    largeTranscriptFrameThreshold: 50,
  };
}
