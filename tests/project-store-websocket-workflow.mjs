import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  ProjectStore,
  ProjectStoreWebSocketRecorder,
} = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-websocket-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'websocket-workflow.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

let seedStore;
let reopened;
let restored;

const connectionId = 'wsc-project-store-live';
const wsUrl = 'wss://socket.issue-report.local/ws/refunds?tenant=alpha';
const binaryPayload = Buffer.from('binary-session=ws-binary-secret;token=ws-binary-token', 'utf8');
const frames = [
  {
    id: 'wsf-client-open',
    connectionId,
    time: '14:40:01',
    direction: 'client',
    host: 'socket.issue-report.local',
    path: '/ws/refunds?tenant=alpha',
    url: wsUrl,
    opcode: 1,
    type: 'text',
    payload: 'open-refund session=ws-client-session token=ws-client-token',
    payloadEncoding: 'text',
    length: Buffer.byteLength('open-refund session=ws-client-session token=ws-client-token'),
    tags: ['websocket', 'wss', 'client', 'forwarded'],
  },
  {
    id: 'wsf-server-role',
    connectionId,
    time: '14:40:02',
    direction: 'server',
    host: 'socket.issue-report.local',
    path: '/ws/refunds?tenant=alpha',
    url: wsUrl,
    opcode: 1,
    type: 'text',
    payload: '{"role":"support_admin","api_key":"ws-server-api-key"}',
    payloadEncoding: 'text',
    length: Buffer.byteLength('{"role":"support_admin","api_key":"ws-server-api-key"}'),
    tags: ['websocket', 'wss', 'server', 'forwarded'],
  },
  {
    id: 'wsf-client-binary',
    connectionId,
    time: '14:40:03',
    direction: 'client',
    host: 'socket.issue-report.local',
    path: '/ws/refunds?tenant=alpha',
    url: wsUrl,
    opcode: 2,
    type: 'binary',
    payload: binaryPayload.toString('hex'),
    payloadEncoding: 'hex',
    length: binaryPayload.length,
    tags: ['websocket', 'wss', 'client', 'held', 'edited', 'replayed', 'rewritten', 'rewrite:session'],
  },
];

try {
  seedStore = await ProjectStore.create(projectDir, {
    projectName: 'Project Store WebSocket Workflow',
    projectId: 'project-store-websocket-workflow',
  });
  seedStore.close();
  seedStore = null;

  const recorder = new ProjectStoreWebSocketRecorder(projectDir, {
    projectName: 'Project Store WebSocket Workflow',
    projectId: 'project-store-websocket-workflow',
  });
  for (const frame of frames) {
    await recorder.recordMessage(frame);
  }
  assert.equal(recorder.stats().failedCount, 0);
  assert.equal(recorder.stats().persistedFrameCount, 3);
  assert.equal(recorder.stats().lastConnectionId, connectionId);
  await recorder.close();

  reopened = await ProjectStore.open(projectDir);
  await reopened.upsertIssue({
    id: 'issue-websocket-role-leak',
    title: 'WebSocket role event exposes privileged context',
    type: 'websocket-manual',
    severity: 'medium',
    confidence: 'firm',
    status: 'open',
    host: 'socket.issue-report.local',
    path: '/ws/refunds?tenant=alpha',
    detail: 'WebSocket frame evidence preserves session=ws-client-session and ws-server-api-key for executor replay.',
    remediation: 'Remove privileged role fields from the WebSocket stream before report export.',
    evidenceRefs: [
      { kind: 'websocket-frame', id: 'wsf-client-open', label: 'Client open frame', source: 'websocket' },
      { kind: 'websocket-frame', id: 'wsf-server-role', label: 'Server role frame', source: 'websocket' },
      { kind: 'websocket-frame', id: 'wsf-client-binary', label: 'Binary replay frame', source: 'websocket' },
    ],
    source: 'websocket-workflow',
  });

  const stats = reopened.stats();
  assert.equal(stats.webSocketConnectionCount, 1);
  assert.equal(stats.webSocketFrameCount, 3);
  assert(stats.webSocketPayloadBytes >= binaryPayload.length);
  assert.equal(stats.issueCount, 1);
  assert.equal(stats.auditEventCount, 3);

  const connections = reopened.listWebSocketConnections({ text: 'refunds', limit: 5 });
  assert.equal(connections.length, 1);
  assert.equal(connections[0].frameCount, 3);
  assert.equal(connections[0].clientFrameCount, 2);
  assert.equal(connections[0].serverFrameCount, 1);

  const textFrames = reopened.listWebSocketFrames({ type: 'text', text: 'ws-client-session', limit: 5 });
  assert.equal(textFrames.length, 1);
  assert.equal(textFrames[0].id, 'wsf-client-open');

  const binaryFrame = reopened.getWebSocketFrame('wsf-client-binary');
  assert(binaryFrame);
  assert.equal(binaryFrame.payload.toString('utf8'), binaryPayload.toString('utf8'));
  assert.equal(binaryFrame.intercepted, true);
  assert.equal(binaryFrame.modified, true);
  assert.equal(binaryFrame.replayed, true);
  assert.equal(binaryFrame.rewritten, true);

  const issue = reopened.getIssue('issue-websocket-role-leak');
  assert(issue);
  assert.equal(issue.evidenceRefs.filter((ref) => ref.kind === 'websocket-frame').length, 3);
  assert.match(issue.detail, /ws-client-session|ws-server-api-key/);

  const backup = await reopened.createBackup(path.join(artifactRoot, 'backups'), { label: 'websocket-store' });
  assert.equal(backup.stats.webSocketFrameCount, 3);
  reopened.close();
  reopened = null;

  restored = await ProjectStore.open(backup.backupDir);
  assert.equal(restored.stats().webSocketConnectionCount, 1);
  assert.equal(restored.stats().webSocketFrameCount, 3);
  assert.equal(restored.getWebSocketFrame('wsf-server-role').payload.toString('utf8').includes('ws-server-api-key'), true);
  assert.equal(restored.getIssue('issue-websocket-role-leak').evidenceRefs.length, 3);

  console.log(`project-store-websocket-workflow: persisted ${stats.webSocketFrameCount} WebSocket frame(s), raw payload secrets, issue refs, audit events, and backup restore from ${projectDir}`);
} finally {
  restored?.close();
  reopened?.close();
  seedStore?.close();
}
