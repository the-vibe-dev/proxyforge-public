import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  ProjectStore,
  ProjectStoreProxyRecorder,
} = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-target-inventory-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'target-inventory.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

let reopened;
let restored;

try {
  const seedStore = await ProjectStore.create(projectDir, {
    projectName: 'Project Store Target Inventory Workflow',
    projectId: 'project-store-target-inventory-workflow',
  });
  seedStore.close();

  const recorder = new ProjectStoreProxyRecorder(projectDir, {
    projectName: 'Project Store Target Inventory Workflow',
    projectId: 'project-store-target-inventory-workflow',
  });

  await recorder.record({
    id: 'hx-target-json',
    method: 'POST',
    url: 'https://api.fixture.local:8443/api/orders/100/items?view=full&debug=true',
    host: 'api.fixture.local:8443',
    path: '/api/orders/100/items?view=full&debug=true',
    status: 200,
    mime: 'application/json',
    timing: 42,
    source: 'proxy',
    tags: ['fixture', 'json', 'authenticated'],
    notes: 'Target inventory keeps full operator material until report export.',
    time: '2026-05-26T12:00:00.000Z',
    requestRaw: [
      'POST /api/orders/100/items?view=full&debug=true HTTP/1.1',
      'Host: api.fixture.local:8443',
      'Authorization: Bearer target-inventory-token',
      'Cookie: session=target-inventory-session; theme=dark',
      'X-API-Key: target-inventory-key',
      'X-Feature-Flag: inventory-beta',
      'Content-Type: application/json',
      '',
      JSON.stringify({
        orderId: 100,
        role: 'admin',
        token: 'target-inventory-token',
        nested: {
          csrf: 'target-inventory-csrf',
        },
      }),
    ].join('\r\n'),
    responseRaw: [
      'HTTP/1.1 200 OK',
      'Server: fixture-api',
      'Content-Type: application/json',
      '',
      '{"ok":true,"token":"target-inventory-token"}',
    ].join('\r\n'),
  });
  await recorder.close();

  reopened = await ProjectStore.open(projectDir);
  await reopened.addHttpExchange({
    id: 'hx-target-graphql',
    method: 'POST',
    url: 'https://api.fixture.local:8443/graphql',
    host: 'api.fixture.local:8443',
    path: '/graphql',
    protocol: 'https',
    status: 200,
    mime: 'application/json',
    timingMs: 31,
    source: 'crawler',
    tags: ['fixture', 'graphql'],
    notes: 'Crawler-discovered GraphQL route joins the same target inventory.',
    createdAt: '2026-05-26T12:01:00.000Z',
    requestRaw: [
      'POST /graphql HTTP/1.1',
      'Host: api.fixture.local:8443',
      'Authorization: Bearer target-inventory-token',
      'Content-Type: application/json',
      '',
      JSON.stringify({
        operationName: 'UpdateOrder',
        query: 'mutation UpdateOrder($orderId: ID!, $role: String!) { updateOrder(id: $orderId, role: $role) { id } }',
        variables: {
          orderId: '100',
          role: 'support_admin',
        },
      }),
    ].join('\r\n'),
    responseRaw: [
      'HTTP/1.1 200 OK',
      'Content-Type: application/json',
      '',
      '{"data":{"updateOrder":{"id":"100"}}}',
    ].join('\r\n'),
  });
  await reopened.addHttpExchange({
    id: 'hx-target-form-xml',
    method: 'POST',
    url: 'https://api.fixture.local:8443/admin/profile/550e8400-e29b-41d4-a716-446655440000',
    host: 'api.fixture.local:8443',
    path: '/admin/profile/550e8400-e29b-41d4-a716-446655440000',
    protocol: 'https',
    status: 202,
    mime: 'application/xml',
    timingMs: 27,
    source: 'scanner',
    tags: ['fixture', 'xml'],
    notes: 'Scanner-discovered XML parameter inventory.',
    createdAt: '2026-05-26T12:02:00.000Z',
    requestRaw: [
      'POST /admin/profile/550e8400-e29b-41d4-a716-446655440000 HTTP/1.1',
      'Host: api.fixture.local:8443',
      'Content-Type: application/xml',
      '',
      '<profile id="550e8400-e29b-41d4-a716-446655440000"><role>support_admin</role><secret>target-inventory-xml-secret</secret></profile>',
    ].join('\r\n'),
    responseRaw: [
      'HTTP/1.1 202 Accepted',
      'Content-Type: application/xml',
      '',
      '<ok>true</ok>',
    ].join('\r\n'),
  });

  let stats = reopened.stats();
  assert.equal(stats.exchangeCount, 3);
  assert.equal(stats.targetHostCount, 1);
  assert.equal(stats.targetRouteCount, 3);
  assert(stats.parameterCount >= 18, `expected rich parameter inventory, got ${stats.parameterCount}`);
  assert.equal(stats.auditEventCount, 0);

  const hosts = reopened.listTargetHosts({ host: 'api.fixture.local', limit: 5 });
  assert.equal(hosts.length, 1);
  assert.equal(hosts[0].scheme, 'https');
  assert.equal(hosts[0].port, 8443);
  assert.equal(hosts[0].routeCount, 3);
  assert.equal(hosts[0].exchangeCount, 3);
  assert.equal(hosts[0].technologySummary.server, 'fixture-api');

  const normalizedRoutes = reopened.listTargetRoutes({ normalizedPath: '/api/orders/{int}/items', limit: 5 });
  assert.equal(normalizedRoutes.length, 1);
  assert.equal(normalizedRoutes[0].method, 'POST');
  assert.equal(normalizedRoutes[0].parameterCount >= 10, true);
  assert.equal(normalizedRoutes[0].evidenceExchangeId, 'hx-target-json');

  const uuidRoutes = reopened.listTargetRoutes({ pathIncludes: '{uuid}', limit: 5 });
  assert.equal(uuidRoutes.length, 1);
  assert.equal(uuidRoutes[0].normalizedPath, '/admin/profile/{uuid}');

  const cookie = reopened.listParameters({ location: 'cookie', name: 'session', limit: 5 })[0];
  assert(cookie);
  assert.equal(cookie.valueSample, 'target-inventory-session');
  assert.equal(cookie.insertionCandidate, true);

  const authHeader = reopened.listParameters({ location: 'header', name: 'Authorization', limit: 5 })[0];
  assert(authHeader);
  assert.match(authHeader.valueSample, /Bearer target-inventory-token/);
  assert.equal(authHeader.insertionCandidate, true);

  const jsonToken = reopened.listParameters({ location: 'json', text: 'target-inventory-csrf', limit: 5 })[0];
  assert(jsonToken);
  assert.equal(jsonToken.name, '$.nested.csrf');
  assert.equal(jsonToken.inferredType, 'token');

  const graphqlVariables = reopened.listParameters({ location: 'graphql', text: 'support_admin', limit: 5 });
  assert.equal(graphqlVariables.some((parameter) => parameter.name === 'variables.role'), true);

  const xmlSecret = reopened.listParameters({ location: 'xml', text: 'target-inventory-xml-secret', limit: 5 })[0];
  assert(xmlSecret);
  assert.equal(xmlSecret.name, 'secret');

  const fullExchange = reopened.getHttpExchange('hx-target-json');
  assert(fullExchange);
  assert.match(fullExchange.requestRaw.toString('utf8'), /target-inventory-key/);
  assert.match(fullExchange.responseRaw.toString('utf8'), /target-inventory-token/);

  await reopened.upsertIssue({
    id: 'issue-target-inventory',
    title: 'Target route and parameter inventory persists with raw replay evidence',
    type: 'target-inventory',
    severity: 'medium',
    confidence: 'firm',
    status: 'open',
    host: hosts[0].host,
    path: normalizedRoutes[0].normalizedPath,
    detail: `Route ${normalizedRoutes[0].id} and parameter ${cookie.id} keep target-inventory-token available for executor replay.`,
    remediation: 'Use inventory-backed route and parameter evidence during scanner and report triage.',
    evidenceRefs: [
      { kind: 'target-host', id: hosts[0].id, label: 'Inventory host', source: 'target-map' },
      { kind: 'target-route', id: normalizedRoutes[0].id, label: 'Normalized order route', source: 'target-map' },
      { kind: 'parameter', id: cookie.id, label: 'Session cookie parameter', source: 'target-map' },
      { kind: 'http-exchange', id: 'hx-target-json', label: 'Raw captured exchange', source: 'proxy' },
    ],
    source: 'target-inventory-workflow',
  });
  assert.equal(reopened.getIssue('issue-target-inventory').evidenceRefs.length, 4);

  const backup = await reopened.createBackup(path.join(artifactRoot, 'backups'), { label: 'target-inventory' });
  assert.equal(backup.stats.targetHostCount, 1);
  assert.equal(backup.stats.targetRouteCount, 3);
  assert.equal(backup.stats.parameterCount, stats.parameterCount);
  reopened.close();
  reopened = null;

  restored = await ProjectStore.open(backup.backupDir);
  stats = restored.stats();
  assert.equal(stats.targetHostCount, 1);
  assert.equal(stats.targetRouteCount, 3);
  assert.equal(restored.listParameters({ text: 'target-inventory-token', limit: 10 }).length >= 2, true);
  assert.match(restored.getHttpExchange('hx-target-json').requestRaw.toString('utf8'), /target-inventory-token/);
  assert.equal(restored.getIssue('issue-target-inventory').evidenceRefs.some((ref) => ref.kind === 'target-route'), true);

  console.log(`project-store-target-inventory-workflow: persisted ${stats.targetRouteCount} route(s), ${stats.parameterCount} parameter record(s), raw inventory evidence, issue refs, and backup restore from ${projectDir}`);
} finally {
  restored?.close();
  reopened?.close();
}
