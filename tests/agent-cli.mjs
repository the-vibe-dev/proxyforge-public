// run-all: slow  (spawns HTTP server and runs full agent CLI workflow; needs ~60 s)
import { strict as assert } from 'node:assert';
import { spawn } from 'node:child_process';
import { createHash, createHmac } from 'node:crypto';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  ProjectStore,
  appendProjectStorePendingHttpExchange,
} = require('../dist-electron/projectStore.js');

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyforge-agent-cli-'));
const observed = {
  replay: false,
  authorization: '',
  cookie: '',
  apiKey: '',
  bulkMaxActive: 0,
  refundRequests: 0,
  transport: [],
  discoveryAuthorization: '',
  discoveryCookie: '',
  discoveryApiKey: '',
  liveAuthorization: '',
  liveCookie: '',
  liveApiKey: '',
  liveTargetRequests: [],
  searchProviderAuthorization: '',
  searchProviderApiKey: '',
  searchProviderCookie: '',
  searchProviderBody: '',
};
let activeBulkRequests = 0;
const providerRecords = new Map();
const providerSecrets = {
  'agent-http-provider': 'agent-http-provider-token',
  'agent-dns-provider': 'agent-dns-provider-token',
};

const server = http.createServer(async (request, response) => {
  if (request.url === '/semantic/rank') {
    const body = await readAgentBody(request);
    observed.searchProviderAuthorization = String(request.headers.authorization ?? '');
    observed.searchProviderApiKey = String(request.headers['x-api-key'] ?? '');
    observed.searchProviderCookie = String(request.headers.cookie ?? '');
    observed.searchProviderBody = body;
    const parsed = JSON.parse(body);
    const documents = Array.isArray(parsed.documents) ? parsed.documents : [];
    const refundDocument = documents.find((document) => document.exchangeId === 'hx-agent-refund');
    const bodyText = JSON.stringify(parsed);
    response.writeHead(200, {
      'content-type': 'application/json',
      'x-agent-search-provider': 'fixture-rerank',
    });
    response.end(JSON.stringify({
      kind: 'proxyforge-agent-search-provider-rank-response',
      providerId: 'agent-live-semantic',
      matches: [
        {
          exchangeId: refundDocument?.exchangeId ?? 'hx-agent-refund',
          score: 0.98,
          rationale: `Fixture provider ranked refund authz evidence with ${bodyText.includes('agent-secret-token') ? 'full token context' : 'missing token context'}.`,
          labels: ['authz', 'refund', 'agent-secret-token'],
        },
      ],
      operationalEcho: {
        authorization: observed.searchProviderAuthorization,
        apiKey: observed.searchProviderApiKey,
        cookie: observed.searchProviderCookie,
        tokenPreserved: bodyText.includes('agent-secret-token'),
        cookiePreserved: bodyText.includes('agent-secret-session'),
        apiKeyPreserved: bodyText.includes('agent-secret-key'),
      },
      reportRedactionBoundary: 'redact-only-during-report-export',
    }));
    return;
  }

  if (request.url?.startsWith('/provider/')) {
    const body = await readAgentBody(request);
    const url = new URL(request.url, 'http://127.0.0.1');
    const parts = url.pathname.split('/').filter(Boolean);
    const [, providerId, tenantId, action, payloadId] = parts;
    if (!providerSecrets[providerId] || !tenantId || !action) {
      response.writeHead(404);
      response.end('unknown provider');
      return;
    }
    const authorization = String(request.headers.authorization ?? '');
    if (authorization !== `Bearer ${providerSecrets[providerId]}`) {
      response.writeHead(403);
      response.end('forbidden');
      return;
    }
    const recordKey = `${providerId}:${tenantId}`;
    if (action === 'ingest') {
      const protocol = url.searchParams.get('protocol') ?? 'http';
      const records = providerRecords.get(recordKey) ?? [];
      records.push({
        id: `${providerId}-${tenantId}-${records.length + 1}`,
        payloadId,
        protocol,
        observedAt: '2026-05-26T12:00:00.000Z',
        sourceIp: '127.0.0.1',
        sourceHost: request.headers.host,
        requestLine: `${request.method} ${request.url} HTTP/${request.httpVersion}`,
        userAgent: String(request.headers['user-agent'] ?? 'agent-provider-fixture'),
        raw: [
          `${request.method} ${request.url} HTTP/${request.httpVersion}`,
          ...Object.entries(request.headers).map(([name, value]) => `${name}: ${Array.isArray(value) ? value.join(', ') : value ?? ''}`),
          '',
          body,
        ].join('\r\n'),
        severity: protocol === 'dns' ? 'medium' : 'high',
        tags: ['oast', 'agent-provider-host-proof', providerId, tenantId],
      });
      providerRecords.set(recordKey, records);
      response.writeHead(202, { 'content-type': 'application/json', 'x-agent-provider-ingest': providerId });
      response.end(JSON.stringify({ accepted: true, providerId, tenantId, payloadId, protocol }));
      return;
    }
    if (action === 'poll') {
      const responseBody = JSON.stringify({
        kind: 'proxyforge-agent-provider-poll-response',
        providerId,
        tenantId,
        interactions: providerRecords.get(recordKey) ?? [],
        payloadTokens: (providerRecords.get(recordKey) ?? []).map((record) => record.raw),
        operationalSecrets: {
          authorization,
          signingSecret: 'agent-provider-signing-secret',
        },
        replaySupported: true,
        reportRedactionBoundary: 'redact-only-during-report-export',
      });
      const signature = createHmac('sha256', 'agent-provider-signing-secret').update(responseBody).digest('hex');
      response.writeHead(200, {
        'content-type': 'application/json',
        'x-proxyforge-signature-key-id': `${providerId}-key`,
        'x-proxyforge-signature': signature,
      });
      response.end(responseBody);
      return;
    }
  }

  if (request.url === '/api/replay-redirect') {
    observed.transport.push({ url: request.url, connection: String(request.headers.connection ?? '') });
    request.resume();
    request.on('end', () => {
      response.writeHead(302, {
        location: '/api/replay-final',
        'content-type': 'text/plain',
      });
      response.end('redirecting');
    });
    return;
  }

  if (request.url === '/api/replay-final') {
    observed.transport.push({ url: request.url, connection: String(request.headers.connection ?? '') });
    request.resume();
    request.on('end', () => {
      const body = JSON.stringify({ ok: true, transport: 'final' });
      response.writeHead(200, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
      });
      response.end(body);
    });
    return;
  }

  if (request.url === '/api/replay-slow') {
    observed.transport.push({ url: request.url, connection: String(request.headers.connection ?? '') });
    request.resume();
    request.on('end', () => {
      setTimeout(() => {
        response.writeHead(200, { 'content-type': 'text/plain' });
        response.end('too slow');
      }, 300);
    });
    return;
  }

  if (request.url?.startsWith('/api/bulk-replay')) {
    activeBulkRequests += 1;
    observed.bulkMaxActive = Math.max(observed.bulkMaxActive, activeBulkRequests);
    response.once('finish', () => {
      activeBulkRequests = Math.max(0, activeBulkRequests - 1);
    });
    request.resume();
    request.on('end', () => {
      setTimeout(() => {
        const body = JSON.stringify({ ok: true, path: request.url, bulk: true });
        response.writeHead(200, {
          'content-type': 'application/json',
          'content-length': Buffer.byteLength(body),
          'x-agent-bulk-replay': 'accepted',
        });
        response.end(body);
      }, 25);
    });
    return;
  }

  if (request.url?.endsWith('/openapi.json') || request.url?.endsWith('/admin/export')) {
    observed.discoveryAuthorization = String(request.headers.authorization ?? '');
    observed.discoveryCookie = String(request.headers.cookie ?? '');
    observed.discoveryApiKey = String(request.headers['x-api-key'] ?? '');
    request.resume();
    request.on('end', () => {
      const body = JSON.stringify({ openapi: '3.1.0', paths: { '/api/refunds': {}, '/admin/export': {} } });
      response.writeHead(200, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        'x-agent-content-discovery': 'hit',
      });
      response.end(body);
    });
    return;
  }

  if (request.url?.startsWith('/api/refunds')) {
    observed.refundRequests += 1;
    observed.replay = true;
    observed.authorization = String(request.headers.authorization ?? '');
    observed.cookie = String(request.headers.cookie ?? '');
    observed.apiKey = String(request.headers['x-api-key'] ?? '');
    request.resume();
    request.on('end', () => {
      const body = JSON.stringify({ ok: true, role: 'support_admin' });
      response.writeHead(202, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        'x-agent-replay': 'accepted',
      });
      response.end(body);
    });
    return;
  }

  if (request.url?.startsWith('/live/')) {
    const body = await readAgentBody(request);
    observed.liveAuthorization = String(request.headers.authorization ?? '');
    observed.liveCookie = String(request.headers.cookie ?? '');
    observed.liveApiKey = String(request.headers['x-api-key'] ?? '');
    observed.liveTargetRequests.push({
      method: request.method,
      url: request.url,
      authorization: observed.liveAuthorization,
      cookie: observed.liveCookie,
      apiKey: observed.liveApiKey,
      body,
    });
    if (request.url.startsWith('/live/admin')) {
      response.writeHead(403, {
        'content-type': 'application/json',
        'x-agent-live-target': 'admin-denied',
      });
      response.end(JSON.stringify({ error: 'forbidden', token: 'agent-secret-token', role: 'customer' }));
      return;
    }
    if (request.url.startsWith('/live/graphql')) {
      response.writeHead(200, {
        'content-type': 'application/json',
        'x-agent-live-target': 'graphql',
      });
      response.end(JSON.stringify({ data: { viewer: { id: 'agent-secret-session' } }, apiKey: 'agent-secret-key' }));
      return;
    }
    if (request.url.startsWith('/live/redirect')) {
      response.writeHead(302, {
        location: '/live/profile?user=agent-secret-token',
        'content-type': 'text/plain',
        'x-agent-live-target': 'redirect',
      });
      response.end('redirecting agent-secret-token');
      return;
    }
    response.writeHead(200, {
      'content-type': 'text/html',
      'x-agent-live-target': 'profile',
    });
    response.end('<html><form><input name="csrf" value="agent-secret-token"></form><script>window.token="agent-secret-session"</script></html>');
    return;
  }

  response.writeHead(200, { 'content-type': 'text/html' });
  response.end('<html><a href="/api/refunds?orderId=100">refunds</a></html>');
});

let wsServer;

try {
  const port = await listen(server);
  wsServer = createWebSocketEchoServer();
  const wsPort = await listen(wsServer);
  const targetUrl = `http://127.0.0.1:${port}/api/refunds?orderId=100`;
  const webSocketUrl = `ws://127.0.0.1:${wsPort}/socket?room=orders`;
  const webSocketPayload = JSON.stringify({
    action: 'refund-review',
    role: 'customer',
    token: 'agent-secret-token',
    session: 'agent-secret-session',
    apiKey: 'agent-secret-key',
  });
  const projectPath = path.join(tempDir, 'agent-project.proxyforge.json');
  const bulkProjectPath = path.join(tempDir, 'agent-bulk-project.proxyforge.json');
  const callbacksPath = path.join(tempDir, 'callbacks.json');
  const providerManifestPath = path.join(tempDir, 'callback-providers.json');
  const liveTargetsPath = path.join(tempDir, 'live-targets.json');
  const approvalPath = path.join(tempDir, 'approval.json');
  const extensionManifestPath = path.join(tempDir, 'legacy-proxy-style-extension.json');
  const sequencerSamplesPath = path.join(tempDir, 'sequencer-samples.txt');
  const scannerDir = path.join(tempDir, 'scanner-run');
  const reportsDir = path.join(tempDir, 'reports');
  const vantixDir = path.join(tempDir, 'vantix');
  const mitmSessionDir = path.join(tempDir, 'mitm-session');
  const projectStoreDir = path.join(tempDir, 'agent-store.proxyforge');
  const projectStoreBackupRoot = path.join(tempDir, 'agent-store-backups');

  await fs.writeFile(projectPath, JSON.stringify({
    version: 1,
    savedAt: '2026-05-24T22:20:00.000Z',
    projectName: 'Agent CLI Assessment',
    scopeAllowlist: ['127.0.0.1'],
    webSocketMessages: [
      {
        id: 'ws-agent-refund-client',
        connectionId: 'ws-agent-refund-conn',
        time: '2026-05-24T22:19:59.000Z',
        direction: 'client',
        host: `127.0.0.1:${wsPort}`,
        path: '/socket?room=orders',
        url: webSocketUrl,
        opcode: 1,
        type: 'text',
        payload: webSocketPayload,
        payloadEncoding: 'text',
        length: Buffer.byteLength(webSocketPayload),
        tags: ['websocket', 'refund', 'agent'],
      },
      {
        id: 'ws-agent-refund-server',
        connectionId: 'ws-agent-refund-conn',
        time: '2026-05-24T22:20:00.000Z',
        direction: 'server',
        host: `127.0.0.1:${wsPort}`,
        path: '/socket?room=orders',
        url: webSocketUrl,
        opcode: 1,
        type: 'text',
        payload: '{"ok":true,"state":"customer"}',
        payloadEncoding: 'text',
        length: 30,
        tags: ['websocket', 'baseline'],
      },
    ],
    exchanges: [
      {
        id: 'hx-agent-refund',
        method: 'POST',
        host: '127.0.0.1',
        path: '/api/refunds?orderId=100',
        url: targetUrl,
        status: 403,
        length: 61,
        mime: 'application/json',
        risk: 'high',
        timing: 30,
        source: 'repeater',
        time: '22:19:55',
        requestRaw: [
          'POST /api/refunds?orderId=100 HTTP/1.1',
          `Host: 127.0.0.1:${port}`,
          'Authorization: Bearer agent-secret-token',
          'Cookie: session=agent-secret-session',
          'X-API-Key: agent-secret-key',
          'Content-Type: application/json',
          'Content-Length: 35',
          '',
          '{"amount":100,"reason":"agent cli"}',
        ].join('\n'),
        responseRaw: 'HTTP/1.1 403 Forbidden\nContent-Type: application/json\n\n{"error":"role required"}',
        notes: 'Agent CLI replay and scanner candidate.',
        tags: ['authz', 'refund'],
      },
      {
        id: 'hx-agent-redirect',
        method: 'GET',
        host: '127.0.0.1',
        path: '/api/replay-redirect',
        url: `http://127.0.0.1:${port}/api/replay-redirect`,
        status: 302,
        length: 11,
        mime: 'text/plain',
        risk: 'info',
        timing: 5,
        source: 'repeater',
        time: '22:19:56',
        requestRaw: [
          'GET /api/replay-redirect HTTP/1.1',
          `Host: 127.0.0.1:${port}`,
          'Authorization: Bearer agent-secret-token',
          'Cookie: session=agent-secret-session',
          'X-API-Key: agent-secret-key',
          '',
          '',
        ].join('\n'),
        responseRaw: 'HTTP/1.1 302 Found\nLocation: /api/replay-final\n\nredirecting',
        notes: 'Agent CLI replay transport redirect candidate.',
        tags: ['replay-transport', 'redirect'],
      },
      {
        id: 'hx-agent-slow',
        method: 'GET',
        host: '127.0.0.1',
        path: '/api/replay-slow',
        url: `http://127.0.0.1:${port}/api/replay-slow`,
        status: 200,
        length: 8,
        mime: 'text/plain',
        risk: 'info',
        timing: 300,
        source: 'repeater',
        time: '22:19:57',
        requestRaw: [
          'GET /api/replay-slow HTTP/1.1',
          `Host: 127.0.0.1:${port}`,
          'Authorization: Bearer agent-secret-token',
          'Cookie: session=agent-secret-session',
          'X-API-Key: agent-secret-key',
          '',
          '',
        ].join('\n'),
        responseRaw: 'HTTP/1.1 200 OK\nContent-Type: text/plain\n\ntoo slow',
        notes: 'Agent CLI replay transport timeout candidate.',
        tags: ['replay-transport', 'timeout'],
      },
      {
        id: 'hx-agent-anvil',
        method: 'GET',
        host: '127.0.0.1',
        path: '/api/refunds/metadata',
        url: `http://127.0.0.1:${port}/api/refunds/metadata`,
        status: 200,
        length: 82,
        mime: 'application/json',
        risk: 'medium',
        timing: 24,
        source: 'scanner',
        time: '22:19:58',
        requestRaw: [
          'GET /api/refunds/metadata HTTP/1.1',
          `Host: 127.0.0.1:${port}`,
          'Authorization: Bearer agent-secret-token',
          'Cookie: session=agent-secret-session',
          'X-API-Key: agent-secret-key',
          '',
          '',
        ].join('\n'),
        responseRaw: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"role":"support_admin","path":"internal/export"}',
        notes: 'Agent CLI Anvil custom scan-check candidate.',
        tags: ['scanner', 'anvil', 'metadata'],
      },
    ],
    issues: [
      {
        id: 'issue-agent-1',
        title: 'Refund authorization boundary requires replay',
        severity: 'high',
        host: '127.0.0.1',
        path: '/api/refunds',
        confidence: 'firm',
        status: 'open',
        detail: 'Role-boundary replay needed for refund endpoint.',
        remediation: 'Enforce server-side authorization checks for refund writes.',
      },
    ],
    callbackPayloads: [
      {
        id: 'cb-1',
        token: 'callback-secret-token',
        label: 'Agent Scanner OAST payload',
        protocol: 'http',
        endpoint: 'https://callbacks.agent.test/probe/callback-secret-token',
        createdAt: '2026-05-24T22:18:00.000Z',
        status: 'observed',
        sourceExchangeId: 'hx-agent-refund',
        sourceHost: '127.0.0.1',
        sourcePath: '/api/refunds?orderId=100',
        notes: 'Agent CLI Scanner OAST issue promotion payload.',
      },
    ],
    callbackInteractions: [
      {
        id: 'int-1',
        payloadId: 'cb-1',
        token: 'callback-secret-token',
        protocol: 'http',
        observedAt: '2026-05-24T22:19:30.000Z',
        sourceIp: '127.0.0.1',
        sourceHost: 'callbacks.agent.test',
        requestLine: 'GET /probe/callback-secret-token HTTP/1.1',
        userAgent: 'ProxyForge Agent OAST',
        raw: 'GET /probe/callback-secret-token HTTP/1.1\nAuthorization: Bearer callback-secret-token\nCookie: session=agent-secret-session\n\n',
        severity: 'high',
        tags: ['oast', 'scanner'],
      },
    ],
  }, null, 2));
  const bulkExchanges = Array.from({ length: 24 }, (_unused, index) => ({
    id: `hx-agent-bulk-${index + 1}`,
    method: 'GET',
    host: '127.0.0.1',
    path: `/api/bulk-replay?item=${index + 1}`,
    url: `http://127.0.0.1:${port}/api/bulk-replay?item=${index + 1}`,
    status: 200,
    length: 40,
    mime: 'application/json',
    risk: 'medium',
    timing: 10,
    source: 'repeater',
    time: '22:19:56',
    requestRaw: [
      `GET /api/bulk-replay?item=${index + 1} HTTP/1.1`,
      `Host: 127.0.0.1:${port}`,
      'Authorization: Bearer agent-secret-token',
      'Cookie: session=agent-secret-session',
      'X-API-Key: agent-secret-key',
      '',
      '',
    ].join('\n'),
    responseRaw: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"ok":true}',
    notes: 'Agent CLI bulk replay soak candidate.',
    tags: ['bulk-replay', 'authz'],
  }));
  await fs.writeFile(bulkProjectPath, JSON.stringify({
    version: 1,
    savedAt: '2026-05-24T22:20:30.000Z',
    projectName: 'Agent CLI Bulk Replay Assessment',
    scopeAllowlist: ['127.0.0.1'],
    exchanges: bulkExchanges,
    issues: [],
  }, null, 2));
  await fs.writeFile(callbacksPath, JSON.stringify({
    publicBaseUrl: 'callbacks.agent.test',
    retentionHours: 24,
    payloads: [
      {
        id: 'cb-1',
        token: 'callback-secret-token',
        sourceExchangeId: 'hx-agent-refund',
        protocol: 'http',
        status: 'active',
        createdAt: '2026-05-24T22:18:00.000Z',
        lastInteractionAt: '2026-05-24T22:19:00.000Z',
      },
      {
        id: 'cb-old',
        token: 'old-callback-secret-token',
        protocol: 'dns',
        status: 'active',
        createdAt: '2026-05-24T20:00:00.000Z',
        lastInteractionAt: '2026-05-24T20:05:00.000Z',
      },
    ],
    interactions: [
      {
        id: 'int-1',
        payloadId: 'cb-1',
        token: 'callback-secret-token',
        protocol: 'http',
        observedAt: '2026-05-24T22:19:30.000Z',
        sourceIp: '127.0.0.1',
        raw: 'GET /probe/callback-secret-token HTTP/1.1\nAuthorization: Bearer callback-secret-token\n\n',
      },
      {
        id: 'int-old',
        payloadId: 'cb-old',
        token: 'old-callback-secret-token',
        protocol: 'dns',
        observedAt: '2026-05-24T20:05:00.000Z',
        sourceIp: '127.0.0.2',
        raw: 'TXT old-callback-secret-token.old.callbacks.agent.test',
      },
    ],
    signedPollBatches: [
      {
        id: 'agent-signed-poll-1',
        reportReady: true,
        content: 'proxyforge-callback-signed-poll-batch callback-secret-token',
      },
    ],
    replayExecutionBatches: [
      {
        id: 'agent-replay-execution-1',
        reportReady: true,
        content: 'proxyforge-callback-replay-execution-batch callback-secret-token',
      },
    ],
    lifecycleReviews: [
      {
        id: 'agent-lifecycle-1',
        reportReady: true,
        content: 'proxyforge-callback-payload-lifecycle-review old-callback-secret-token',
      },
    ],
    ciHandoffPackages: [
      {
        id: 'agent-ci-handoff-1',
        reportReady: true,
        content: 'proxyforge-callback-ci-handoff-package callback-secret-token',
      },
    ],
  }, null, 2));
  await fs.writeFile(providerManifestPath, JSON.stringify({
    publicBaseUrl: 'providers.agent.test',
    requireSigned: true,
    minProviderCount: 2,
    minProtocolCount: 2,
    minInteractionCount: 2,
    relayIntegrationPackageIds: ['agent-relay-integration-package'],
    payloads: [
      {
        id: 'agent-provider-http-payload',
        providerId: 'agent-http-provider',
        tenantId: 'agent-alpha',
        token: 'agent-http-provider-secret-token',
        protocol: 'http',
      },
      {
        id: 'agent-provider-dns-payload',
        providerId: 'agent-dns-provider',
        tenantId: 'agent-alpha',
        token: 'agent-dns-provider-secret-token',
        protocol: 'dns',
      },
    ],
    providers: [
      {
        id: 'agent-http-provider',
        kind: 'generic-http-relay',
        tenantId: 'agent-alpha',
        baseUrl: `http://127.0.0.1:${port}`,
        ingestPath: '/provider/:providerId/:tenantId/ingest/:payloadId?protocol=http',
        pollPath: '/provider/:providerId/:tenantId/poll',
        bearerToken: providerSecrets['agent-http-provider'],
        payloadIds: ['agent-provider-http-payload'],
      },
      {
        id: 'agent-dns-provider',
        kind: 'dns-webhook-relay',
        tenantId: 'agent-alpha',
        baseUrl: `http://127.0.0.1:${port}`,
        ingestPath: '/provider/:providerId/:tenantId/ingest/:payloadId?protocol=dns',
        pollPath: '/provider/:providerId/:tenantId/poll',
        bearerToken: providerSecrets['agent-dns-provider'],
        payloadIds: ['agent-provider-dns-payload'],
      },
    ],
  }, null, 2));
  await fs.writeFile(liveTargetsPath, JSON.stringify({
    minHostCount: 1,
    minRouteCount: 4,
    minStatusClassCount: 3,
    minRequestCount: 4,
    headers: {
      Authorization: 'Bearer agent-secret-token',
      Cookie: 'session=agent-secret-session',
      'X-API-Key': 'agent-secret-key',
    },
    targets: [
      {
        id: 'agent-live-profile',
        label: 'Live profile route',
        url: `http://127.0.0.1:${port}/live/profile?user=agent-secret-token`,
        role: 'customer',
        category: 'profile',
        expectedToolHandoff: ['scanner', 'intruder', 'replay'],
      },
      {
        id: 'agent-live-admin-denied',
        label: 'Live admin role boundary',
        url: `http://127.0.0.1:${port}/live/admin?role=customer`,
        role: 'customer',
        category: 'authz',
        expectedToolHandoff: ['scanner', 'intruder'],
      },
      {
        id: 'agent-live-graphql',
        label: 'Live GraphQL route',
        url: `http://127.0.0.1:${port}/live/graphql`,
        method: 'POST',
        role: 'support_admin',
        category: 'api',
        headers: { 'Content-Type': 'application/json' },
        body: '{"query":"query Viewer { viewer { id } }","token":"agent-secret-token"}',
        expectedToolHandoff: ['scanner', 'intruder'],
      },
      {
        id: 'agent-live-redirect',
        label: 'Live redirect route',
        url: `http://127.0.0.1:${port}/live/redirect?next=profile`,
        role: 'anonymous',
        category: 'redirect',
        expectedToolHandoff: ['scanner', 'replay'],
      },
    ],
  }, null, 2));
  await fs.writeFile(approvalPath, JSON.stringify({
    id: 'approval-agent-1',
    status: 'approved',
    operator: 'Agent Test',
    reason: 'Local controlled validation',
  }, null, 2));
  await fs.writeFile(extensionManifestPath, JSON.stringify({
    name: 'Agent legacy proxy Compatibility Probe',
    version: '0.3.0',
    author: 'ProxyForge Agent Test',
    hooks: ['request-editor', 'response-editor', 'message-editor', 'scanner-check', 'headless-runner'],
    permissions: ['read-traffic', 'modify-traffic', 'create-issues'],
    dependencies: [
      { name: 'legacy-extension-shim', version: '^2026.5.0' },
      { name: '@proxyforge/session-adapter', version: '^1.2.0' },
    ],
    runtimeApi: {
      apiVersion: 'proxyforge-extender-api/v1',
      sandbox: 'isolated-worker',
      actions: [
        { hook: 'request-editor', kind: 'request-listener', name: 'IHttpListener.processHttpMessage(request)' },
        { hook: 'request-editor', kind: 'proxy-listener', name: 'IProxyListener.processProxyMessage(request)' },
        { hook: 'request-editor', kind: 'request-response-annotation', value: 'Agent selected message annotation.' },
        { hook: 'request-editor', kind: 'helpers-update-parameter', name: 'agentEdge', value: 'true' },
        { hook: 'request-editor', kind: 'helpers-url-encode', value: 'agent-secret-token' },
        { hook: 'request-editor', kind: 'context-menu-multi-selection', title: 'Send selected requests to Intruder' },
        { hook: 'request-editor', kind: 'session-token-refresh', name: 'X-Session-Token', value: 'agent-secret-token' },
        { hook: 'response-editor', kind: 'response-listener', name: 'IHttpListener.processHttpMessage(response)' },
        { hook: 'response-editor', kind: 'helpers-analyze-response', name: 'IExtensionHelpers.analyzeResponse' },
        { hook: 'scanner-check', kind: 'scanner-check', title: 'Agent migrated scanner check' },
        { hook: 'scanner-check', kind: 'scanner-insertion-point-provider', name: 'IScannerInsertionPointProvider.getInsertionPoints' },
        { hook: 'message-editor', kind: 'editor-tab', title: 'Agent legacy proxy Message Tab' },
        { hook: 'message-editor', kind: 'extension-state-listener', name: 'IExtensionStateListener.extensionUnloaded' },
        { hook: 'headless-runner', kind: 'policy-denied', name: 'ILegacyExtensionCallbacks.makeHttpRequest' },
      ],
    },
  }, null, 2));
  await fs.writeFile(sequencerSamplesPath, Array.from({ length: 5000 }, (_value, index) =>
    `agent-secret-token-${String(index).padStart(4, '0')}-${createHash('sha256').update(`proxyforge-agent-sequencer:${index}`).digest('base64url')}`,
  ).join('\n'));

  const agentStore = await ProjectStore.create(projectStoreDir, {
    projectName: 'Agent Project Store Recovery',
    projectId: 'agent-project-store-recovery',
  });
  await agentStore.upsertRepeaterTab({
    id: 'rt-agent-store',
    name: 'Agent stored Repeater request',
    targetUrl,
    rawRequest: [
      'POST /api/refunds?orderId=100 HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      'Authorization: Bearer agent-secret-token',
      'Cookie: session=agent-secret-session',
      'X-API-Key: agent-secret-key',
      '',
      '{"agent":true}',
    ].join('\r\n'),
    group: 'agent-cli',
    tags: ['agent', 'repeater'],
  });
  await agentStore.addRepeaterSend({
    id: 'send-agent-store',
    tabId: 'rt-agent-store',
    targetUrl,
    rawRequest: [
      'POST /api/refunds?orderId=100 HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      'Authorization: Bearer agent-secret-token',
      'Cookie: session=agent-secret-session',
      'X-API-Key: agent-secret-key',
      '',
      '{"agent":true,"secret":"agent-secret-token"}',
    ].join('\r\n'),
    responseRaw: [
      'HTTP/1.1 202 Accepted',
      'Content-Type: application/json',
      '',
      '{"ok":true,"token":"agent-secret-token"}',
    ].join('\r\n'),
    status: 202,
    mime: 'application/json',
    timingMs: 31,
    tags: ['agent', 'repeater-send'],
  });
  await agentStore.addIntruderAttack({
    id: 'intruder-agent-store',
    targetUrl,
    rawRequest: [
      'GET /api/refunds?orderId=§orderId§ HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      'Authorization: Bearer agent-secret-token',
      'Cookie: session=agent-secret-session',
      'X-API-Key: agent-secret-key',
      '',
      '',
    ].join('\r\n'),
    attackMode: 'sniper',
    payloadPositions: 1,
    totalRequests: 2,
    blocked: false,
    message: 'Agent Project Store Intruder attack preserves raw result rows for restart and agent replay.',
    payloads: ['100', 'support_admin'],
    payloadSets: [['100', 'support_admin']],
    payloadProcessors: ['url-encode'],
    payloadRules: ['grep:agent-secret-token'],
    scopeAllowlist: ['127.0.0.1'],
    resourcePoolName: 'agent-cli-intruder',
    resourcePoolMaxConcurrent: 1,
    results: [
      {
        id: 'intruder-result-agent-100',
        payload: '100',
        payloads: ['100'],
        attackMode: 'sniper',
        status: 202,
        length: 44,
        mime: 'application/json',
        timing: 21,
        grepMatches: ['agent-secret-token'],
        extractMatches: ['orderId=100'],
        notes: 'Agent Intruder row keeps Bearer agent-secret-token.',
        requestRaw: [
          'GET /api/refunds?orderId=100 HTTP/1.1',
          `Host: 127.0.0.1:${port}`,
          'Authorization: Bearer agent-secret-token',
          'Cookie: session=agent-secret-session',
          '',
          '',
        ].join('\r\n'),
        responseRaw: [
          'HTTP/1.1 202 Accepted',
          'Content-Type: application/json',
          '',
          '{"ok":true,"token":"agent-secret-token"}',
        ].join('\r\n'),
        tags: ['agent', 'intruder', 'grep-match'],
        oastPayloadIds: [],
        callbackInteractionIds: [],
      },
      {
        id: 'intruder-result-agent-support',
        payload: 'support_admin',
        payloads: ['support_admin'],
        attackMode: 'sniper',
        status: 403,
        length: 52,
        mime: 'application/json',
        timing: 29,
        grepMatches: ['agent-secret-key'],
        extractMatches: ['role=support_admin'],
        notes: 'Agent Intruder row keeps api key material until report export.',
        requestRaw: [
          'GET /api/refunds?orderId=support_admin HTTP/1.1',
          `Host: 127.0.0.1:${port}`,
          'Authorization: Bearer agent-secret-token',
          'X-API-Key: agent-secret-key',
          '',
          '',
        ].join('\r\n'),
        responseRaw: [
          'HTTP/1.1 403 Forbidden',
          'Content-Type: application/json',
          '',
          '{"blocked":true,"apiKey":"agent-secret-key"}',
        ].join('\r\n'),
        tags: ['agent', 'intruder', 'grep-match'],
        oastPayloadIds: [],
        callbackInteractionIds: [],
      },
    ],
  });
  await agentStore.addScannerTask({
    id: 'scan-agent-store',
    request: {
      rawRequest: [
        'GET /reflected?input=agent-secret-token HTTP/1.1',
        `Host: 127.0.0.1:${port}`,
        'Authorization: Bearer agent-secret-token',
        'Cookie: session=agent-secret-session',
        'X-API-Key: agent-secret-key',
        '',
        '',
      ].join('\r\n'),
      targetUrl,
      scopeAllowlist: ['127.0.0.1'],
      checks: ['reflected-xss'],
      throttleMs: 0,
      maxRequests: 1,
    },
    summary: {
      id: 'scan-agent-store',
      targetUrl,
      startedAt: '2026-05-26T03:01:00.000Z',
      completedAt: '2026-05-26T03:01:01.000Z',
      totalRequests: 1,
      blocked: false,
      message: 'Agent scanner task preserves raw probe evidence for restart and agent review.',
      findings: [{
        id: 'finding-agent-store-reflection',
        checkId: 'reflected-xss',
        title: 'Agent scanner reflected input proof',
        severity: 'medium',
        confidence: 'firm',
        host: '127.0.0.1',
        path: '/reflected',
        detail: 'Scanner finding detail preserves Bearer agent-secret-token and session=agent-secret-session.',
        remediation: 'Encode reflected input and redact only exported report text.',
        evidenceExchangeId: 'scan-agent-exchange',
        dedupeKey: 'agent-store:reflected-xss:/reflected',
        confidenceReason: 'Fixture response reflected the scanner-controlled token.',
      }],
      suppressedFindings: [],
      tuning: {
        profile: 'browser-app-calibration',
        falsePositiveControls: [],
        suppressedFindingCount: 0,
        dedupedFindingCount: 0,
        findingDedupeKeys: ['agent-store:reflected-xss:/reflected'],
        calibrationNotes: ['agent fixture'],
      },
      exchanges: [{
        id: 'scan-agent-exchange',
        method: 'GET',
        url: `${targetUrl}?scan=agent-secret-token`,
        host: '127.0.0.1',
        path: '/api/refunds?orderId=100&scan=agent-secret-token',
        status: 200,
        length: 64,
        mime: 'text/html',
        risk: 'medium',
        timing: 18,
        notes: 'Agent scanner exchange keeps full raw executor material.',
        source: 'scanner',
        time: '03:01:01',
        requestRaw: [
          'GET /reflected?input=agent-secret-token HTTP/1.1',
          `Host: 127.0.0.1:${port}`,
          'Authorization: Bearer agent-secret-token',
          'Cookie: session=agent-secret-session',
          '',
          '',
        ].join('\r\n'),
        responseRaw: [
          'HTTP/1.1 200 OK',
          'Content-Type: text/html',
          '',
          '<output>agent-secret-token</output>',
        ].join('\r\n'),
        tags: ['scanner', 'active-scan', 'check:reflected-xss'],
      }],
    },
    tags: ['agent', 'scanner'],
  });
  await agentStore.upsertIssue({
    id: 'issue-agent-store',
    title: 'Agent Project Store issue',
    type: 'manual',
    severity: 'high',
    confidence: 'firm',
    status: 'open',
    host: '127.0.0.1',
    path: '/api/refunds?orderId=100',
    detail: 'Agent issue detail preserves Bearer agent-secret-token and session=agent-secret-session for executor replay.',
    remediation: 'Validate the refund boundary and rotate api_key=agent-secret-key only in the report phase.',
    evidenceRefs: [
      { kind: 'repeater-send', id: 'send-agent-store', label: 'Agent Repeater send', source: 'repeater' },
      { kind: 'intruder-result', id: 'intruder-result-agent-100', label: 'Agent Intruder row', source: 'intruder' },
      { kind: 'scanner-finding', id: 'finding-agent-store-reflection', label: 'Agent Scanner finding', source: 'scanner' },
    ],
    source: 'agent-cli-fixture',
  });
  await agentStore.addReportExport({
    id: 'report-agent-store',
    format: 'json',
    fileName: 'agent-store-report.json',
    path: 'reports/agent-store-report.json',
    content: JSON.stringify({
      kind: 'agent-store-report',
      issueIds: ['issue-agent-store'],
      redacted: '[redacted]',
    }, null, 2),
    issueIds: ['issue-agent-store'],
    exchangeIds: ['hx-agent-store-pending'],
    templateId: 'technical-remediation',
    sections: ['executive', 'technical', 'evidence'],
    preparedFor: 'Agent CLI',
    engagementId: 'AGENT-PROJECT-STORE',
    signatureStatus: 'unsigned',
    redacted: true,
    notes: 'Agent CLI report sample is report-phase material.',
  });
  await agentStore.addWebSocketFrames([
    {
      id: 'wsf-agent-client',
      connectionId: 'wsc-agent-store',
      direction: 'client',
      host: '127.0.0.1',
      path: '/ws/refunds',
      url: `ws://127.0.0.1:${port}/ws/refunds`,
      opcode: 1,
      type: 'text',
      payload: 'agent websocket session=agent-secret-session token=agent-secret-token',
      payloadEncoding: 'text',
      length: Buffer.byteLength('agent websocket session=agent-secret-session token=agent-secret-token'),
      tags: ['websocket', 'client', 'agent'],
      source: 'agent-cli-fixture',
    },
    {
      id: 'wsf-agent-server',
      connectionId: 'wsc-agent-store',
      direction: 'server',
      host: '127.0.0.1',
      path: '/ws/refunds',
      url: `ws://127.0.0.1:${port}/ws/refunds`,
      opcode: 2,
      type: 'binary',
      payload: Buffer.from('agent websocket api_key=agent-secret-key', 'utf8').toString('hex'),
      payloadEncoding: 'hex',
      length: Buffer.byteLength('agent websocket api_key=agent-secret-key'),
      tags: ['websocket', 'server', 'agent', 'replayed'],
      source: 'agent-cli-fixture',
    },
  ]);
  await agentStore.addAutomationRun({
    id: 'automation-agent-store',
    workflowId: 'wf-agent-project-store',
    workflowName: 'Agent Project Store automation',
    status: 'complete',
    trigger: 'scheduled',
    startedAt: '2026-05-26T03:02:00.000Z',
    completedAt: '2026-05-26T03:02:03.000Z',
    durationMs: 3000,
    totalRequests: 1,
    logs: [
      'Agent automation replay kept Bearer agent-secret-token.',
      'Agent automation scheduler kept session=agent-secret-session.',
    ],
    operationalRawMaterial: {
      sourceExchangeId: 'hx-agent-store-pending',
      requestRaw: 'Authorization: Bearer agent-secret-token\r\nCookie: session=agent-secret-session\r\nX-API-Key: agent-secret-key',
      responseRaw: '{"token":"agent-secret-token"}',
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    },
    schedulerJobId: 'scheduler-job-agent-store',
    schedulerLeaseId: 'scheduler-lease-agent-store',
    ciProvider: 'github-actions',
    ciConfig: 'AGENT_SECRET_TOKEN=agent-secret-token',
    tags: ['agent', 'automation'],
  });
  await agentStore.addAiRun({
    id: 'ai-agent-store',
    providerId: 'codex',
    task: 'replay-plan',
    status: 'complete',
    model: 'configured-default',
    startedAt: '2026-05-26T03:03:00.000Z',
    completedAt: '2026-05-26T03:03:02.000Z',
    summary: 'Agent AI run keeps raw prompt and output for replay planning.',
    prompt: 'Explain Bearer agent-secret-token and session=agent-secret-session for agent replay.',
    output: 'Use Repeater and Scanner with agent-secret-token; report redaction happens only during export.',
    evidenceCount: 2,
    command: 'codex exec --sandbox read-only -',
    providerLabel: 'Codex',
    contextDigest: 'agent-ai-context',
    usage: { promptTokens: 10, completionTokens: 12, totalTokens: 22, estimatedCostUsd: 0.001, latencyMs: 2000, source: 'estimated' },
    streamEvents: [{ id: 'ai-agent-complete', at: '2026-05-26T03:03:02.000Z', source: 'complete', text: 'agent-secret-token complete' }],
    suggestedActions: [{ id: 'ai-action-agent-repeater', kind: 'stage-repeater', label: 'Stage in Repeater', detail: 'agent-secret-token', target: targetUrl, priority: 'medium' }],
    tags: ['agent', 'ai'],
  });
  await agentStore.addExtensionRun({
    id: 'extension-agent-store',
    extensionId: 'ext-agent-store',
    extensionName: 'Agent Header Lens',
    hook: 'request-editor',
    status: 'complete',
    target: `POST 127.0.0.1:${port}/api/refunds`,
    startedAt: '2026-05-26T03:04:00.000Z',
    completedAt: '2026-05-26T03:04:01.000Z',
    summary: 'Agent extension run kept request-editor secrets.',
    logs: [
      'request-editor saw X-API-Key: agent-secret-key.',
      'request-editor saw Authorization: Bearer agent-secret-token.',
    ],
    tags: ['agent', 'extension'],
  });
  agentStore.close();
  await appendProjectStorePendingHttpExchange(projectStoreDir, {
    id: 'hx-agent-store-pending',
    method: 'POST',
    url: targetUrl,
    host: '127.0.0.1',
    path: '/api/refunds?orderId=100',
    protocol: 'http',
    status: 202,
    mime: 'application/json',
    timingMs: 41,
    source: 'proxy',
    tags: ['agent-store', 'crash-recovery'],
    notes: 'Agent CLI Project Store pending capture with full secrets.',
    scopeState: 'captured',
    createdAt: '2026-05-26T03:00:00.000Z',
    requestRaw: [
      'POST /api/refunds?orderId=100 HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      'Authorization: Bearer agent-secret-token',
      'Cookie: session=agent-secret-session',
      'X-API-Key: agent-secret-key',
      'Content-Type: application/json',
      '',
      '{"amount":100,"storeToken":"agent-secret-token"}',
    ].join('\r\n'),
    responseRaw: [
      'HTTP/1.1 202 Accepted',
      'Content-Type: application/json',
      'Set-Cookie: callbackToken=agent-secret-callback; HttpOnly',
      '',
      '{"ok":true,"storeToken":"agent-secret-token"}',
    ].join('\r\n'),
  });

  const status = await runAgent(['status', '--project', projectPath, '--json']);
  assert.equal(status.status, 'completed');
  assert.equal(status.project.name, 'Agent CLI Assessment');
  assert.equal(status.project.exchangeCount, 4);
  assert.equal(status.safety.redacted, false);
  assert.equal(status.safety.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.equal(status.data.scannerCatalog.kind, 'proxyforge-agent-scanner-catalog');
  assert.equal(status.data.scannerCatalog.checkCount, 13);
  assert(status.data.scannerCatalog.checks.some((check) => check.id === 'command-injection' && check.severity === 'critical'));
  assert(status.data.scannerCatalog.checkPacks.some((pack) => pack.id === 'full-active' && pack.checks.includes('reflected-xss')));

  const externalCwd = path.join(tempDir, 'external-vantix-runner');
  await fs.mkdir(externalCwd, { recursive: true });
  const externalStatus = await runAgentFromCwd(['status', '--project', projectPath, '--json'], externalCwd);
  assert.equal(externalStatus.status, 'completed');
  assert.equal(externalStatus.data.runtime.cwd, externalCwd);
  assert.equal(externalStatus.data.runtime.appRoot, process.cwd());

  const externalBrowser = await runAgentFromCwd(['chromium-capture', '--project', projectPath, '--target', targetUrl, '--scope', '127.0.0.1', '--json'], externalCwd);
  assert.equal(externalBrowser.status, 'completed');
  assert.match(externalBrowser.data.matrix.content, /proxyforge-managed-browser-launch-matrix/, 'external agents should load runtime modules relative to ProxyForge, not their cwd');
  assert.match(externalBrowser.data.matrix.summary, /Linux\/Windows launch profile/);

  const automationList = await runAgent(['automation-list', '--project', projectPath, '--json']);
  assert.equal(automationList.status, 'completed');
  assert.equal(automationList.data.kind, 'proxyforge-agent-automation-inventory');
  assert(automationList.data.workflows.some((workflow) => workflow.id === 'wf-agent-scheduled-crawl'));
  assert(automationList.data.schedulerState.queue.some((job) => job.status === 'queued'));

  const automationPlan = await runAgent(['automation-run', '--project', projectPath, '--workflow', 'wf-agent-scheduled-crawl', '--json']);
  assert.equal(automationPlan.status, 'planned');
  assert.equal(automationPlan.safety.trafficSent, false);
  assert.equal(automationPlan.data.kind, 'proxyforge-agent-automation-run-plan');

  const automationRun = await runAgent(['automation-run', '--project', projectPath, '--workflow', 'wf-agent-scheduled-crawl', '--execute', '--json']);
  assert.equal(automationRun.status, 'completed');
  assert.equal(automationRun.safety.trafficSent, true);
  assert.equal(automationRun.data.execution.status, 'complete');
  assert.match(JSON.stringify(automationRun.data.execution), /agent-secret-token|agent-secret-session|agent-secret-key/);
  assertHasOperationalSecrets(automationRun);

  const automationBlocked = await runAgentExpectStatus(['automation-run', '--project', projectPath, '--workflow', 'wf-agent-on-tag-authz', '--execute', '--json'], 2);
  assert.equal(automationBlocked.status, 'blocked');
  assert.match(JSON.stringify(automationBlocked.data.execution), /approval/);
  assertHasOperationalSecrets(automationBlocked);

  const automationCi = await runAgent(['automation-ci-export', '--project', projectPath, '--workflow', 'wf-agent-ci-headless', '--json']);
  assert.equal(automationCi.status, 'completed');
  assert.equal(automationCi.data.presets.length, 4);
  assert.equal(automationCi.data.presets.every((preset) => Object.values(preset.requirements).every(Boolean)), true);
  assert.match(JSON.stringify(automationCi.data.presets), /proxyforge headless|proxyforge-results\.sarif|proxyforge-junit\.xml|PROXYFORGE_AUTHORIZATION/);

  const automationScheduler = await runAgent(['automation-scheduler-tick', '--project', projectPath, '--execute', '--json']);
  assert.equal(automationScheduler.status, 'completed');
  assert.equal(automationScheduler.data.tick.claimedJobs >= 1, true);
  assert(automationScheduler.artifacts.some((item) => item.kind === 'automation-scheduler-tick'));
  assertHasOperationalSecrets(automationScheduler);

  const automationParityPath = path.join(tempDir, 'automation-parity.json');
  const automationParity = await runAgent(['automation-parity-export', '--project', projectPath, '--out', automationParityPath, '--json']);
  assert.equal(automationParity.status, 'completed');
  assert.equal(automationParity.data.parityPackage.kind, 'proxyforge-agent-automation-parity-evidence-package');
  assert.equal(Object.values(automationParity.data.parityPackage.requirements).every(Boolean), true);
  assert.match(automationParity.data.parityPackage.content, /agent-secret-token|agent-secret-session|agent-secret-key|proxyforge headless|reportPhaseOnlyRedaction/i);
  assert.equal((await fs.stat(automationParityPath)).isFile(), true);
  assertHasOperationalSecrets(automationParity);

  const automationServicePath = path.join(tempDir, 'automation-service-lifecycle.json');
  const automationService = await runAgent(['automation-service-plan', '--project', projectPath, '--workflow', 'wf-agent-scheduled-crawl', '--out', automationServicePath, '--json']);
  assert.equal(automationService.status, 'completed');
  assert.equal(automationService.data.serviceLifecyclePackage.kind, 'proxyforge-automation-service-lifecycle-package');
  assert.equal(Object.values(automationService.data.serviceLifecyclePackage.requirements).every(Boolean), true);
  assert.equal(automationService.data.serviceLifecyclePackage.platformCount, 2);
  assert.match(JSON.stringify(automationService.data.serviceLifecyclePackage), /systemctl --user|schtasks \/Create|automation-scheduler-tick|Restart=on-failure|RestartOnFailure/i);
  assert.match(automationService.data.serviceLifecyclePackage.content, /agent-secret-token|agent-secret-session|agent-secret-key|redact-only-during-report-export/i);
  assert.equal((await fs.stat(automationServicePath)).isFile(), true);
  assertHasOperationalSecrets(automationService);

  const search = await runAgent(['search', '--project', projectPath, '--query', 'refund authz', '--json']);
  assert.ok(search.data.matchCount >= 1);
  assert.ok(search.data.matches.some((match) => match.id === 'hx-agent-refund'));
  assertHasOperationalSecrets(search);

  const searchIndex = await runAgent(['search-index', '--project', projectPath, '--query', 'authz refund', '--json']);
  assert.equal(searchIndex.data.index.kind, 'proxyforge-search-semantic-index');
  assert.equal(searchIndex.data.index.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.match(searchIndex.data.index.content, /agent-secret-token/);
  assert.ok(searchIndex.data.matches.some((match) => match.exchangeId === 'hx-agent-refund'));
  assertHasOperationalSecrets(searchIndex);

  const privateSearchIndexPath = path.join(tempDir, 'private-output', 'search-index.json');
  const originalUmask = process.umask(0o000);
  try {
    const privateSearchIndex = await runAgent([
      'search-index',
      '--project',
      projectPath,
      '--query',
      'authz refund',
      '--out',
      privateSearchIndexPath,
      '--json',
    ]);
    assert.equal(privateSearchIndex.data.indexPath, privateSearchIndexPath);
    assertHasOperationalSecrets(await fs.readFile(privateSearchIndexPath, 'utf8'));
    await assertPrivatePathMode(path.dirname(privateSearchIndexPath), 0o700, 'search-index output directory');
    await assertPrivatePathMode(privateSearchIndexPath, 0o600, 'search-index output file');
  } finally {
    process.umask(originalUmask);
  }

  const searchIndexSoak = await runAgent(['search-index', '--project', projectPath, '--query', 'authz refund', '--soak', '--soak-min-exchanges', '1', '--soak-min-matches', '1', '--json']);
  assert.equal(searchIndexSoak.data.soakReport.kind, 'proxyforge-search-large-project-soak-report');
  assert.equal(searchIndexSoak.data.soakReport.status, 'pass');
  assert.equal(searchIndexSoak.data.soakReport.indexRestored, true);
  assert.equal(searchIndexSoak.data.soakReport.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.match(searchIndexSoak.data.soakReport.content, /agent-secret-token/);
  assert.equal(searchIndexSoak.artifacts.some((item) => item.kind === 'search-large-project-soak'), true);
  assertHasOperationalSecrets(searchIndexSoak);

  const searchProviderPlan = await runAgent([
    'search-index',
    '--project',
    projectPath,
    '--query',
    'authz refund',
    '--provider-url',
    `http://127.0.0.1:${port}/semantic/rank`,
    '--provider-id',
    'agent-live-semantic',
    '--provider-label',
    'Agent live semantic provider',
    '--provider-model',
    'fixture-rerank',
    '--scope',
    '127.0.0.1',
    '--json',
  ]);
  assert.equal(searchProviderPlan.status, 'planned');
  assert.equal(searchProviderPlan.safety.trafficSent, false);
  assert.equal(searchProviderPlan.data.providerPlan.kind, 'proxyforge-agent-search-live-provider-invocation-plan');
  assert.equal(searchProviderPlan.data.providerPlan.requirements.providerHostScopeCovered, true);
  assert.equal(searchProviderPlan.data.providerPlan.requirements.fullFidelityCorpusPreserved, true);
  assert.equal(observed.searchProviderBody, '', 'dry search provider plan should not contact the provider');

  const searchProviderPackagePath = path.join(tempDir, 'search-provider-package.json');
  const searchProvider = await runAgent([
    'search-index',
    '--project',
    projectPath,
    '--query',
    'authz refund',
    '--provider-url',
    `http://127.0.0.1:${port}/semantic/rank`,
    '--provider-id',
    'agent-live-semantic',
    '--provider-label',
    'Agent live semantic provider',
    '--provider-model',
    'fixture-rerank',
    '--provider-token',
    'agent-search-provider-token',
    '--provider-api-key',
    'agent-search-provider-key',
    '--provider-cookie',
    'search-provider-session=agent-search-provider-session',
    '--provider-out',
    searchProviderPackagePath,
    '--scope',
    '127.0.0.1',
    '--execute',
    '--json',
  ]);
  assert.equal(searchProvider.status, 'completed');
  assert.equal(searchProvider.mode, 'executed');
  assert.equal(searchProvider.safety.trafficSent, true);
  assert.equal(searchProvider.safety.requestCount, 1);
  assert.equal(searchProvider.data.providerPackage.kind, 'proxyforge-agent-search-live-provider-invocation-package');
  assert.equal(searchProvider.data.providerPackage.reportReady, true);
  assert.equal(searchProvider.data.providerMatches[0].exchangeId, 'hx-agent-refund');
  assert.equal(searchProvider.data.providerRankedMatches[0].id, 'hx-agent-refund');
  assert.equal(searchProvider.artifacts.some((item) => item.kind === 'search-live-provider-invocation'), true);
  assert.equal(observed.searchProviderAuthorization, 'Bearer agent-search-provider-token');
  assert.equal(observed.searchProviderApiKey, 'agent-search-provider-key');
  assert.equal(observed.searchProviderCookie, 'search-provider-session=agent-search-provider-session');
  assert.match(observed.searchProviderBody, /agent-secret-token|agent-secret-session|agent-secret-key/);
  const searchProviderPackageContent = await fs.readFile(searchProviderPackagePath, 'utf8');
  assert.match(searchProviderPackageContent, /rawRequest|rawResponse|agent-secret-token|agent-secret-session|agent-secret-key|agent-search-provider-token|agent-search-provider-key|agent-search-provider-session/);

  const sequencer = await runAgent([
    'sequencer-analyze',
    '--sample-file',
    sequencerSamplesPath,
    '--label',
    'Agent session token corpus',
    '--soak',
    '--min-samples',
    '5000',
    '--min-reliability',
    'reliable',
    '--min-entropy-bits',
    '96',
    '--json',
  ]);
  assert.equal(sequencer.status, 'completed');
  assert.equal(sequencer.safety.trafficSent, false);
  assert.equal(sequencer.data.sampleCount, 5000);
  assert.equal(sequencer.data.result.reliability.level, 'reliable');
  assert.equal(sequencer.data.soakPackage.kind, 'proxyforge-agent-sequencer-large-sample-soak-package');
  assert.equal(sequencer.data.soakPackage.status, 'pass');
  assert.equal(sequencer.data.soakPackage.observed.sampleCount, 5000);
  assert.equal(sequencer.artifacts.some((item) => item.kind === 'sequencer-soak'), true);
  assert.match(JSON.stringify(sequencer), /agent-secret-token-0000/);

  const decoderInput = Buffer.from(JSON.stringify({
    token: 'agent-secret-token',
    cookie: 'agent-secret-session',
    apiKey: 'agent-secret-key',
  }), 'utf8').toString('base64');
  const decoderChain = await runAgent([
    'decoder-chain',
    '--input',
    decoderInput,
    '--transforms',
    'base64-decode,json-pretty',
    '--json',
  ]);
  assert.equal(decoderChain.status, 'completed');
  assert.equal(decoderChain.safety.trafficSent, false);
  assert.equal(decoderChain.data.kind, 'proxyforge-agent-decoder-transform-chain-package');
  assert.equal(decoderChain.data.run.ok, true);
  assert.deepEqual(decoderChain.data.transformIds, ['base64-decode', 'json-pretty']);
  assert.match(decoderChain.data.finalOutput, /agent-secret-token|agent-secret-session|agent-secret-key/);
  assert.match(decoderChain.data.package.content, /execution-full-fidelity-secrets-preserved|redact-only-during-report-export/);
  assertHasOperationalSecrets(decoderChain);

  const insertionOutPath = path.join(tempDir, 'agent-insertion-points.json');
  const insertionPoints = await runAgent([
    'insertion-points',
    '--project',
    projectPath,
    '--request-id',
    'hx-agent-refund',
    '--out',
    insertionOutPath,
    '--json',
  ]);
  assert.equal(insertionPoints.status, 'completed');
  assert.equal(insertionPoints.safety.trafficSent, false);
  assert.equal(insertionPoints.data.package.kind, 'proxyforge-agent-insertion-point-inventory-package');
  assert(insertionPoints.data.points.some((point) => point.location === 'query' && point.name === 'orderId'));
  assert(insertionPoints.data.points.some((point) => point.location === 'header' && point.name === 'Authorization'));
  assert(insertionPoints.data.points.some((point) => point.location === 'cookie' && point.name === 'session'));
  assert(insertionPoints.data.points.some((point) => point.location === 'json' && point.name === 'amount'));
  assert.match(insertionPoints.data.package.content, /agent-secret-token|agent-secret-session|agent-secret-key/);
  assert.equal((await fs.stat(insertionOutPath)).isFile(), true);
  assertHasOperationalSecrets(insertionPoints);

  const webSocketList = await runAgent(['websocket-list', '--project', projectPath, '--connection-id', 'ws-agent-refund-conn', '--json']);
  assert.equal(webSocketList.status, 'completed');
  assert.equal(webSocketList.safety.trafficSent, false);
  assert.equal(webSocketList.data.kind, 'proxyforge-agent-websocket-inventory');
  assert.equal(webSocketList.data.frameCount, 2);
  assert.match(JSON.stringify(webSocketList.data.frames), /agent-secret-token|agent-secret-session|agent-secret-key/);
  assertHasOperationalSecrets(webSocketList);

  const webSocketReplay = await runAgent([
    'websocket-replay',
    '--project',
    projectPath,
    '--frame-id',
    'ws-agent-refund-client',
    '--execute',
    '--timeout',
    '2000',
    '--json',
  ]);
  assert.equal(webSocketReplay.status, 'completed');
  assert.equal(webSocketReplay.safety.trafficSent, true);
  assert.equal(webSocketReplay.data.package.kind, 'proxyforge-agent-websocket-replay-result');
  assert.equal(webSocketReplay.data.package.result.handshakeAccepted, true);
  assert.match(JSON.stringify(webSocketReplay.data.package.result.receivedFrames), /agent-ws-ack|agent-secret-token|agent-secret-session|agent-secret-key/);
  assertHasOperationalSecrets(webSocketReplay);

  const webSocketFuzzOutPath = path.join(tempDir, 'agent-websocket-fuzz.json');
  const webSocketFuzz = await runAgent([
    'websocket-fuzz',
    '--project',
    projectPath,
    '--frame-id',
    'ws-agent-refund-client',
    '--payloads',
    'agent-secret-token|agent-secret-session|agent-secret-key,support_admin|agent-secret-token|agent-secret-session|agent-secret-key',
    '--max-probes',
    '2',
    '--execute',
    '--timeout',
    '2000',
    '--out',
    webSocketFuzzOutPath,
    '--json',
  ]);
  assert.equal(webSocketFuzz.status, 'completed');
  assert.equal(webSocketFuzz.data.package.kind, 'proxyforge-agent-websocket-fuzz-result');
  assert.equal(webSocketFuzz.data.package.summary.totalProbes, 2);
  assert(webSocketFuzz.data.package.results.every((probe) => probe.outcome === 'accepted'));
  assert.match(JSON.stringify(webSocketFuzz.data.package.results), /support_admin|agent-secret-token|agent-secret-session|agent-secret-key/);
  assert.equal((await fs.stat(webSocketFuzzOutPath)).isFile(), true);
  assertHasOperationalSecrets(webSocketFuzz);

  const webSocketTranscriptPath = path.join(tempDir, 'agent-websocket-transcript.md');
  const webSocketTranscript = await runAgent([
    'websocket-transcript-export',
    '--project',
    projectPath,
    '--connection-id',
    'ws-agent-refund-conn',
    '--format',
    'markdown',
    '--out',
    webSocketTranscriptPath,
    '--json',
  ]);
  assert.equal(webSocketTranscript.status, 'completed');
  assert.equal(webSocketTranscript.safety.trafficSent, false);
  assert.equal(webSocketTranscript.data.transcript.kind, 'proxyforge-agent-websocket-transcript');
  assert.equal(webSocketTranscript.data.transcript.frameCount, 2);
  assert.match(await fs.readFile(webSocketTranscriptPath, 'utf8'), /agent-secret-token|agent-secret-session|agent-secret-key|refund-review/);
  assertHasOperationalSecrets(webSocketTranscript);

  const projectStoreStatus = await runAgent(['project-store-status', '--store', projectStoreDir, '--json']);
  assert.equal(projectStoreStatus.status, 'completed');
  assert.equal(projectStoreStatus.data.kind, 'proxyforge-agent-project-store-status');
  assert.equal(projectStoreStatus.data.recovery.recoveredHttpExchangeCount, 1);
  assert.equal(projectStoreStatus.data.recovery.requirements.rawOperationalSecretsPreserved, true);
  assert.equal(projectStoreStatus.data.stats.exchangeCount, 2);
  assert.equal(projectStoreStatus.data.stats.targetHostCount >= 1, true);
  assert.equal(projectStoreStatus.data.stats.targetRouteCount >= 2, true);
  assert.equal(projectStoreStatus.data.stats.parameterCount >= 6, true);
  assert.equal(projectStoreStatus.data.stats.repeaterSendCount, 1);
  assert.equal(projectStoreStatus.data.stats.intruderAttackCount, 1);
  assert.equal(projectStoreStatus.data.stats.intruderResultCount, 2);
  assert.equal(projectStoreStatus.data.stats.scannerTaskCount, 1);
  assert.equal(projectStoreStatus.data.stats.scannerFindingCount, 1);
  assert.equal(projectStoreStatus.data.stats.webSocketConnectionCount, 1);
  assert.equal(projectStoreStatus.data.stats.webSocketFrameCount, 2);
  assert.equal(projectStoreStatus.data.stats.issueCount, 1);
  assert.equal(projectStoreStatus.data.stats.reportExportCount, 1);
  assert.equal(projectStoreStatus.data.stats.automationRunCount, 1);
  assert.equal(projectStoreStatus.data.stats.aiRunCount, 1);
  assert.equal(projectStoreStatus.data.stats.extensionRunCount, 1);
  assert.equal(projectStoreStatus.data.stats.aiPromptBytes > 0, true);
  assert.equal(projectStoreStatus.data.stats.aiOutputBytes > 0, true);
  assert.match(projectStoreStatus.data.sampleRepeaterSends[0].rawRequest, /agent-secret-token/);
  assert.match(projectStoreStatus.data.sampleIntruderAttacks[0].rawRequest, /agent-secret-token/);
  assert.match(projectStoreStatus.data.sampleIntruderResults[0].requestRaw, /agent-secret-token/);
  assert.match(projectStoreStatus.data.sampleScannerFindings[0].evidenceExchange.requestRaw, /agent-secret-token/);
  assert.match(JSON.stringify(projectStoreStatus.data.sampleTargetHosts), /127\.0\.0\.1/);
  assert.match(JSON.stringify(projectStoreStatus.data.sampleTargetRoutes), /api\/refunds|reflected/);
  assert.match(JSON.stringify(projectStoreStatus.data.sampleParameters), /agent-secret-token|agent-secret-session|agent-secret-key/);
  assert.match(projectStoreStatus.data.sampleWebSocketFrames[0].payloadPreview, /agent-secret-token|6167656e7420776562736f636b6574/);
  assert.match(projectStoreStatus.data.sampleIssues[0].detail, /agent-secret-token/);
  assert.match(projectStoreStatus.data.sampleReports[0].contentPreview, /agent-store-report/);
  assert.match(JSON.stringify(projectStoreStatus.data.sampleAutomationRuns), /agent-secret-token|agent-secret-session|agent-secret-key/);
  assert.match(JSON.stringify(projectStoreStatus.data.sampleAiRuns), /agent-secret-token|agent-secret-session/);
  assert.match(JSON.stringify(projectStoreStatus.data.sampleExtensionRuns), /agent-secret-token|agent-secret-key/);
  assert.match(JSON.stringify(projectStoreStatus), /agent-secret-token|agent-secret-session|agent-secret-key/);
  assertHasOperationalSecrets(projectStoreStatus);

  const projectStoreRecoveryPath = path.join(tempDir, 'project-store-recovery.json');
  const projectStoreRecover = await runAgent(['project-store-recover', '--store', projectStoreDir, '--out', projectStoreRecoveryPath, '--json']);
  assert.equal(projectStoreRecover.status, 'completed');
  assert.equal(projectStoreRecover.data.recoveredHttpExchangeCount, 0);
  assert.equal(projectStoreRecover.data.skippedCommittedCount, 1);
  assert.equal((await fs.stat(projectStoreRecoveryPath)).isFile(), true);
  assertHasOperationalSecrets(projectStoreRecover);

  const projectStoreBackupPlan = await runAgent(['project-store-backup', '--store', projectStoreDir, '--out', projectStoreBackupRoot, '--label', 'agent-restore-point', '--json']);
  assert.equal(projectStoreBackupPlan.status, 'planned');
  assert.equal(projectStoreBackupPlan.safety.trafficSent, false);
  assert.match(projectStoreBackupPlan.data.command, /project-store-backup/);

  const projectStoreBackup = await runAgent(['project-store-backup', '--store', projectStoreDir, '--out', projectStoreBackupRoot, '--label', 'agent-restore-point', '--execute', '--json']);
  assert.equal(projectStoreBackup.status, 'completed');
  assert.equal(projectStoreBackup.data.backup.kind, 'proxyforge-project-store-backup');
  assert.equal(projectStoreBackup.data.backup.requirements.databaseCopied, true);
  assert.equal(projectStoreBackup.data.backup.requirements.recoveryJournalCopied, true);
  assert.equal(projectStoreBackup.data.backup.stats.exchangeCount, 2);
  assert.equal(projectStoreBackup.data.backup.stats.targetHostCount >= 1, true);
  assert.equal(projectStoreBackup.data.backup.stats.targetRouteCount >= 2, true);
  assert.equal(projectStoreBackup.data.backup.stats.parameterCount >= 6, true);
  assert.equal(projectStoreBackup.data.backup.stats.repeaterSendCount, 1);
  assert.equal(projectStoreBackup.data.backup.stats.intruderAttackCount, 1);
  assert.equal(projectStoreBackup.data.backup.stats.intruderResultCount, 2);
  assert.equal(projectStoreBackup.data.backup.stats.scannerTaskCount, 1);
  assert.equal(projectStoreBackup.data.backup.stats.scannerFindingCount, 1);
  assert.equal(projectStoreBackup.data.backup.stats.webSocketConnectionCount, 1);
  assert.equal(projectStoreBackup.data.backup.stats.webSocketFrameCount, 2);
  assert.equal(projectStoreBackup.data.backup.stats.issueCount, 1);
  assert.equal(projectStoreBackup.data.backup.stats.reportExportCount, 1);
  assert.equal(projectStoreBackup.data.backup.stats.automationRunCount, 1);
  assert.equal(projectStoreBackup.data.backup.stats.aiRunCount, 1);
  assert.equal(projectStoreBackup.data.backup.stats.extensionRunCount, 1);
  assert.match(projectStoreBackup.data.backup.content, /agent-project-store-recovery/);
  await fs.access(projectStoreBackup.data.backup.manifestPath);
  assertHasOperationalSecrets(projectStoreBackup);

  const importedHistoryPath = path.join(tempDir, 'agent-import-history.jsonl');
  await fs.writeFile(importedHistoryPath, `${JSON.stringify({
    kind: 'proxyforge-agent-mitm-exchange',
    payload: {
      exchange: {
        id: 'hx-agent-imported-refund',
        method: 'POST',
        host: '127.0.0.1',
        path: '/api/refunds?orderId=200',
        url: `http://127.0.0.1:${port}/api/refunds?orderId=200`,
        status: 202,
        length: 27,
        mime: 'application/json',
        risk: 'medium',
        timing: 18,
        source: 'proxy',
        time: '2026-05-24T22:21:00.000Z',
        requestRaw: [
          'POST /api/refunds?orderId=200 HTTP/1.1',
          `Host: 127.0.0.1:${port}`,
          'Authorization: Bearer agent-secret-token',
          'Cookie: session=agent-secret-session',
          'X-API-Key: agent-secret-key',
          'Content-Type: application/json',
          '',
          '{"amount":200}',
        ].join('\n'),
        responseRaw: 'HTTP/1.1 202 Accepted\nContent-Type: application/json\n\n{"ok":true}',
        tags: ['mitm'],
      },
    },
  })}\n`, 'utf8');
  const proxyImport = await runAgent(['proxy-import', '--file', importedHistoryPath, '--json']);
  assert.equal(proxyImport.status, 'completed');
  assert.match(proxyImport.data.sourceFormat, /agent-(jsonl|mitm-event)/);
  assert.equal(proxyImport.data.exchangeCount, 1);
  assert.equal(proxyImport.data.exchanges[0].tags.includes('proxy-import'), true);
  assertHasOperationalSecrets(proxyImport);

  const legacyProxyRequestRaw = [
    'GET /legacy-proxy/import?token=full HTTP/1.1',
    `Host: 127.0.0.1:${port}`,
    'Authorization: Bearer legacy-proxy-secret-token',
    'Cookie: session=legacy-proxy-secret-session',
    'X-API-Key: legacy-proxy-secret-key',
    '',
    '',
  ].join('\r\n');
  const legacyProxyResponseRaw = [
    'HTTP/1.1 200 OK',
    'Content-Type: text/html',
    '',
    '<html>legacy-proxy import ok</html>',
  ].join('\r\n');
  const legacyProxyXmlPath = path.join(tempDir, 'agent-legacy-proxy-history.xml');
  await fs.writeFile(legacyProxyXmlPath, [
    '<?xml version="1.0"?>',
    '<items>',
    '<item>',
    '<time>2026-05-26T00:00:00.000Z</time>',
    `<url>http://127.0.0.1:${port}/legacy-proxy/import?token=full</url>`,
    '<host>127.0.0.1</host>',
    `<port>${port}</port>`,
    '<protocol>http</protocol>',
    '<method>GET</method>',
    '<path>/legacy-proxy/import?token=full</path>',
    '<status>200</status>',
    '<responselength>26</responselength>',
    '<mimetype>HTML</mimetype>',
    `<request base64="true">${Buffer.from(legacyProxyRequestRaw, 'utf8').toString('base64')}</request>`,
    `<response base64="true">${Buffer.from(legacyProxyResponseRaw, 'utf8').toString('base64')}</response>`,
    '</item>',
    '</items>',
  ].join('\n'), 'utf8');
  const legacyProxyImport = await runAgent(['proxy-import', '--file', legacyProxyXmlPath, '--json']);
  assert.equal(legacyProxyImport.status, 'completed');
  assert.equal(legacyProxyImport.data.sourceFormat, 'legacy-proxy-xml');
  assert.equal(legacyProxyImport.data.exchangeCount, 1);
  assert.equal(legacyProxyImport.data.exchanges[0].mime, 'text/html');
  assert.equal(legacyProxyImport.data.exchanges[0].tags.includes('legacy-proxy-xml'), true);
  assert.match(JSON.stringify(legacyProxyImport), /Bearer legacy-proxy-secret-token|session=legacy-proxy-secret-session|legacy-proxy-secret-key/);

  const rawHttpArchivePath = path.join(tempDir, 'agent-raw-http.txt');
  await fs.writeFile(rawHttpArchivePath, [
    'POST /raw/import HTTP/1.1',
    `Host: 127.0.0.1:${port}`,
    'Authorization: Bearer raw-http-secret-token',
    'Cookie: session=raw-http-secret-session',
    'Content-Type: application/json',
    '',
    '{"apiKey":"raw-http-secret-key"}',
    'HTTP/1.1 201 Created',
    'Content-Type: application/json',
    '',
    '{"ok":true}',
  ].join('\r\n'), 'utf8');
  const rawHttpImport = await runAgent(['proxy-import', '--file', rawHttpArchivePath, '--json']);
  assert.equal(rawHttpImport.status, 'completed');
  assert.equal(rawHttpImport.data.sourceFormat, 'raw-http');
  assert.equal(rawHttpImport.data.exchangeCount, 1);
  assert.equal(rawHttpImport.data.exchanges[0].status, 201);
  assert.equal(rawHttpImport.data.exchanges[0].tags.includes('raw-http'), true);
  assert.match(JSON.stringify(rawHttpImport), /Bearer raw-http-secret-token|raw-http-secret-session|raw-http-secret-key/);

  const contentDiscovery = await runAgent(['content-discovery-plan', '--project', projectPath, '--limit', '20', '--json']);
  assert.equal(contentDiscovery.status, 'completed');
  assert.equal(contentDiscovery.data.plan.kind, 'proxyforge-agent-content-discovery-plan');
  assert.equal(contentDiscovery.data.plan.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert(contentDiscovery.data.plan.candidateCount >= 1);
  assert.match(JSON.stringify(contentDiscovery.data.plan), /openapi\.json|swagger\.json|bulk|export|robots\.txt/);

  const contentDiscoveryRunPlan = await runAgent([
    'content-discovery-run',
    '--project',
    projectPath,
    '--scope',
    '127.0.0.1',
    '--limit',
    '6',
    '--concurrency',
    '2',
    '--throttle',
    '0',
    '--wordlist',
    'admin/export,missing.txt',
    '--json',
  ]);
  assert.equal(contentDiscoveryRunPlan.status, 'planned');
  assert.equal(contentDiscoveryRunPlan.safety.trafficSent, false);
  assert.equal(contentDiscoveryRunPlan.data.runPlan.kind, 'proxyforge-agent-content-discovery-run-plan');
  assert(contentDiscoveryRunPlan.data.runPlan.candidateCount >= 1);

  const contentDiscoveryRun = await runAgent([
    'content-discovery-run',
    '--project',
    projectPath,
    '--scope',
    '127.0.0.1',
    '--limit',
    '6',
    '--concurrency',
    '2',
    '--throttle',
    '0',
    '--wordlist',
    'admin/export,missing.txt',
    '--soak',
    '--min-requests',
    '4',
    '--min-discovered',
    '1',
    '--max-failures',
    '0',
    '--execute',
    '--json',
  ]);
  assert.equal(contentDiscoveryRun.status, 'completed');
  assert.equal(contentDiscoveryRun.safety.trafficSent, true);
  assert.equal(contentDiscoveryRun.data.summary.kind, 'proxyforge-agent-content-discovery-run-summary');
  assert(contentDiscoveryRun.data.summary.totalRequests >= 4);
  assert(contentDiscoveryRun.data.summary.discoveredCount >= 1);
  assert.equal(contentDiscoveryRun.data.summary.maxInFlight >= 2, true);
  assert.equal(contentDiscoveryRun.data.soakPackage.kind, 'proxyforge-agent-content-discovery-runner-soak-package');
  assert.equal(contentDiscoveryRun.data.soakPackage.status, 'pass');
  assert(contentDiscoveryRun.data.results.some((item) => /openapi\.json|admin\/export/.test(item.candidate.url)));
  assert.match(observed.discoveryAuthorization, /agent-secret-token/);
  assert.match(observed.discoveryCookie, /agent-secret-session/);
  assert.match(observed.discoveryApiKey, /agent-secret-key/);
  assertHasOperationalSecrets(contentDiscoveryRun);

  const liveTargetProfilePath = path.join(tempDir, 'live-target-profile.json');
  const liveTargetPlan = await runAgent([
    'live-target-profile',
    '--manifest',
    liveTargetsPath,
    '--scope',
    '127.0.0.1',
    '--json',
  ]);
  assert.equal(liveTargetPlan.status, 'planned');
  assert.equal(liveTargetPlan.safety.trafficSent, false);
  assert.equal(liveTargetPlan.data.plan.kind, 'proxyforge-agent-live-target-profile-plan');
  assert.equal(liveTargetPlan.data.plan.targetCount, 4);
  assert.match(JSON.stringify(liveTargetPlan.data.plan), /agent-secret-token|agent-secret-session|agent-secret-key/);
  assertHasOperationalSecrets(liveTargetPlan);

  const liveTargetProfile = await runAgent([
    'live-target-profile',
    '--manifest',
    liveTargetsPath,
    '--scope',
    '127.0.0.1',
    '--execute',
    '--out',
    liveTargetProfilePath,
    '--json',
  ]);
  assert.equal(liveTargetProfile.status, 'completed');
  assert.equal(liveTargetProfile.safety.trafficSent, true);
  assert.equal(liveTargetProfile.safety.requestCount, 4);
  assert.equal(liveTargetProfile.data.package.kind, 'proxyforge-agent-live-target-profile-package');
  assert.equal(liveTargetProfile.data.package.liveRequestCount, 4);
  assert.equal(liveTargetProfile.data.package.hostCount, 1);
  assert.equal(liveTargetProfile.data.package.routeCount, 4);
  assert.equal(liveTargetProfile.data.package.statusClassCount, 3);
  assert.equal(liveTargetProfile.data.package.reportReady, true);
  assert.equal(liveTargetProfile.data.package.requirements.scannerCandidateHandoffCovered, true);
  assert.equal(liveTargetProfile.data.package.requirements.intruderCandidateHandoffCovered, true);
  assert(liveTargetProfile.data.package.scannerCandidates.some((candidate) => candidate.checks.includes('graphql-introspection')));
  assert(liveTargetProfile.data.package.intruderCandidates.some((candidate) => /§/.test(candidate.rawRequestWithMarkers)));
  assert(liveTargetProfile.artifacts.some((item) => item.kind === 'live-target-profile'));
  assert.equal(observed.liveTargetRequests.length, 4);
  assert.match(observed.liveAuthorization, /agent-secret-token/);
  assert.match(observed.liveCookie, /agent-secret-session/);
  assert.match(observed.liveApiKey, /agent-secret-key/);
  assert.match(await fs.readFile(liveTargetProfilePath, 'utf8'), /rawRequest|rawResponse|agent-secret-token|agent-secret-session|agent-secret-key/);
  assertHasOperationalSecrets(liveTargetProfile);

  const targetAccess = await runAgent([
    'target-access-review',
    '--project',
    projectPath,
    '--scope',
    '127.0.0.1',
    '--roles',
    'customer,support_admin',
    '--json',
  ]);
  assert.equal(targetAccess.status, 'completed');
  assert.equal(targetAccess.safety.trafficSent, false);
  assert.equal(targetAccess.data.review.kind, 'proxyforge-agent-target-access-control-review');
  assert.equal(targetAccess.data.review.lanes.length, 2);
  assert(targetAccess.data.review.lanes.some((lane) => lane.role === 'customer'));
  assert(targetAccess.data.review.lanes.some((lane) => lane.role === 'support_admin' && lane.underexposedCount >= 1));
  assert.match(JSON.stringify(targetAccess.data.review), /replay-matrix|scanner-run|target-access-review|role required/i);
  assertHasOperationalSecrets(targetAccess);

  const targetCompare = await runAgent([
    'target-map-compare',
    '--project',
    projectPath,
    '--scope',
    '127.0.0.1',
    '--baseline',
    'hx-agent-refund',
    '--candidate',
    'hx-agent-refund,hx-agent-redirect',
    '--json',
  ]);
  assert.equal(targetCompare.status, 'completed');
  assert.equal(targetCompare.data.comparison.kind, 'proxyforge-agent-target-site-map-comparison');
  assert.equal(targetCompare.data.comparison.stats.added >= 1, true);
  assert.equal(targetCompare.data.comparison.stats.changed, 0);
  assert.equal(targetCompare.data.comparison.stats.authzSensitiveChanged >= 1, true);
  assert.match(JSON.stringify(targetCompare.data.comparison), /parameter-names|authz-sensitive-route|target-access-review/);
  assertHasOperationalSecrets(targetCompare);

  const crawlPlan = await runAgent(['crawl-run', '--target', `http://127.0.0.1:${port}/`, '--scope', '127.0.0.1', '--depth', '1', '--pages', '4', '--throttle', '0', '--json']);
  assert.equal(crawlPlan.status, 'planned');
  assert.equal(crawlPlan.safety.trafficSent, false);
  assert.equal(crawlPlan.data.request.startUrl, `http://127.0.0.1:${port}/`);

  const crawlRun = await runAgent(['crawl-run', '--target', `http://127.0.0.1:${port}/`, '--scope', '127.0.0.1', '--depth', '1', '--pages', '4', '--throttle', '0', '--execute', '--json']);
  assert.equal(crawlRun.status, 'completed');
  assert.equal(crawlRun.safety.trafficSent, true);
  assert(crawlRun.data.summary.totalRequests >= 1);
  assert(crawlRun.data.summary.exchanges.some((exchange) => exchange.tags.includes('content-discovery')));
  assert(crawlRun.data.contentDiscovery.candidateCount >= 1);

  const view = await runAgent(['view', '--project', projectPath, '--request-id', 'hx-agent-refund', '--mode', 'raw', '--json']);
  assert.match(view.data.requestRaw, /Authorization: Bearer agent-secret-token/);
  assertHasOperationalSecrets(view);

  const browser = await runAgent(['chromium-capture', '--target', targetUrl, '--scope', '127.0.0.1', '--json']);
  assert.equal(browser.status, 'completed');
  assert.equal(browser.data.matrix.entryCount >= 4, true);
  assert(browser.safety.gates.includes('scope-match'));

  const mitmPort = await reservePort();
  const mitm = await startMitmSession([
    'mitm-start',
    '--project',
    projectPath,
    '--session-dir',
    mitmSessionDir,
    '--port',
    String(mitmPort),
    '--ensure-ca',
    '--scope',
    '127.0.0.1',
    '--json',
  ]);
  try {
    assert.equal(mitm.ready.status, 'running');
    assert.equal(mitm.ready.data.port, mitmPort);
    assert.match(mitm.ready.data.proxyUrl, new RegExp(`127\\.0\\.0\\.1:${mitmPort}`));
    assert.equal(mitm.ready.data.httpsInspection.enabled, true);
    assert.equal(mitm.ready.data.httpsInspection.upstreamTlsMode, 'strict');
    if (process.platform !== 'win32') {
      assert.equal((await fs.stat(mitmSessionDir)).mode & 0o777, 0o700, 'agent MITM session directory should be private');
      assert.equal((await fs.stat(path.join(mitmSessionDir, 'session.json'))).mode & 0o777, 0o600, 'agent MITM status file should be private');
      assert.equal((await fs.stat(path.join(mitmSessionDir, 'exchanges.jsonl'))).mode & 0o777, 0o600, 'agent MITM exchange log should be private');
    }
    assert.equal(mitm.ready.data.httpsInspection.certificate.ready, true);
    assert.match(mitm.ready.data.httpsInspection.certificate.fingerprintSha256, /^([0-9a-f]{2}:){31}[0-9a-f]{2}$/i);
    assert(mitm.ready.data.capabilities.includes('project-ca-status'));
    assert(mitm.ready.data.capabilities.includes('upstream-tls-mode'));
    await proxyHttpRequest(mitmPort, targetUrl);
    await waitFor(async () => {
      const exported = await runAgent(['mitm-export', '--session-dir', mitmSessionDir, '--json']);
      return exported.data.exchangeCount >= 1 ? exported : null;
    });
    const mitmStatus = await runAgent(['mitm-status', '--session-dir', mitmSessionDir, '--json']);
    assert.equal(mitmStatus.data.status, 'running');
    assert.equal(mitmStatus.data.httpsInspection.upstreamTlsMode, 'strict');
    assert.equal(mitmStatus.data.exchangeCount >= 1, true);
    const mitmExport = await runAgent(['mitm-export', '--session-dir', mitmSessionDir, '--json']);
    assert.equal(mitmExport.data.exchangeCount >= 1, true);
    assert(mitmExport.data.exchanges.some((exchange) => exchange.source === 'proxy' && exchange.url === targetUrl));
    assertHasOperationalSecrets(mitmExport);
  } finally {
    mitm.child.kill('SIGTERM');
    await mitm.done;
  }

  const replayPlan = await runAgent(['replay-run', '--project', projectPath, '--request-id', 'hx-agent-refund', '--json']);
  assert.equal(replayPlan.status, 'planned');
  assert.equal(replayPlan.safety.trafficSent, false);
  assertHasOperationalSecrets(replayPlan);

  const replay = await runAgent(['replay-run', '--project', projectPath, '--request-id', 'hx-agent-refund', '--execute', '--json']);
  assert.equal(replay.status, 'completed');
  assert.equal(replay.safety.trafficSent, true);
  assert.equal(replay.safety.requestCount, 1);
  assert.equal(replay.data.response.status, 202);
  assert.equal(observed.replay, true);
  assert.equal(observed.authorization, 'Bearer agent-secret-token');
  assert.match(observed.cookie, /agent-secret-session/);
  assert.equal(observed.apiKey, 'agent-secret-key');
  assertHasOperationalSecrets(replay);

  observed.transport = [];
  const manualRedirect = await runAgent(['replay-run', '--project', projectPath, '--request-id', 'hx-agent-redirect', '--redirect', 'manual', '--connection', 'close', '--timeout', '1000', '--execute', '--json']);
  assert.equal(manualRedirect.status, 'completed');
  assert.equal(manualRedirect.safety.requestCount, 1);
  assert.equal(manualRedirect.data.transportSettings.redirectMode, 'manual');
  assert.equal(manualRedirect.data.transportSettings.connectionMode, 'close');
  assert.equal(manualRedirect.data.response.status, 302);
  assert.equal(manualRedirect.data.response.redirectHistory.length, 0);
  assert.equal(manualRedirect.data.response.finalUrl, `http://127.0.0.1:${port}/api/replay-redirect`);
  assert.deepEqual(observed.transport.map((entry) => entry.url), ['/api/replay-redirect']);
  assert.equal(observed.transport.at(-1).connection, 'close');
  assertHasOperationalSecrets(manualRedirect);

  observed.transport = [];
  const followedRedirect = await runAgent(['replay-run', '--project', projectPath, '--request-id', 'hx-agent-redirect', '--redirect', 'follow', '--max-redirects', '5', '--connection', 'keep-alive', '--timeout', '1000', '--execute', '--json']);
  assert.equal(followedRedirect.status, 'completed');
  assert.equal(followedRedirect.safety.requestCount, 2);
  assert.equal(followedRedirect.data.transportSettings.redirectMode, 'follow');
  assert.equal(followedRedirect.data.transportSettings.connectionMode, 'keep-alive');
  assert.equal(followedRedirect.data.response.status, 200);
  assert.equal(followedRedirect.data.response.redirectHistory.length, 1);
  assert.equal(followedRedirect.data.response.finalUrl, `http://127.0.0.1:${port}/api/replay-final`);
  assert.match(followedRedirect.data.response.rawResponse, /replay-final|transport/);
  assert.deepEqual(observed.transport.map((entry) => entry.url), ['/api/replay-redirect', '/api/replay-final']);
  assert(observed.transport.every((entry) => entry.connection === 'keep-alive'));
  assertHasOperationalSecrets(followedRedirect);

  const timeoutReplay = await runAgentExpectStatus(['replay-run', '--project', projectPath, '--request-id', 'hx-agent-slow', '--timeout', '50', '--execute', '--json'], 2);
  assert.equal(timeoutReplay.status, 'blocked');
  assert.match(timeoutReplay.data.response.error, /timed out/i);
  assert.equal(timeoutReplay.data.transportSettings.timeoutMs, 250);
  assertHasOperationalSecrets(timeoutReplay);

  const bulkReplay = await runAgent([
    'bulk-replay',
    '--project',
    bulkProjectPath,
    '--limit',
    '24',
    '--concurrency',
    '4',
    '--result-window-size',
    '6',
    '--min-requests',
    '24',
    '--min-concurrency',
    '4',
    '--execute',
    '--soak',
    '--json',
  ]);
  assert.equal(bulkReplay.status, 'completed');
  assert.equal(bulkReplay.safety.trafficSent, true);
  assert.equal(bulkReplay.safety.requestCount, 24);
  assert.equal(bulkReplay.data.summary.kind, 'proxyforge-agent-bulk-replay-summary');
  assert.equal(bulkReplay.data.summary.totalRequests, 24);
  assert.equal(bulkReplay.data.summary.completedRequests, 24);
  assert.equal(bulkReplay.data.summary.maxConcurrency, 4);
  assert.equal(bulkReplay.data.summary.maxInFlight, 4);
  assert.equal(bulkReplay.data.summary.retainedResultCount, 6);
  assert.equal(bulkReplay.data.summary.droppedResultCount, 18);
  assert(bulkReplay.data.summary.requestRatePerSecond > 0);
  assert.equal(bulkReplay.data.soakPackage.kind, 'proxyforge-agent-bulk-replay-high-volume-soak-package');
  assert.equal(bulkReplay.data.soakPackage.status, 'pass');
  assert(bulkReplay.artifacts.some((item) => item.kind === 'bulk-replay-soak'));
  assert(observed.bulkMaxActive > 1, `expected bulk replay concurrency, saw ${observed.bulkMaxActive}`);
  assert(observed.bulkMaxActive <= 4, `bulk replay should cap concurrency at 4, saw ${observed.bulkMaxActive}`);
  assert.match(JSON.stringify(bulkReplay.data.results.at(-1)), /agent-secret-token|agent-secret-session|agent-secret-key/);
  assertHasOperationalSecrets(bulkReplay);

  const intruderModePlan = await runAgent([
    'intruder-run',
    '--project',
    projectPath,
    '--target',
    targetUrl,
    '--raw-request',
    [
      'GET /combo?role=§role§&region=§region§ HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      'Authorization: Bearer agent-secret-token',
      'Cookie: session=agent-secret-session',
      'X-API-Key: agent-secret-key',
      '',
      '',
    ].join('\n'),
    '--mode',
    'cluster-bomb',
    '--payloads',
    'user,admin',
    '--payload-set-two',
    'us,eu,ap',
    '--json',
  ]);
  assert.equal(intruderModePlan.status, 'planned');
  assert.equal(intruderModePlan.safety.trafficSent, false);
  assert.equal(intruderModePlan.data.plan.attackModeMatrix.kind, 'proxyforge-agent-intruder-attack-mode-matrix');
  assert.equal(intruderModePlan.data.plan.attackModeMatrix.modes.find((entry) => entry.mode === 'cluster-bomb').requestCount, 6);
  assert.match(JSON.stringify(intruderModePlan.data.plan.attackModeMatrix), /sniper|battering-ram|pitchfork|cluster-bomb|role=user&region=ap/);
  assertHasOperationalSecrets(intruderModePlan);

  const intruderTransformPlan = await runAgent([
    'intruder-run',
    '--project',
    projectPath,
    '--target',
    targetUrl,
    '--raw-request',
    [
      'POST /api/refunds HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      'Authorization: Bearer agent-secret-token',
      'Cookie: session=agent-secret-session',
      'X-API-Key: agent-secret-key',
      'Content-Type: application/json',
      '',
      '{"role":"§role§"}',
    ].join('\n'),
    '--payloads',
    '<Admin Root>,/api/v1/users',
    '--processors',
    'html-encode,json-escape',
    '--rules',
    'delimiter-variants,extension-bypass,null-byte',
    '--json',
  ]);
  assert.equal(intruderTransformPlan.status, 'planned');
  assert.deepEqual(intruderTransformPlan.data.plan.payloadProcessors, ['html-encode', 'json-escape']);
  assert.deepEqual(intruderTransformPlan.data.plan.payloadRules, ['delimiter-variants', 'extension-bypass', 'null-byte']);
  assert.equal(intruderTransformPlan.data.plan.attackModeMatrix.payloadTransformations.expandedPayloadCounts.every((count) => count > 4), true);
  assert.match(JSON.stringify(intruderTransformPlan.data.plan.attackModeMatrix.payloadTransformations), /&lt;Admin-Root&gt;|extension-bypass|null-byte|api-v1-users|%00/i);
  assertHasOperationalSecrets(intruderTransformPlan);

  const intruder = await runAgent([
    'intruder-run',
    '--project',
    projectPath,
    '--target',
    targetUrl,
    '--raw-request',
    [
      'POST /api/refunds?orderId=§orderId§ HTTP/1.1',
      `Host: 127.0.0.1:${port}`,
      'Authorization: Bearer agent-secret-token',
      'Cookie: session=agent-secret-session',
      'X-API-Key: agent-secret-key',
      'Content-Type: application/json',
      'Content-Length: 35',
      '',
      '{"amount":100,"reason":"agent cli"}',
    ].join('\n'),
    '--payload-count',
    '12',
    '--payload-prefix',
    'order',
    '--grep',
    'order',
    '--stream-chunk-size',
    '4',
    '--result-window-size',
    '5',
    '--memory-budget-bytes',
    '1',
    '--concurrency',
    '3',
    '--min-requests',
    '12',
    '--min-concurrency',
    '3',
    '--execute',
    '--soak',
    '--json',
  ]);
  assert.equal(intruder.status, 'completed');
  assert.equal(intruder.safety.trafficSent, true);
  assert.equal(intruder.safety.requestCount, 12);
  assert.equal(intruder.data.summary.totalRequests, 12);
  assert.equal(intruder.data.summary.streaming.maxConcurrency, 3);
  assert.equal(intruder.data.summary.streaming.maxInFlight, 3);
  assert.equal(intruder.data.summary.streaming.chunkCount, 3);
  assert.equal(intruder.data.summary.streaming.retainedResultCount, 5);
  assert.equal(intruder.data.summary.streaming.droppedResultCount, 7);
  assert(intruder.data.summary.streaming.requestRatePerSecond > 0);
  assert.equal(intruder.data.soakPackage.kind, 'proxyforge-agent-intruder-high-volume-soak-package');
  assert.equal(intruder.data.soakPackage.status, 'pass');
  assert(intruder.artifacts.some((item) => item.kind === 'intruder-run'));
  assert(intruder.artifacts.some((item) => item.kind === 'intruder-soak'));
  assert.match(intruder.data.summary.results.at(-1).requestRaw, /order-11/);
  assertHasOperationalSecrets(intruder);

  const desyncPlan = await runAgent(['repeater-desync-plan', '--project', projectPath, '--request-id', 'hx-agent-refund', '--json']);
  assert.equal(desyncPlan.status, 'planned');
  assert.equal(desyncPlan.data.plan.requests.some((request) => request.role === 'poison'), true);
  assert.equal(desyncPlan.data.plan.parserDifferential.kind, 'proxyforge-agent-repeater-desync-parser-differential-package');
  assert.equal(desyncPlan.data.plan.parserDifferential.highRiskCandidateCount >= 1, true);
  assert.match(JSON.stringify(desyncPlan.data.plan.parserDifferential), /cl0-backend|queued-followup|body-contains-http-request-line/);
  assertHasOperationalSecrets(desyncPlan);

  const racePlan = await runAgent(['repeater-race-run', '--project', projectPath, '--request-id', 'hx-agent-refund', '--count', '2', '--json']);
  assert.equal(racePlan.status, 'planned');
  assert.equal(racePlan.safety.trafficSent, false);
  assert.equal(racePlan.data.plan.requestCount, 2);
  assertHasOperationalSecrets(racePlan);

  const raceRun = await runAgent(['repeater-race-run', '--project', projectPath, '--request-id', 'hx-agent-refund', '--count', '2', '--timeout', '2000', '--execute', '--json']);
  assert.equal(raceRun.status, 'completed');
  assert.equal(raceRun.safety.trafficSent, true);
  assert.equal(raceRun.safety.requestCount, 2);
  assert.equal(raceRun.data.result.transport, 'parallel-last-byte');
  assert.match(raceRun.data.result.rawTranscript, /Authorization: Bearer agent-secret-token/);
  assertHasOperationalSecrets(raceRun);

  const refundRequestsBeforeRaceSoak = observed.refundRequests;
  const raceSoak = await runAgent([
    'repeater-race-run',
    '--project',
    projectPath,
    '--request-id',
    'hx-agent-refund',
    '--count',
    '12',
    '--sync',
    'single-packet',
    '--timeout',
    '2000',
    '--execute',
    '--soak',
    '--min-requests',
    '12',
    '--max-release-skew-ms',
    '100',
    '--max-race-window-ms',
    '100',
    '--json',
  ]);
  assert.equal(raceSoak.status, 'completed');
  assert.equal(raceSoak.safety.trafficSent, true);
  assert.equal(raceSoak.safety.requestCount, 12);
  assert(raceSoak.safety.gates.includes('high-concurrency-race-soak'));
  assert.equal(raceSoak.data.result.transport, 'parallel-single-packet');
  assert.equal(raceSoak.data.result.requestCount, 12);
  assert.equal(raceSoak.data.soakPackage.kind, 'proxyforge-agent-repeater-race-high-concurrency-soak-package');
  assert.equal(raceSoak.data.soakPackage.status, 'pass');
  assert.equal(raceSoak.data.soakPackage.observed.requestCount, 12);
  assert.equal(raceSoak.data.soakPackage.observed.observedResponses, 12);
  assert(raceSoak.artifacts.some((item) => item.kind === 'repeater-race-soak'));
  assert.equal(observed.refundRequests - refundRequestsBeforeRaceSoak, 12);
  assert.match(raceSoak.data.result.rawTranscript, /Authorization: Bearer agent-secret-token/);
  assertHasOperationalSecrets(raceSoak);

  const scannerPlan = await runAgent(['scanner-plan', '--project', projectPath, '--request-id', 'hx-agent-refund', '--check-pack', 'full-active', '--json']);
  assert.equal(scannerPlan.status, 'completed');
  assert.equal(scannerPlan.data.checkPackId, 'full-active');
  assert(scannerPlan.data.checks.includes('security-headers'));
  assert(scannerPlan.data.checks.includes('command-injection'));
  assert(scannerPlan.data.catalog.checkPacks.some((pack) => pack.id === 'input-attacks'));
  assert(scannerPlan.data.insertionPoints.some((point) => point.location === 'query' && point.name === 'orderId'));

  const scannerRun = await runAgent([
    'scanner-run',
    '--project',
    projectPath,
    '--request-id',
    'hx-agent-refund',
    '--scope',
    '127.0.0.1',
    '--check-pack',
    'full-active',
    '--max-requests',
    '13',
    '--throttle',
    '0',
    '--out',
    scannerDir,
    '--execute',
    '--soak',
    '--min-requests',
    '13',
    '--min-findings',
    '1',
    '--json',
  ]);
  assert.equal(scannerRun.status, 'completed');
  assert.equal(scannerRun.safety.trafficSent, true);
  assert(scannerRun.safety.requestCount >= 13);
  assert(scannerRun.safety.gates.includes('scanner-calibration-soak'));
  assert.equal(scannerRun.data.plan.checkPackId, 'full-active');
  assert(scannerRun.data.plan.checks.includes('reflected-xss'));
  assert.equal(scannerRun.data.calibrationPackage.kind, 'proxyforge-agent-scanner-live-calibration-soak-package');
  assert.equal(scannerRun.data.calibrationPackage.status, 'pass');
  assert(scannerRun.data.calibrationPackage.observed.totalRequests >= 13);
  assert(scannerRun.data.calibrationPackage.observed.findingCount >= 1);
  assert(scannerRun.data.calibrationPackage.observed.falsePositiveControls.includes('suppress-error-page-security-header-noise'));
  assert(scannerRun.data.calibrationPackage.observed.falsePositiveControls.includes('preserve-confidence-reason-per-finding'));
  assert.match(scannerRun.data.calibrationPackage.content, /scanner-live-calibration-soak/);
  assert.equal((await fs.stat(scannerRun.data.summary.summaryPath)).isFile(), true);
  assertHasOperationalSecrets(scannerRun);

  const scannerRetest = await runAgent([
    'scanner-retest',
    '--project',
    projectPath,
    '--issue',
    'issue-agent-1',
    '--request-id',
    'hx-agent-refund',
    '--retest-id',
    'hx-agent-refund',
    '--checks',
    'authz-diff,method-options',
    '--edit',
    'Authorization:customer-token->agent-secret-token',
    '--json',
  ]);
  assert.equal(scannerRetest.status, 'completed');
  assert.equal(scannerRetest.safety.redacted, false);
  assert.equal(scannerRetest.data.retestPackage.kind, 'proxyforge-scanner-retest-evidence-delta-package');
  assert.equal(scannerRetest.data.retestPackage.workflow.outcome, 'fixed');
  assert.equal(scannerRetest.data.retestPackage.requirements.issueLinked, true);
  assert.equal(scannerRetest.data.retestPackage.requirements.baselineExchangePreserved, true);
  assert.equal(scannerRetest.data.retestPackage.requirements.retestExchangePreserved, true);
  assert(scannerRetest.artifacts.some((item) => item.kind === 'scanner-retest-evidence-delta'));
  assert.match(scannerRetest.data.retestPackage.content, /Bearer agent-secret-token|session=agent-secret-session|agent-secret-key|reportPhaseOnlyRedaction/i);
  assertHasOperationalSecrets(scannerRetest);

  const scannerEvidenceExportPath = path.join(scannerDir, 'scanner-evidence-export.json');
  const scannerEvidenceExport = await runAgent([
    'scanner-evidence-export',
    '--project',
    projectPath,
    '--issue',
    'issue-agent-1',
    '--request-id',
    'hx-agent-refund',
    '--retest-id',
    'hx-agent-refund',
    '--out',
    scannerEvidenceExportPath,
    '--json',
  ]);
  assert.equal(scannerEvidenceExport.status, 'completed');
  assert.equal(scannerEvidenceExport.safety.redacted, false);
  assert.equal(scannerEvidenceExport.data.exportPackage.kind, 'proxyforge-agent-scanner-evidence-export');
  assert(scannerEvidenceExport.data.exportPackage.packages.some((item) => item.kind === 'proxyforge-scanner-retest-evidence-delta-package'));
  assert.equal((await fs.stat(scannerEvidenceExportPath)).isFile(), true);
  assert.match(JSON.stringify(scannerEvidenceExport.data.exportPackage), /Bearer agent-secret-token|agent-secret-key|redact-only-during-report-export/i);
  assertHasOperationalSecrets(scannerEvidenceExport);

  const scannerOastPromotionPath = path.join(scannerDir, 'scanner-oast-issue-promotion.json');
  const scannerOastPromotion = await runAgent([
    'scanner-oast-promote',
    '--project',
    projectPath,
    '--workspace',
    callbacksPath,
    '--request-id',
    'hx-agent-refund',
    '--payload-id',
    'cb-1',
    '--interaction-id',
    'int-1',
    '--out',
    scannerOastPromotionPath,
    '--json',
  ]);
  assert.equal(scannerOastPromotion.status, 'completed');
  assert.equal(scannerOastPromotion.safety.redacted, false);
  assert.equal(scannerOastPromotion.data.promotionPackage.kind, 'proxyforge-scanner-oast-issue-promotion-package');
  assert.equal(scannerOastPromotion.data.promotionPackage.requirements.callbackPayloadLinked, true);
  assert.equal(scannerOastPromotion.data.promotionPackage.requirements.callbackInteractionLinked, true);
  assert.equal(scannerOastPromotion.data.promotionPackage.requirements.oastTokenObserved, true);
  assert.equal(scannerOastPromotion.data.promotionPackage.requirements.reportPhaseOnlyRedaction, true);
  assert.equal((await fs.stat(scannerOastPromotionPath)).isFile(), true);
  assert.match(JSON.stringify(scannerOastPromotion.data.promotionPackage), /callback-secret-token|agent-secret-session|scanner-oast-promote|redact-only-during-report-export/i);
  assertHasOperationalSecrets(scannerOastPromotion);

  const anvilSourcePath = path.join(scannerDir, 'agent-compatibility.anvil');
  await fs.writeFile(anvilSourcePath, [
    'metadata:',
    '  language: v2-beta',
    '  name: "Agent Anvil compatibility operators"',
    '  description: "Exercises status, body regex, and missing-header compatibility evaluation."',
    '  tags: "proxyforge", "agent", "anvil", "compatibility"',
    '',
    'define:',
    '  role_marker = "support_admin"',
    '',
    'given response then',
    '  if {latest.response.status_code} == 200 then',
    '  if {latest.response.body} matches "${role_marker}" then',
    '  if not {latest.response.headers} contains "content-security-policy" then',
    '    report issue:',
    '      name: "Agent Anvil compatibility operator match"',
    '      severity: medium',
    '      confidence: firm',
  ].join('\n'), 'utf8');

  const anvilPlan = await runAgent([
    'anvil-plan',
    '--project',
    projectPath,
    '--request-id',
    'hx-agent-anvil',
    '--source-file',
    anvilSourcePath,
    '--json',
  ]);
  assert.equal(anvilPlan.status, 'completed');
  assert.equal(anvilPlan.data.plan.kind, 'proxyforge-agent-anvil-plan');
  assert.equal(anvilPlan.data.plan.positiveFixtureCount, 1);
  assert.equal(anvilPlan.data.plan.negativeFixtureCount, 1);
  assert.match(JSON.stringify(anvilPlan.data.fixtures), /Bearer agent-secret-token|session=agent-secret-session|agent-secret-key/);
  assertHasOperationalSecrets(anvilPlan);

  const anvilRun = await runAgent([
    'anvil-run',
    '--project',
    projectPath,
    '--request-id',
    'hx-agent-anvil',
    '--source-file',
    anvilSourcePath,
    '--execute',
    '--json',
  ]);
  assert.equal(anvilRun.status, 'completed');
  assert.equal(anvilRun.safety.trafficSent, false);
  assert(anvilRun.safety.gates.includes('custom-only-headless'));
  assert.equal(anvilRun.data.parityPackage.kind, 'proxyforge-anvil-custom-check-parity-package');
  assert.equal(anvilRun.data.parityPackage.requirements.plainTextDefinitionPreserved, true);
  assert.equal(anvilRun.data.parityPackage.requirements.positiveNegativeFixturesCovered, true);
  assert.equal(anvilRun.data.parityPackage.requirements.fixtureValidationPassed, true);
  assert.equal(anvilRun.data.parityPackage.requirements.headlessCustomOnlyCovered, true);
  assert.equal(anvilRun.data.parityPackage.requirements.signedPackageReviewCovered, true);
  assert.equal(anvilRun.data.parityPackage.requirements.scannerIssueHandoffCovered, true);
  assert.equal(anvilRun.data.parityPackage.requirements.operationalSecretsPreserved, true);
  assert.match(JSON.stringify(anvilRun.data.validationRun), /compatibility|status_code|matches|not contains/i);
  assert(anvilRun.data.headlessRun.issueIds.some((issueId) => issueId.includes('hx-agent-anvil')));
  assert.match(anvilRun.data.headlessRun.content, /matchedExchangeIds[\s\S]*hx-agent-anvil/i);
  assert.match(anvilRun.data.parityPackage.content, /support_admin|Bearer agent-secret-token|agent-secret-key|reportPhaseOnlyRedaction|compatibility/i);
  assertHasOperationalSecrets(anvilRun);

  const anvilExportPath = path.join(scannerDir, 'anvil-package-export.json');
  const anvilExport = await runAgent([
    'anvil-package-export',
    '--project',
    projectPath,
    '--request-id',
    'hx-agent-anvil',
    '--source-file',
    anvilSourcePath,
    '--out',
    anvilExportPath,
    '--json',
  ]);
  assert.equal(anvilExport.status, 'completed');
  assert.equal(anvilExport.data.exportPackage.kind, 'proxyforge-agent-anvil-package-export');
  assert.equal(anvilExport.data.exportPackage.parityPackage.kind, 'proxyforge-anvil-custom-check-parity-package');
  assert.equal((await fs.stat(anvilExportPath)).isFile(), true);
  assert.match(JSON.stringify(anvilExport.data.exportPackage), /Bearer agent-secret-token|agent-secret-key|redact-only-during-report-export/i);
  assertHasOperationalSecrets(anvilExport);

  const extensionFixtures = await runAgent(['extension-fixtures', '--project', projectPath, '--manifest', extensionManifestPath, '--request-id', 'hx-agent-refund', '--json']);
  assert.equal(extensionFixtures.status, 'completed');
  assert.equal(extensionFixtures.data.kind, 'proxyforge-agent-extension-compatibility-fixture-package');
  assert.equal(extensionFixtures.data.fixtureCount, 5);
  assert(extensionFixtures.data.fixtures.some((fixture) => fixture.legacyExtensionApi === 'IHttpListener' && fixture.hook === 'request-editor' && fixture.status === 'pass'));
  assert(extensionFixtures.data.fixtures.some((fixture) => fixture.legacyExtensionApi === 'IScannerCheck' && fixture.hook === 'scanner-check' && fixture.status === 'pass'));
  assert(extensionFixtures.data.fixtures.some((fixture) => fixture.legacyExtensionApi === 'IMessageEditorTab' && fixture.hook === 'message-editor' && fixture.status === 'pass'));
  assert(extensionFixtures.data.policyDeniedOperations.includes('ILegacyExtensionCallbacks.makeHttpRequest'));
  assert.equal(extensionFixtures.data.thirdPartyRequirements.helpersTransformCovered, true);
  assert.equal(extensionFixtures.data.thirdPartyRequirements.contextMenuMultiSelectionCovered, true);
  assert.equal(extensionFixtures.data.thirdPartyRequirements.sessionHandlingTokenRefreshCovered, true);
  assert.equal(extensionFixtures.data.thirdPartyRequirements.insertionPointProviderCovered, true);
  assert.equal(extensionFixtures.data.thirdPartyRequirements.unsupportedApisFailClosedCovered, true);
  assert(extensionFixtures.data.thirdPartySdkEdges.some((edge) => edge.category === 'package-refresh'));
  assert.match(extensionFixtures.data.content, /agent-secret-token|IHttpListener|IScannerCheck|policy-denied|context-menu-multi-selection|session-handling-token-refresh|package-refresh/);
  assertHasOperationalSecrets(extensionFixtures);

  const callbacks = await runAgent(['callback-poll', '--workspace', callbacksPath, '--json']);
  assert.equal(callbacks.data.payloadCount, 2);
  assert.equal(callbacks.data.interactionCount, 2);
  assert.match(JSON.stringify(callbacks), /callback-secret-token/);

  const providerProbePath = path.join(tempDir, 'callback-provider-host-proof.json');
  const providerProbe = await runAgent([
    'callback-provider-probe',
    '--providers',
    providerManifestPath,
    '--scope',
    '127.0.0.1',
    '--execute',
    '--out',
    providerProbePath,
    '--json',
  ]);
  assert.equal(providerProbe.status, 'completed');
  assert.equal(providerProbe.safety.trafficSent, true);
  assert.equal(providerProbe.data.package.kind, 'proxyforge-agent-callback-provider-host-proof-package');
  assert.equal(providerProbe.data.package.providerCount, 2);
  assert.equal(providerProbe.data.package.protocolCount, 2);
  assert.equal(providerProbe.data.package.interactionCount, 2);
  assert.equal(providerProbe.data.package.reportReady, true);
  assert.equal(providerProbe.data.package.requirements.signedPollsCovered, true);
  assert.equal(providerProbe.data.package.requirements.tenantIsolationCovered, true);
  assert(providerProbe.data.package.providerProbes.every((probe) => probe.isolationStatus === 'isolated'));
  assert(providerProbe.artifacts.some((item) => item.kind === 'callback-provider-host-proof'));
  assert.match(JSON.stringify(providerProbe), /agent-http-provider-secret-token|agent-dns-provider-secret-token|agent-provider-signing-secret|redact-only-during-report-export/);
  assert.match(await fs.readFile(providerProbePath, 'utf8'), /agent-http-provider-token|agent-dns-provider-token|rawRequest|rawResponse/);

  const relayPlan = await runAgent([
    'callback-relay-plan',
    '--workspace',
    callbacksPath,
    '--public-base',
    'callbacks.agent.test',
    '--signing-secret',
    'agent-callback-signing-secret',
    '--relay-token',
    'agent-relay-token',
    '--json',
  ]);
  assert.equal(relayPlan.status, 'planned');
  assert.equal(relayPlan.data.publicBaseUrl, 'callbacks.agent.test');
  assert(relayPlan.data.dnsRecords.some((record) => record.includes('callbacks.agent.test')));
  assert.match(JSON.stringify(relayPlan), /agent-callback-signing-secret|agent-relay-token|callbacks\.agent\.test/);

  const relaySoak = await runAgent([
    'callback-relay-soak',
    '--workspace',
    callbacksPath,
    '--public-base',
    'callbacks.agent.test',
    '--signing-secret',
    'agent-callback-signing-secret',
    '--relay-token',
    'agent-relay-token',
    '--min-payloads',
    '2',
    '--min-interactions',
    '2',
    '--min-protocols',
    '3',
    '--json',
  ]);
  assert.equal(relaySoak.status, 'completed');
  assert.equal(relaySoak.data.kind, 'proxyforge-agent-callback-public-relay-soak-package');
  assert.equal(relaySoak.data.status, 'pass');
  assert.equal(relaySoak.data.reportReady, true);
  assert.equal(relaySoak.data.reportImportProbe.expectedManifestArtifactCount, 4);
  assert(relaySoak.artifacts.some((item) => item.kind === 'callback-relay-soak'));
  assert.match(JSON.stringify(relaySoak), /callback-secret-token|old-callback-secret-token|agent-callback-signing-secret|agent-relay-token|proxyforge-agent-callback-report-import-probe/);

  const prunePlan = await runAgent([
    'callback-retention-prune',
    '--workspace',
    callbacksPath,
    '--retention-hours',
    '1',
    '--now',
    '2026-05-24T22:20:00.000Z',
    '--json',
  ]);
  assert.equal(prunePlan.status, 'completed');
  assert.equal(prunePlan.mode, 'planned');
  assert(prunePlan.data.expiredInteractionIds.includes('int-old'));
  assert(prunePlan.data.retainedInteractionIds.includes('int-1'));
  assert(prunePlan.data.expiredPayloadIds.includes('cb-old'));
  assert.match(JSON.stringify(prunePlan), /old-callback-secret-token/);

  const exploitPreview = await runAgent(['exploit-preview', '--project', projectPath, '--request-id', 'hx-agent-refund', '--template', 'callback-ssrf', '--json']);
  assert.equal(exploitPreview.status, 'completed');
  assert.equal(exploitPreview.data.preview.destructiveClassExcluded, true);
  assertHasOperationalSecrets(exploitPreview);

  const exploitRun = await runAgent(['exploit-run', '--project', projectPath, '--request-id', 'hx-agent-refund', '--template', 'callback-ssrf', '--approve', approvalPath, '--execute', '--json']);
  assert.equal(exploitRun.status, 'queued');
  assert.equal(exploitRun.safety.trafficSent, false);
  assert(exploitRun.safety.gates.includes('approval-file'));
  assertHasOperationalSecrets(exploitRun);

  const report = await runAgent(['report-export', '--project', projectPath, '--format', 'json', '--out', reportsDir, '--json']);
  assert.equal(report.status, 'completed');
  assert.equal((await fs.stat(report.data.report.path)).isFile(), true);
  assert.equal(report.safety.redacted, true);
  assertNoSecrets(report);
  assertNoSecrets(await fs.readFile(report.data.report.path, 'utf8'));

  const vantix = await runAgent(['vantix-sync', '--project', projectPath, '--out', vantixDir, '--json']);
  assert.equal(vantix.status, 'completed');
  assert.equal((await fs.stat(vantix.data.filePath)).isFile(), true);
  assert.equal(vantix.data.payload.agentRuntime.appRoot, process.cwd());
  assert.match(vantix.data.payload.recommendedCommands[0], /proxyforge-agent\.mjs status/);
  assertHasOperationalSecrets(vantix);
  assertHasOperationalSecrets(await fs.readFile(vantix.data.filePath, 'utf8'));

  console.log('agent-cli: exercised status, external-cwd agent runtime, search/index/live-provider/view, Sequencer analysis/soak, WebSocket list/replay/fuzz/transcript export, proxy import, Project Store status/recover/backup, crawl/content discovery run, live target profiling, target access review/comparison, Automations list/run/CI/scheduler/parity/service lifecycle, persistent MITM logging, Chromium plan, replay/bulk replay/intruder/desync/race execution, scanner plan/run/retest/evidence export/OAST promotion, Anvil plan/run/package export, extension fixtures, callback provider host proof/relay/soak/retention controls, exploit approval, reports, and Vantix handoff');
} finally {
  if (wsServer) await close(wsServer);
  await close(server);
  await fs.rm(tempDir, { recursive: true, force: true });
}

async function runAgent(args) {
  const result = await runCli([path.join(process.cwd(), 'scripts', 'proxyforge-agent.mjs'), ...args]);
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

async function runAgentExpectStatus(args, expectedStatus) {
  const result = await runCli([path.join(process.cwd(), 'scripts', 'proxyforge-agent.mjs'), ...args]);
  assert.equal(result.status, expectedStatus, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

async function runAgentFromCwd(args, cwd) {
  const result = await runCli([path.join(process.cwd(), 'scripts', 'proxyforge-agent.mjs'), ...args], { cwd });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return JSON.parse(result.stdout);
}

function assertHasOperationalSecrets(value) {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  assert.match(serialized, /agent-secret-token/);
  assert.match(serialized, /agent-secret-session/);
  assert.match(serialized, /agent-secret-key/);
}

function assertNoSecrets(value) {
  const serialized = typeof value === 'string' ? value : JSON.stringify(value);
  assert.doesNotMatch(serialized, /agent-secret-token/);
  assert.doesNotMatch(serialized, /agent-secret-session/);
  assert.doesNotMatch(serialized, /agent-secret-key/);
  assert.doesNotMatch(serialized, /callback-secret-token/);
}

async function assertPrivatePathMode(filePath, expectedMode, label) {
  if (process.platform === 'win32') return;
  const mode = (await fs.stat(filePath)).mode & 0o777;
  assert.equal(mode, expectedMode, `${label} should be ${expectedMode.toString(8)}, got ${mode.toString(8)}`);
}

async function readAgentBody(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
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

function createWebSocketEchoServer() {
  return net.createServer((socket) => {
    let handshakeComplete = false;
    let buffer = Buffer.alloc(0);
    socket.on('data', (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (!handshakeComplete) {
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) return;
        const header = buffer.slice(0, headerEnd).toString('utf8');
        const key = header.match(/^Sec-WebSocket-Key:\s*(.+)$/im)?.[1]?.trim() ?? '';
        socket.write(renderWebSocketAccept(key));
        buffer = buffer.slice(headerEnd + 4);
        handshakeComplete = true;
      }
      const drained = drainMaskedWebSocketFrames(buffer);
      buffer = drained.remaining;
      for (const frame of drained.frames) {
        const payload = frame.payload.toString('utf8');
        socket.write(encodeServerWebSocketFrame(Buffer.from(`agent-ws-ack ${payload}`, 'utf8'), 1));
      }
    });
  });
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

function drainMaskedWebSocketFrames(buffer) {
  const frames = [];
  let offset = 0;
  while (buffer.length - offset >= 2) {
    const first = buffer[offset];
    const second = buffer[offset + 1];
    const opcode = first & 0x0f;
    const masked = Boolean(second & 0x80);
    let length = second & 0x7f;
    let headerLength = 2;
    if (length === 126) {
      if (buffer.length - offset < 4) break;
      length = buffer.readUInt16BE(offset + 2);
      headerLength = 4;
    } else if (length === 127) {
      if (buffer.length - offset < 10) break;
      length = Number(buffer.readBigUInt64BE(offset + 2));
      headerLength = 10;
    }
    const maskOffset = offset + headerLength;
    const payloadOffset = maskOffset + (masked ? 4 : 0);
    if (buffer.length < payloadOffset + length) break;
    const payload = Buffer.from(buffer.slice(payloadOffset, payloadOffset + length));
    if (masked) {
      const mask = buffer.slice(maskOffset, maskOffset + 4);
      for (let index = 0; index < payload.length; index += 1) payload[index] ^= mask[index % 4];
    }
    frames.push({ opcode, payload });
    offset = payloadOffset + length;
  }
  return { frames, remaining: buffer.slice(offset) };
}

function encodeServerWebSocketFrame(payload, opcode = 1) {
  const length = payload.length;
  const headerLength = length < 126 ? 2 : length <= 0xffff ? 4 : 10;
  const frame = Buffer.alloc(headerLength + length);
  frame[0] = 0x80 | (opcode & 0x0f);
  if (length < 126) {
    frame[1] = length;
  } else if (length <= 0xffff) {
    frame[1] = 126;
    frame.writeUInt16BE(length, 2);
  } else {
    frame[1] = 127;
    frame.writeBigUInt64BE(BigInt(length), 2);
  }
  payload.copy(frame, headerLength);
  return frame;
}

function runCli(args, options = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, {
      ...options,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', (error) => {
      resolve({ status: 1, stdout, stderr: `${stderr}${error.message}` });
    });
    child.on('close', (status) => {
      resolve({ status: status ?? 1, stdout, stderr });
    });
  });
}

function startMitmSession(args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [path.join(process.cwd(), 'scripts', 'proxyforge-agent.mjs'), ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stdout = '';
    let stderr = '';
    let settled = false;
    const done = new Promise((doneResolve) => {
      child.on('close', (status) => doneResolve({ status, stdout, stderr }));
    });
    child.stdout.on('data', (chunk) => {
      stdout += chunk.toString('utf8');
      if (settled || !stdout.includes('\n')) return;
      settled = true;
      try {
        resolve({ child, ready: JSON.parse(stdout.slice(0, stdout.indexOf('\n'))), done });
      } catch (error) {
        reject(error);
      }
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', reject);
    setTimeout(() => {
      if (!settled) {
        child.kill('SIGTERM');
        reject(new Error(`MITM session did not become ready. stderr=${stderr}`));
      }
    }, 10000);
  });
}

async function proxyHttpRequest(proxyPort, targetUrl) {
  await new Promise((resolve, reject) => {
    const request = http.request({
      host: '127.0.0.1',
      port: proxyPort,
      method: 'GET',
      path: targetUrl,
      headers: {
        Host: new URL(targetUrl).host,
        Authorization: 'Bearer agent-secret-token',
        Cookie: 'session=agent-secret-session',
        'X-API-Key': 'agent-secret-key',
      },
    }, (response) => {
      response.resume();
      response.on('end', resolve);
    });
    request.on('error', reject);
    request.end();
  });
}

async function waitFor(check, timeoutMs = 5000) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    const value = await check();
    if (value) return value;
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
  throw new Error('Timed out waiting for condition');
}

async function reservePort() {
  const reserved = http.createServer();
  const port = await listen(reserved);
  await close(reserved);
  return port;
}
