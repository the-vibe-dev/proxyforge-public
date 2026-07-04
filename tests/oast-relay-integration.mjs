import { strict as assert } from 'node:assert';
import { createHmac } from 'node:crypto';
import fs from 'node:fs/promises';
import { createServer, request as httpRequest } from 'node:http';
import { createRequire } from 'node:module';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildCallbackListenerProfile',
  'buildCallbackExternalRelayIntegrationPackage',
];

const enginePath = path.resolve('src/callbackEngine.ts');
const callbackEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof callbackEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `oast-relay-integration: missing export(s): ${missingExports.join(', ')}`);

const now = '2026-05-26T08:15:00.000Z';
const relaySigningSecret = 'relay-signing-secret-full-fidelity';
const tenantSecrets = {
  north: {
    relayToken: 'north-relay-token-full-fidelity',
    executorToken: 'north-executor-raw-token',
  },
  south: {
    relayToken: 'south-relay-token-full-fidelity',
    executorToken: 'south-executor-raw-token',
  },
};
const records = {
  north: [],
  south: [],
};

const server = createServer(async (req, res) => {
  const base = `http://${req.headers.host ?? '127.0.0.1'}`;
  const url = new URL(req.url ?? '/', base);
  const body = await readBody(req);

  if (url.pathname.startsWith('/ingest/')) {
    const [, , tenantId, payloadId] = url.pathname.split('/');
    const protocol = url.searchParams.get('protocol') ?? 'http';
    if (!isKnownTenant(tenantId) || !['dns', 'http', 'smtp'].includes(protocol) || !payloadId) {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    const raw = formatRawRequest(req, body);
    records[tenantId].push({
      id: `relay-${tenantId}-${records[tenantId].length + 1}-${protocol}`,
      payloadId,
      protocol,
      observedAt: now,
      sourceIp: '127.0.0.1',
      sourceHost: req.headers.host ?? '127.0.0.1',
      requestLine: `${req.method ?? 'GET'} ${url.pathname}${url.search} HTTP/${req.httpVersion}`,
      userAgent: String(req.headers['user-agent'] ?? 'ProxyForgeRelayFixture/1.0'),
      raw,
      severity: protocol === 'dns' ? 'medium' : 'high',
      tags: ['oast', 'external-relay', tenantId],
    });
    res.writeHead(204, { 'X-ProxyForge-Relay': tenantId });
    res.end();
    return;
  }

  if (url.pathname === '/api/poll') {
    const tenantId = url.searchParams.get('tenant') ?? '';
    if (!isKnownTenant(tenantId)) {
      res.writeHead(404);
      res.end('unknown tenant');
      return;
    }
    const authorization = String(req.headers.authorization ?? '');
    if (authorization !== `Bearer ${tenantSecrets[tenantId].relayToken}`) {
      res.writeHead(403);
      res.end('forbidden');
      return;
    }
    const tenantPayloads = payloads.filter((payload) => payload.tenantId === tenantId);
    const payloadTokens = tenantPayloads.map((payload) => payload.token);
    const responseBody = JSON.stringify({
      kind: 'proxyforge-relay-signed-poll-response',
      tenantId,
      interactions: records[tenantId],
      payloadTokens,
      operationalSecrets: {
        relayAuthorization: authorization,
        relaySigningSecret,
        executorToken: tenantSecrets[tenantId].executorToken,
      },
      reportRedactionBoundary: 'redact-only-during-report-export',
    });
    const signature = createHmac('sha256', relaySigningSecret).update(responseBody).digest('hex');
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-ProxyForge-Signature-Key-Id': 'relay-key-live',
      'X-ProxyForge-Signature': signature,
    });
    res.end(responseBody);
    return;
  }

  res.writeHead(404);
  res.end('not found');
});

await listen(server);
const address = server.address();
const port = typeof address === 'object' && address ? address.port : 0;
const relayBaseUrl = `http://127.0.0.1:${port}`;

const payloads = [
  buildPayload('cb-relay-north-http', 'north', 'north-relay-secret-token', 'http', `${relayBaseUrl}/ingest/north/cb-relay-north-http?protocol=http`),
  buildPayload('cb-relay-north-dns', 'north', 'north-dns-secret-token', 'dns', `${relayBaseUrl}/ingest/north/cb-relay-north-dns?protocol=dns`),
  buildPayload('cb-relay-south-smtp', 'south', 'south-smtp-secret-token', 'smtp', `${relayBaseUrl}/ingest/south/cb-relay-south-smtp?protocol=smtp`),
  buildPayload('cb-relay-south-http', 'south', 'south-http-secret-token', 'http', `${relayBaseUrl}/ingest/south/cb-relay-south-http?protocol=http`),
];

const profile = callbackEngine.buildCallbackListenerProfile({
  mode: 'hybrid-local',
  host: '127.0.0.1',
  publicBaseUrl: 'callbacks.external.test',
  httpPort: port,
  dnsPort: 15353,
  smtpPort: 12525,
  pollIntervalSeconds: 15,
  retentionHours: 72,
  signingKeyId: 'relay-key-live',
  now,
});

try {
  await ingest('north', 'cb-relay-north-http', 'http', 'GET', 'north callback body north-relay-secret-token');
  await ingest('north', 'cb-relay-north-dns', 'dns', 'POST', 'north dns body north-dns-secret-token');
  await ingest('south', 'cb-relay-south-smtp', 'smtp', 'POST', 'south smtp body south-smtp-secret-token');
  await ingest('south', 'cb-relay-south-http', 'http', 'GET', 'south http body south-http-secret-token');

  const northPoll = await pollTenant('north');
  const southPoll = await pollTenant('south');
  const northBody = JSON.parse(northPoll.body);
  const southBody = JSON.parse(southPoll.body);

  assert.doesNotMatch(northPoll.body, /south-smtp-secret-token|south-http-secret-token/, 'north poll must not contain south payload tokens');
  assert.doesNotMatch(southPoll.body, /north-relay-secret-token|north-dns-secret-token/, 'south poll must not contain north payload tokens');

  const integration = callbackEngine.buildCallbackExternalRelayIntegrationPackage({
    profile,
    relayBaseUrl,
    publicBaseUrl: 'callbacks.external.test',
    payloads,
    tenantPolls: [
      buildTenantPoll('north', northPoll, northBody.interactions),
      buildTenantPoll('south', southPoll, southBody.interactions),
    ],
    minTenantCount: 2,
    minInteractionCount: 4,
    minProtocolCount: 3,
    now,
  });

  assert.equal(integration.kind, 'proxyforge-callback-external-relay-integration-package');
  assert.equal(integration.status, 'pass');
  assert.equal(integration.reportReady, true);
  assert.equal(integration.tenantCount, 2);
  assert.equal(integration.interactionCount, 4);
  assert.equal(integration.observedProtocolCount, 3);
  assert.equal(integration.leakedInteractionIds.length, 0);
  assert.ok(integration.tenantPolls.every((poll) => poll.isolationStatus === 'isolated'));
  assert.ok(integration.tenantPolls.every((poll) => poll.signature.status === 'signed'));
  assert.match(integration.content, /north-relay-token-full-fidelity|south-relay-token-full-fidelity/);
  assert.match(integration.content, /north-executor-raw-token|south-executor-raw-token|relay-signing-secret-full-fidelity/);
  assert.match(integration.content, /north-relay-secret-token|south-smtp-secret-token|redact-only-during-report-export/);

  const leakingIntegration = callbackEngine.buildCallbackExternalRelayIntegrationPackage({
    profile,
    relayBaseUrl,
    publicBaseUrl: 'callbacks.external.test',
    payloads,
    tenantPolls: [
      buildTenantPoll('north', {
        ...northPoll,
        body: JSON.stringify({
          ...northBody,
          interactions: [...northBody.interactions, southBody.interactions[0]],
          payloadTokens: [...northBody.payloadTokens, 'south-smtp-secret-token'],
        }),
        rawResponse: [
          'HTTP/1.1 200 OK',
          'Content-Type: application/json',
          'X-ProxyForge-Signature-Key-Id: relay-key-live',
          'X-ProxyForge-Signature: leaked-signature',
          '',
          JSON.stringify({
            ...northBody,
            interactions: [...northBody.interactions, southBody.interactions[0]],
            payloadTokens: [...northBody.payloadTokens, 'south-smtp-secret-token'],
          }),
        ].join('\r\n'),
      }, [...northBody.interactions, southBody.interactions[0]]),
      buildTenantPoll('south', southPoll, southBody.interactions),
    ],
    minTenantCount: 2,
    minInteractionCount: 4,
    minProtocolCount: 3,
    now,
  });

  assert.equal(leakingIntegration.status, 'fail');
  assert.equal(leakingIntegration.reportReady, false);
  assert.ok(leakingIntegration.leakedInteractionIds.includes(southBody.interactions[0].id));
  assert.ok(leakingIntegration.tenantPolls.some((poll) => poll.isolationStatus === 'leaked'));
  assert.match(leakingIntegration.content, /tenant poll leaked payload token/);

  const artifactDir = path.resolve('.gitignored/test-artifacts/oast-relay-integration');
  await fs.mkdir(artifactDir, { recursive: true });
  await fs.writeFile(
    path.join(artifactDir, 'external-relay-integration-package.json'),
    `${integration.content}\n`,
  );

  console.log('oast-relay-integration: verified signed external relay polling, tenant isolation, and report-phase-only redaction boundary');
} finally {
  await closeServer(server);
}

async function ingest(tenantId, payloadId, protocol, method, body) {
  return requestRaw(`${relayBaseUrl}/ingest/${tenantId}/${payloadId}?protocol=${protocol}`, {
    method,
    headers: {
      Authorization: `Bearer ${tenantSecrets[tenantId].executorToken}`,
      'Content-Type': 'text/plain',
      'User-Agent': 'ProxyForgeRelayFixture/1.0',
      'X-ProxyForge-Callback-Token': payloads.find((payload) => payload.id === payloadId)?.token ?? '',
    },
    body,
  });
}

async function pollTenant(tenantId) {
  return requestRaw(`${relayBaseUrl}/api/poll?tenant=${tenantId}`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${tenantSecrets[tenantId].relayToken}`,
      Accept: 'application/json',
      'User-Agent': 'ProxyForgeRelayPoller/1.0',
    },
  });
}

function buildTenantPoll(tenantId, pollResult, interactions) {
  return {
    tenantId,
    relayBaseUrl,
    publicBaseUrl: 'callbacks.external.test',
    payloadIds: payloads.filter((payload) => payload.tenantId === tenantId).map((payload) => payload.id),
    interactions,
    statusCode: pollResult.statusCode,
    rawRequest: pollResult.rawRequest,
    rawResponse: pollResult.rawResponse,
    signature: {
      algorithm: 'HMAC-SHA256',
      keyId: headerValue(pollResult.headers, 'x-proxyforge-signature-key-id') || 'relay-key-live',
      status: headerValue(pollResult.headers, 'x-proxyforge-signature') ? 'signed' : 'missing',
      digestPreview: headerValue(pollResult.headers, 'x-proxyforge-signature').slice(0, 16),
    },
  };
}

function buildPayload(id, tenantId, token, protocol, endpoint) {
  return {
    id,
    tenantId,
    token,
    label: `${tenantId} ${protocol} relay payload`,
    protocol,
    endpoint,
    createdAt: now,
    status: 'waiting',
    sourceExchangeId: `exchange-${tenantId}`,
    sourceHost: `${tenantId}.app.local`,
    sourcePath: `/callback/${protocol}`,
    notes: `Tenant ${tenantId} ${protocol} relay payload keeps callback token material until report export.`,
  };
}

function requestRaw(urlText, options) {
  const url = new URL(urlText);
  const method = options.method ?? 'GET';
  const body = options.body ?? '';
  const headers = {
    Host: url.host,
    ...(options.headers ?? {}),
  };
  if (body && !Object.keys(headers).some((name) => name.toLowerCase() === 'content-length')) {
    headers['Content-Length'] = Buffer.byteLength(body);
  }
  const rawRequest = [
    `${method} ${url.pathname}${url.search} HTTP/1.1`,
    ...Object.entries(headers).map(([name, value]) => `${name}: ${value}`),
    '',
    body,
  ].join('\r\n');

  return new Promise((resolve, reject) => {
    const req = httpRequest({
      hostname: url.hostname,
      port: url.port,
      path: `${url.pathname}${url.search}`,
      method,
      headers,
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        const responseBody = Buffer.concat(chunks).toString('utf8');
        const rawResponse = [
          `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage}`,
          ...Object.entries(res.headers).map(([name, value]) => `${name}: ${Array.isArray(value) ? value.join(', ') : value ?? ''}`),
          '',
          responseBody,
        ].join('\r\n');
        resolve({
          statusCode: res.statusCode ?? 0,
          headers: res.headers,
          body: responseBody,
          rawRequest,
          rawResponse,
        });
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function formatRawRequest(req, body) {
  return [
    `${req.method ?? 'GET'} ${req.url ?? '/'} HTTP/${req.httpVersion}`,
    ...Object.entries(req.headers).map(([name, value]) => `${name}: ${Array.isArray(value) ? value.join(', ') : value ?? ''}`),
    '',
    body,
  ].join('\r\n');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (chunk) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function headerValue(headers, name) {
  const value = headers[name];
  if (Array.isArray(value)) return value.join(', ');
  return value ?? '';
}

function isKnownTenant(value) {
  return value === 'north' || value === 'south';
}

function listen(activeServer) {
  return new Promise((resolve, reject) => {
    activeServer.once('error', reject);
    activeServer.listen(0, '127.0.0.1', resolve);
  });
}

function closeServer(activeServer) {
  return new Promise((resolve, reject) => {
    activeServer.close((error) => (error ? reject(error) : resolve()));
  });
}

async function loadEngine(filePath) {
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
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    Buffer,
    console,
    require,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: filePath });
  return module.exports;
}

function normalizeModuleExports(moduleExports) {
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}
