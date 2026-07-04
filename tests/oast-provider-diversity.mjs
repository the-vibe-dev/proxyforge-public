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
  'buildCallbackExternalOastProviderDiversityPackage',
];

const enginePath = path.resolve('src/callbackEngine.ts');
const callbackEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof callbackEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `oast-provider-diversity: missing export(s): ${missingExports.join(', ')}`);

const now = '2026-05-26T09:40:00.000Z';
const signingSecret = 'provider-diversity-signing-secret';
const providerSecrets = {
  'generic-http': 'generic-http-provider-token',
  'dns-webhook': 'dns-webhook-provider-token',
  'smtp-relay': 'smtp-relay-provider-token',
};
const providerKinds = {
  'generic-http': 'generic-http-relay',
  'dns-webhook': 'dns-webhook-relay',
  'smtp-relay': 'smtp-relay',
};
const records = new Map();

const server = createServer(async (req, res) => {
  const base = `http://${req.headers.host ?? '127.0.0.1'}`;
  const url = new URL(req.url ?? '/', base);
  const body = await readBody(req);
  const parts = url.pathname.split('/').filter(Boolean);

  if (parts[0] === 'provider' && parts[3] === 'ingest') {
    const [, providerId, tenantId, , payloadId] = parts;
    const protocol = url.searchParams.get('protocol') ?? 'http';
    if (!isProvider(providerId) || !isTenant(tenantId) || !payloadId || !['dns', 'http', 'smtp'].includes(protocol)) {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    const raw = formatRawRequest(req, body);
    const key = recordKey(providerId, tenantId);
    const providerRecords = records.get(key) ?? [];
    providerRecords.push({
      id: `${providerId}-${tenantId}-${providerRecords.length + 1}-${protocol}`,
      payloadId,
      protocol,
      observedAt: now,
      sourceIp: '127.0.0.1',
      sourceHost: req.headers.host ?? '127.0.0.1',
      requestLine: `${req.method ?? 'GET'} ${url.pathname}${url.search} HTTP/${req.httpVersion}`,
      userAgent: String(req.headers['user-agent'] ?? 'ProxyForgeProviderFixture/1.0'),
      raw,
      severity: protocol === 'dns' ? 'medium' : 'high',
      tags: ['oast', 'provider-diversity', providerId, tenantId],
    });
    records.set(key, providerRecords);
    res.writeHead(202, { 'X-ProxyForge-OAST-Provider': providerId });
    res.end(JSON.stringify({ accepted: true, providerId, tenantId, payloadId, protocol }));
    return;
  }

  if (parts[0] === 'provider' && parts[3] === 'poll') {
    const [, providerId, tenantId] = parts;
    if (!isProvider(providerId) || !isTenant(tenantId)) {
      res.writeHead(404);
      res.end('not found');
      return;
    }
    const authorization = String(req.headers.authorization ?? '');
    if (authorization !== `Bearer ${providerSecrets[providerId]}`) {
      res.writeHead(403);
      res.end('forbidden');
      return;
    }
    const providerPayloads = payloads.filter((payload) => payload.providerId === providerId && payload.tenantId === tenantId);
    const bodyText = JSON.stringify({
      kind: 'proxyforge-provider-signed-poll-response',
      providerId,
      providerKind: providerKinds[providerId],
      tenantId,
      interactions: records.get(recordKey(providerId, tenantId)) ?? [],
      payloadTokens: providerPayloads.map((payload) => payload.token),
      operationalSecrets: {
        providerAuthorization: authorization,
        signingSecret,
      },
      reportRedactionBoundary: 'redact-only-during-report-export',
    });
    const signature = createHmac('sha256', signingSecret).update(bodyText).digest('hex');
    res.writeHead(200, {
      'Content-Type': 'application/json',
      'X-ProxyForge-Signature-Key-Id': `${providerId}-key`,
      'X-ProxyForge-Signature': signature,
    });
    res.end(bodyText);
    return;
  }

  res.writeHead(404);
  res.end('not found');
});

await listen(server);
const address = server.address();
const port = typeof address === 'object' && address ? address.port : 0;
const baseUrl = `http://127.0.0.1:${port}`;

const payloads = [
  buildPayload('cb-provider-http-alpha', 'alpha', 'generic-http', 'http', 'alpha-generic-http-secret-token'),
  buildPayload('cb-provider-dns-alpha', 'alpha', 'dns-webhook', 'dns', 'alpha-dns-webhook-secret-token'),
  buildPayload('cb-provider-smtp-beta', 'beta', 'smtp-relay', 'smtp', 'beta-smtp-relay-secret-token'),
  buildPayload('cb-provider-http-beta', 'beta', 'generic-http', 'http', 'beta-generic-http-secret-token'),
];

const profile = callbackEngine.buildCallbackListenerProfile({
  mode: 'hybrid-local',
  host: '127.0.0.1',
  publicBaseUrl: 'providers.external.test',
  httpPort: port,
  dnsPort: 15353,
  smtpPort: 12525,
  pollIntervalSeconds: 15,
  retentionHours: 72,
  signingKeyId: 'provider-diversity-key',
  now,
});

try {
  await ingest('generic-http', 'alpha', 'cb-provider-http-alpha', 'http');
  await ingest('dns-webhook', 'alpha', 'cb-provider-dns-alpha', 'dns');
  await ingest('smtp-relay', 'beta', 'cb-provider-smtp-beta', 'smtp');
  await ingest('generic-http', 'beta', 'cb-provider-http-beta', 'http');

  const genericAlpha = await pollProvider('generic-http', 'alpha');
  const genericBeta = await pollProvider('generic-http', 'beta');
  const dnsAlpha = await pollProvider('dns-webhook', 'alpha');
  const smtpBeta = await pollProvider('smtp-relay', 'beta');
  const genericAlphaBody = JSON.parse(genericAlpha.body);
  const genericBetaBody = JSON.parse(genericBeta.body);
  const dnsAlphaBody = JSON.parse(dnsAlpha.body);
  const smtpBetaBody = JSON.parse(smtpBeta.body);

  assert.doesNotMatch(genericAlpha.body, /beta-generic-http-secret-token|beta-smtp-relay-secret-token/, 'alpha provider poll must not include beta payload tokens');
  assert.doesNotMatch(smtpBeta.body, /alpha-generic-http-secret-token|alpha-dns-webhook-secret-token/, 'beta provider poll must not include alpha payload tokens');

  const relayIntegration = callbackEngine.buildCallbackExternalRelayIntegrationPackage({
    profile,
    relayBaseUrl: baseUrl,
    publicBaseUrl: 'providers.external.test',
    payloads,
    tenantPolls: [
      {
        tenantId: 'alpha',
        relayBaseUrl: baseUrl,
        publicBaseUrl: 'providers.external.test',
        payloadIds: ['cb-provider-http-alpha', 'cb-provider-dns-alpha'],
        interactions: [...genericAlphaBody.interactions, ...dnsAlphaBody.interactions],
        statusCode: 200,
        rawRequest: `${genericAlpha.rawRequest}\n${dnsAlpha.rawRequest}`,
        rawResponse: `${genericAlpha.rawResponse}\n${dnsAlpha.rawResponse}`,
        signature: signatureFrom(genericAlpha, 'generic-http-key'),
      },
      {
        tenantId: 'beta',
        relayBaseUrl: baseUrl,
        publicBaseUrl: 'providers.external.test',
        payloadIds: ['cb-provider-smtp-beta', 'cb-provider-http-beta'],
        interactions: [...smtpBetaBody.interactions, ...genericBetaBody.interactions],
        statusCode: 200,
        rawRequest: `${smtpBeta.rawRequest}\n${genericBeta.rawRequest}`,
        rawResponse: `${smtpBeta.rawResponse}\n${genericBeta.rawResponse}`,
        signature: signatureFrom(smtpBeta, 'smtp-relay-key'),
      },
    ],
    minTenantCount: 2,
    minInteractionCount: 4,
    minProtocolCount: 3,
    now,
  });
  assert.equal(relayIntegration.status, 'pass');

  const diversity = callbackEngine.buildCallbackExternalOastProviderDiversityPackage({
    profile,
    payloads,
    relayIntegrationPackages: [relayIntegration],
    providerProbes: [
      buildProviderProbe('generic-http', 'alpha', 'http', genericAlpha, genericAlphaBody.interactions),
      buildProviderProbe('dns-webhook', 'alpha', 'dns', dnsAlpha, dnsAlphaBody.interactions),
      buildProviderProbe('smtp-relay', 'beta', 'smtp', smtpBeta, smtpBetaBody.interactions),
    ],
    minProviderCount: 3,
    minProtocolCount: 3,
    minInteractionCount: 3,
    now,
  });

  assert.equal(diversity.kind, 'proxyforge-callback-external-oast-provider-diversity-package');
  assert.equal(diversity.status, 'pass');
  assert.equal(diversity.reportReady, true);
  assert.equal(diversity.providerCount, 3);
  assert.equal(diversity.providerKinds.length, 3);
  assert.equal(diversity.protocolCount, 3);
  assert.equal(diversity.linkedRelayIntegrationPackageIds.length, 1);
  assert.equal(diversity.leakedInteractionIds.length, 0);
  assert.ok(diversity.providerProbes.every((probe) => probe.isolationStatus === 'isolated' && probe.signature.status === 'signed'));
  assert.match(diversity.content, /generic-http-provider-token|dns-webhook-provider-token|smtp-relay-provider-token/);
  assert.match(diversity.content, /alpha-generic-http-secret-token|alpha-dns-webhook-secret-token|beta-smtp-relay-secret-token/);
  assert.match(diversity.content, /redact-only-during-report-export/);

  const leakingDiversity = callbackEngine.buildCallbackExternalOastProviderDiversityPackage({
    profile,
    payloads,
    relayIntegrationPackages: [relayIntegration],
    providerProbes: [
      buildProviderProbe('generic-http', 'alpha', 'http', {
        ...genericAlpha,
        body: JSON.stringify({
          ...genericAlphaBody,
          interactions: [...genericAlphaBody.interactions, smtpBetaBody.interactions[0]],
          payloadTokens: [...genericAlphaBody.payloadTokens, 'beta-smtp-relay-secret-token'],
        }),
        rawResponse: `${genericAlpha.rawResponse}\nLEAK beta-smtp-relay-secret-token`,
      }, [...genericAlphaBody.interactions, smtpBetaBody.interactions[0]]),
      buildProviderProbe('dns-webhook', 'alpha', 'dns', dnsAlpha, dnsAlphaBody.interactions),
      buildProviderProbe('smtp-relay', 'beta', 'smtp', smtpBeta, smtpBetaBody.interactions),
    ],
    minProviderCount: 3,
    minProtocolCount: 3,
    minInteractionCount: 3,
    now,
  });
  assert.equal(leakingDiversity.status, 'fail');
  assert.equal(leakingDiversity.reportReady, false);
  assert.ok(leakingDiversity.providerProbes.some((probe) => probe.isolationStatus === 'leaked'));
  assert.ok(leakingDiversity.leakedInteractionIds.includes(smtpBetaBody.interactions[0].id));

  const artifactDir = path.resolve('.gitignored/test-artifacts/oast-provider-diversity');
  await fs.mkdir(artifactDir, { recursive: true });
  await fs.writeFile(
    path.join(artifactDir, 'external-oast-provider-diversity-package.json'),
    `${diversity.content}\n`,
  );

  console.log('oast-provider-diversity: verified signed isolated generic HTTP, DNS webhook, and SMTP OAST provider probes');
} finally {
  await closeServer(server);
}

async function ingest(providerId, tenantId, payloadId, protocol) {
  const payload = payloads.find((item) => item.id === payloadId);
  return requestRaw(`${baseUrl}/provider/${providerId}/${tenantId}/ingest/${payloadId}?protocol=${protocol}`, {
    method: protocol === 'http' ? 'GET' : 'POST',
    headers: {
      Authorization: `Bearer ${providerSecrets[providerId]}`,
      'Content-Type': 'text/plain',
      'User-Agent': 'ProxyForgeProviderFixture/1.0',
      'X-ProxyForge-Provider-Payload': payload?.token ?? '',
    },
    body: `${providerId} ${tenantId} ${protocol} callback ${payload?.token ?? ''}`,
  });
}

async function pollProvider(providerId, tenantId) {
  return requestRaw(`${baseUrl}/provider/${providerId}/${tenantId}/poll`, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${providerSecrets[providerId]}`,
      Accept: 'application/json',
      'User-Agent': 'ProxyForgeProviderPoller/1.0',
    },
  });
}

function buildProviderProbe(providerId, tenantId, protocol, pollResult, interactions) {
  return {
    providerId,
    providerName: providerId.replace(/-/g, ' '),
    providerKind: providerKinds[providerId],
    tenantId,
    baseUrl: `${baseUrl}/provider/${providerId}`,
    publicBaseUrl: `${providerId}.providers.external.test`,
    protocol,
    payloadIds: payloads.filter((payload) => payload.providerId === providerId && payload.tenantId === tenantId).map((payload) => payload.id),
    interactions,
    statusCode: pollResult.statusCode,
    rawRequest: pollResult.rawRequest,
    rawResponse: pollResult.rawResponse,
    replaySupported: true,
    signature: signatureFrom(pollResult, `${providerId}-key`),
  };
}

function signatureFrom(pollResult, fallbackKeyId) {
  return {
    algorithm: 'HMAC-SHA256',
    keyId: headerValue(pollResult.headers, 'x-proxyforge-signature-key-id') || fallbackKeyId,
    status: headerValue(pollResult.headers, 'x-proxyforge-signature') ? 'signed' : 'missing',
    digestPreview: headerValue(pollResult.headers, 'x-proxyforge-signature').slice(0, 16),
  };
}

function buildPayload(id, tenantId, providerId, protocol, token) {
  return {
    id,
    tenantId,
    providerId,
    token,
    label: `${providerId} ${tenantId} ${protocol} provider payload`,
    protocol,
    endpoint: `${token}.${providerId}.providers.external.test`,
    createdAt: now,
    status: 'waiting',
    sourceExchangeId: `exchange-${tenantId}`,
    sourceHost: `${tenantId}.app.local`,
    sourcePath: `/provider/${providerId}/${protocol}`,
    notes: `Provider ${providerId} ${protocol} payload keeps callback token material until report export.`,
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

function recordKey(providerId, tenantId) {
  return `${providerId}:${tenantId}`;
}

function isProvider(value) {
  return value === 'generic-http' || value === 'dns-webhook' || value === 'smtp-relay';
}

function isTenant(value) {
  return value === 'alpha' || value === 'beta';
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
