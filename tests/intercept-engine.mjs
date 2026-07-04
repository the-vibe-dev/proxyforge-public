import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const {
  ProxyEngine,
  buildProxyInterceptEvidencePackage,
  buildProxyMatchReplaceRuleLibraryPackage,
  importProxyMatchReplaceRuleLibraryPackage,
} = require('../dist-electron/proxyEngine.js');

const artifactRoot = path.resolve('.gitignored', 'test-artifacts');
const tempDir = path.join(artifactRoot, `proxyforge-intercept-${Date.now()}-${process.pid}`);
const pendingQueues = [];
const exchanges = [];
const upstreamPaths = [];
let upstream;
let proxy;

try {
  await fs.mkdir(tempDir, { recursive: true });
  upstream = http.createServer((request, response) => {
    upstreamPaths.push(request.url);
    response.writeHead(200, { 'content-type': 'application/json' });
    response.end(JSON.stringify({ path: request.url }));
  });
  const upstreamPort = await listen(upstream);

  proxy = new ProxyEngine(
    (exchange) => exchanges.push(exchange),
    new CertificateAuthorityManager(path.join(tempDir, 'certs')),
    (pending) => pendingQueues.push(pending),
  );
  const proxyPort = await freePort();
  await proxy.start(proxyPort);
  proxy.setIntercept(true);

  const forwarded = requestViaProxy(proxyPort, upstreamPort, '/original');
  await waitFor(() => pendingQueues.at(-1)?.length === 1);
  const firstIntercept = pendingQueues.at(-1)[0];
  assert.equal(firstIntercept.path, '/original');
  proxy.resolveIntercept({
    id: firstIntercept.id,
    action: 'forward',
    rawRequest: `GET /edited HTTP/1.1\r\nHost: 127.0.0.1:${upstreamPort}\r\nConnection: close\r\n\r\n`,
  });

  const forwardedResponse = await forwarded;
  assert.equal(forwardedResponse.statusCode, 200);
  assert.match(forwardedResponse.body, /edited/);
  assert.equal(upstreamPaths.at(-1), '/edited');
  await waitFor(() => exchanges.some((exchange) => exchange.path === '/edited' && exchange.tags.includes('edited')));

  const dropped = requestViaProxy(proxyPort, upstreamPort, '/drop-me');
  await waitFor(() => pendingQueues.at(-1)?.length === 1);
  const secondIntercept = pendingQueues.at(-1)[0];
  proxy.resolveIntercept({ id: secondIntercept.id, action: 'drop' });
  const droppedResponse = await dropped;
  assert.equal(droppedResponse.statusCode, 444);
  assert.match(droppedResponse.body, /dropped/);
  await waitFor(() => exchanges.some((exchange) => exchange.path === '/drop-me' && exchange.tags.includes('dropped')));

  proxy.setIntercept(false);
  proxy.setResponseIntercept(true);

  const editedResponseRequest = requestViaProxy(proxyPort, upstreamPort, '/response-original');
  await waitFor(() => pendingQueues.at(-1)?.some((pending) => pending.direction === 'response' && pending.path === '/response-original'));
  const responseIntercept = pendingQueues.at(-1).find((pending) => pending.direction === 'response' && pending.path === '/response-original');
  assert.equal(responseIntercept.status, 200);
  proxy.resolveIntercept({
    id: responseIntercept.id,
    action: 'forward',
    rawRequest: [
      'HTTP/1.1 202 Accepted',
      'Content-Type: application/json',
      '',
      '{"path":"/response-original","edited":true}',
    ].join('\r\n'),
  });

  const editedResponse = await editedResponseRequest;
  assert.equal(editedResponse.statusCode, 202);
  assert.match(editedResponse.body, /"edited":true/);
  await waitFor(() => exchanges.some((exchange) => exchange.path === '/response-original' && exchange.tags.includes('response-edited')));

  const droppedResponseRequest = requestViaProxy(proxyPort, upstreamPort, '/drop-response');
  await waitFor(() => pendingQueues.at(-1)?.some((pending) => pending.direction === 'response' && pending.path === '/drop-response'));
  const droppedResponseIntercept = pendingQueues.at(-1).find((pending) => pending.direction === 'response' && pending.path === '/drop-response');
  proxy.resolveIntercept({ id: droppedResponseIntercept.id, action: 'drop' });
  const droppedInterceptResponse = await droppedResponseRequest;
  assert.equal(droppedInterceptResponse.statusCode, 444);
  assert.match(droppedInterceptResponse.body, /dropped this intercepted response/);
  await waitFor(() => exchanges.some((exchange) => exchange.path === '/drop-response' && exchange.tags.includes('response-dropped')));

  proxy.setResponseIntercept(false);
  const activeMatchReplaceRules = [
    {
      id: 'request-path-rewrite',
      name: 'Path rewrite',
      enabled: true,
      direction: 'request',
      match: '/match-original',
      replace: '/match-edited',
      isRegex: false,
      caseSensitive: true,
    },
    {
      id: 'response-body-rewrite',
      name: 'Response body rewrite',
      enabled: true,
      direction: 'response',
      match: '"path":"/response-match"',
      replace: '"rewritten":true',
      isRegex: false,
      caseSensitive: true,
    },
  ];
  proxy.setMatchReplaceRules(activeMatchReplaceRules);

  const rewrittenRequest = await requestViaProxy(proxyPort, upstreamPort, '/match-original');
  assert.equal(rewrittenRequest.statusCode, 200);
  assert.equal(upstreamPaths.at(-1), '/match-edited');
  await waitFor(() => exchanges.some((exchange) => exchange.path === '/match-edited' && exchange.tags.includes('match-replace')));

  const rewrittenResponse = await requestViaProxy(proxyPort, upstreamPort, '/response-match');
  assert.equal(rewrittenResponse.statusCode, 200);
  assert.match(rewrittenResponse.body, /"rewritten":true/);
  await waitFor(() => exchanges.some((exchange) => exchange.path === '/response-match' && exchange.tags.includes('response-rule:Response body rewrite')));

  const evidencePackage = buildProxyInterceptEvidencePackage(exchanges);
  assert.equal(evidencePackage.kind, 'proxyforge-proxy-intercept-evidence-package');
  assert.equal(evidencePackage.requirements.requestForwardCovered, true);
  assert.equal(evidencePackage.requirements.requestEditCovered, true);
  assert.equal(evidencePackage.requirements.requestDropCovered, true);
  assert.equal(evidencePackage.requirements.responseForwardCovered, true);
  assert.equal(evidencePackage.requirements.responseEditCovered, true);
  assert.equal(evidencePackage.requirements.responseDropCovered, true);
  assert.equal(evidencePackage.requirements.matchReplaceCovered, true);
  assert.equal(evidencePackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.match(JSON.stringify(evidencePackage.decisions), /\/edited|\/drop-me|\/response-original|\/drop-response/);
  await fs.writeFile(path.join(tempDir, 'proxy-intercept-evidence-package.json'), JSON.stringify(evidencePackage, null, 2), 'utf8');

  const largeRuleLibrary = [
    ...activeMatchReplaceRules,
    ...Array.from({ length: 128 }, (_, index) => ({
      id: `bulk-rule-${index}`,
      name: `Bulk scoped rule ${index}`,
      enabled: index % 3 === 0,
      direction: index % 2 === 0 ? 'request' : 'response',
      match: `X-Bulk-Needle-${index}`,
      replace: `X-Bulk-Rewrite-${index}`,
      isRegex: index % 5 === 0,
      caseSensitive: index % 4 === 0,
    })),
  ];
  const ruleSampleExchange = {
    id: 'hx-match-replace-sample-before',
    method: 'GET',
    host: `127.0.0.1:${upstreamPort}`,
    path: '/match-original',
    url: `http://127.0.0.1:${upstreamPort}/match-original`,
    status: 200,
    length: 32,
    mime: 'application/json',
    risk: 'info',
    timing: 0,
    notes: 'Synthetic raw before/after sample for match/replace rule-library export.',
    source: 'proxy',
    time: '00:00:00',
    requestRaw: `GET /match-original HTTP/1.1\nHost: 127.0.0.1:${upstreamPort}\n\n`,
    responseRaw: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"path":"/response-match"}',
    tags: ['match-replace-sample'],
  };
  const ruleLibraryPackage = buildProxyMatchReplaceRuleLibraryPackage(largeRuleLibrary, [...exchanges, ruleSampleExchange]);
  assert.equal(ruleLibraryPackage.kind, 'proxyforge-proxy-match-replace-rule-library');
  assert.equal(ruleLibraryPackage.ruleCount, largeRuleLibrary.length);
  assert.equal(ruleLibraryPackage.largeRuleSet.exceeded, true);
  assert.equal(ruleLibraryPackage.requirements.importExportCovered, true);
  assert.equal(ruleLibraryPackage.requirements.requestRewriteCovered, true);
  assert.equal(ruleLibraryPackage.requirements.responseRewriteCovered, true);
  assert.equal(ruleLibraryPackage.requirements.largeRuleSetCovered, true);
  assert(ruleLibraryPackage.appliedRuleTags.some((tag) => /request-rule:Path rewrite/.test(tag)));
  assert(ruleLibraryPackage.appliedRuleTags.some((tag) => /response-rule:Response body rewrite/.test(tag)));
  const importedRules = importProxyMatchReplaceRuleLibraryPackage(JSON.stringify(ruleLibraryPackage));
  assert.equal(importedRules.length, largeRuleLibrary.length);
  assert.deepEqual(importedRules.slice(0, 2), activeMatchReplaceRules);
  await fs.writeFile(path.join(tempDir, 'proxy-match-replace-rule-library.json'), JSON.stringify(ruleLibraryPackage, null, 2), 'utf8');

} finally {
  if (proxy) await proxy.stop().catch(() => undefined);
  if (upstream?.listening) await close(upstream).catch(() => undefined);
}

function requestViaProxy(proxyPort, upstreamPort, requestPath) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: '127.0.0.1',
        port: proxyPort,
        method: 'GET',
        agent: false,
        path: `http://127.0.0.1:${upstreamPort}${requestPath}`,
        headers: {
          host: `127.0.0.1:${upstreamPort}`,
          connection: 'close',
        },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => {
          resolve({
            statusCode: response.statusCode,
            body: Buffer.concat(chunks).toString('utf8'),
          });
        });
      },
    );
    request.on('error', reject);
    request.end();
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

async function waitFor(predicate) {
  const deadline = Date.now() + 3000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
  throw new Error('Timed out waiting for intercept condition');
}
