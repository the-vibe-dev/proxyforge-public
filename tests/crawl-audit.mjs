import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const { CrawlEngine } = require('../dist-electron/crawlEngine.js');
const {
  ProxyEngine,
  buildCrawlAuditInsertionEvidencePackage,
} = require('../dist-electron/proxyEngine.js');

const tempDir = path.resolve('.gitignored/test-artifacts/crawl-audit', `proxyforge-crawl-audit-${Date.now()}-${process.pid}`);
await fs.mkdir(tempDir, { recursive: true });
const target = http.createServer((request, response) => {
  if (request.method === 'OPTIONS') {
    response.writeHead(204, {
      allow: 'GET, POST, DELETE',
      'access-control-allow-methods': 'GET, POST, DELETE',
    });
    response.end();
    return;
  }

  if (request.url === '/') {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end([
      '<html><title>Audit Seed</title>',
      '<a href="/orders?status=open">Orders</a>',
      '<a href="/orders/1234">Order detail</a>',
      '<form method="post" action="/api/refunds">',
      '<input name="orderId"><input name="amount">',
      '</form></html>',
    ].join(''));
    return;
  }

  if (request.url === '/orders/1234') {
    response.writeHead(200, { 'content-type': 'text/html' });
    response.end('<html>Order detail 1234</html>');
    return;
  }

  const headers = {
    'content-type': request.headers.origin ? 'application/json' : 'text/html',
    ...(request.headers.origin ? {
      'access-control-allow-origin': request.headers.origin,
      'access-control-allow-credentials': 'true',
    } : {}),
  };
  response.writeHead(200, headers);
  response.end(`<html>${request.headers['x-forwarded-host'] ?? ''} ${request.url}</html>`);
});

try {
  const port = await listen(target);
  const startUrl = `http://127.0.0.1:${port}/`;
  const crawler = new CrawlEngine();
  const crawl = await crawler.runCrawl({
    startUrl,
    scopeAllowlist: ['127.0.0.1'],
    maxDepth: 1,
    maxPages: 4,
    throttleMs: 0,
    userAgent: 'ProxyForge Crawl Audit Test',
    includeForms: true,
  });
  assert(crawl.insertionPoints.some((point) => point.name === 'status'));
  assert(crawl.insertionPoints.some((point) => point.name === 'orderId'));
  assert(crawl.insertionPoints.some((point) => point.type === 'path' && point.name === 'segment-2'));

  const proxy = new ProxyEngine(
    () => undefined,
    new CertificateAuthorityManager(path.join(tempDir, 'certs')),
  );

  const blocked = await proxy.runCrawlAudit({
    scopeAllowlist: ['example.invalid'],
    checks: ['security-headers'],
    insertionPoints: crawl.insertionPoints,
    throttleMs: 0,
    maxInsertionPoints: 4,
  });
  assert.equal(blocked.blocked, true);
  assert.equal(blocked.auditedInsertionPoints, 0);

  const auditInsertionPoints = [
    ...crawl.insertionPoints,
    { ...crawl.insertionPoints[0], id: `${crawl.insertionPoints[0].id}-duplicate` },
    {
      id: 'ip-out-of-scope-debug',
      routeId: 'route-out-of-scope-debug',
      type: 'query',
      name: 'debug',
      method: 'GET',
      url: 'http://out-of-scope.invalid/debug?debug=1',
      evidence: 'Out-of-scope insertion point fixture',
    },
  ];
  const auditRequest = {
    scopeAllowlist: ['127.0.0.1'],
    checks: ['security-headers', 'cors-origin', 'cache-key', 'method-options'],
    insertionPoints: auditInsertionPoints,
    sessionHeaders: {
      Authorization: 'Bearer crawl-audit-token',
      Cookie: 'session=crawl-audit-cookie',
      'X-API-Key': 'crawl-audit-api-key',
    },
    throttleMs: 0,
    maxInsertionPoints: 8,
  };
  const audit = await proxy.runCrawlAudit(auditRequest);

  assert.equal(audit.blocked, false);
  assert(audit.auditedInsertionPoints >= 4);
  assert.equal(audit.totalRequests, audit.auditedInsertionPoints * auditRequest.checks.length);
  assert(audit.exchanges.every((exchange) => exchange.source === 'scanner'));
  assert(audit.exchanges.every((exchange) => exchange.tags.includes('crawl-audit')));
  assert(audit.exchanges.some((exchange) => exchange.tags.some((tag) => tag.startsWith('insertion:'))));
  assert(audit.findings.some((finding) => finding.title === 'HTML response missing Content-Security-Policy'));
  assert(audit.findings.some((finding) => finding.title === 'CORS policy trusts scanner-controlled origin'));
  assert(audit.findings.some((finding) => finding.title === 'Untrusted cache-routing header reflected'));
  assert(audit.findings.some((finding) => finding.title === 'OPTIONS response advertises state-changing methods'));

  const crawlAuditEvidence = buildCrawlAuditInsertionEvidencePackage(auditRequest, audit, {
    blockedSummary: blocked,
    generatedAt: '2026-05-25T15:30:00.000Z',
  });
  assert.equal(crawlAuditEvidence.kind, 'proxyforge-crawl-audit-insertion-evidence-package');
  assert.equal(crawlAuditEvidence.requirements.crawlerInsertionPointsLinked, true);
  assert.equal(crawlAuditEvidence.requirements.scopeGateBlocksOutOfScope, true);
  assert.equal(crawlAuditEvidence.requirements.queryFormPathCoverage, true);
  assert.equal(crawlAuditEvidence.requirements.duplicateAndOutOfScopeReviewCovered, true);
  assert.equal(crawlAuditEvidence.requirements.activeScannerHandoffCovered, true);
  assert.equal(crawlAuditEvidence.requirements.rateAndCapControlsRecorded, true);
  assert.equal(crawlAuditEvidence.requirements.findingDedupeConfidenceCovered, true);
  assert.equal(crawlAuditEvidence.requirements.falsePositiveTuningCovered, true);
  assert.equal(crawlAuditEvidence.requirements.rawProbeExchangesPreserved, true);
  assert.equal(crawlAuditEvidence.requirements.operationalSecretsPreserved, true);
  assert.equal(crawlAuditEvidence.requirements.reportPhaseOnlyRedaction, true);
  assert.equal(crawlAuditEvidence.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.equal(crawlAuditEvidence.reportRedactionBoundary, 'redact-only-during-report-export');
  assert(crawlAuditEvidence.operationalSecretSignals.includes('authorization-header'));
  assert(crawlAuditEvidence.operationalSecretSignals.includes('cookie-header'));
  assert(crawlAuditEvidence.operationalSecretSignals.includes('x-api-key-header'));
  assert(crawlAuditEvidence.auditedInsertionPoints.some((point) => point.type === 'query' && point.name === 'status'));
  assert(crawlAuditEvidence.auditedInsertionPoints.some((point) => point.type === 'form' && point.name === 'orderId'));
  assert(crawlAuditEvidence.auditedInsertionPoints.some((point) => point.type === 'path' && point.name === 'segment-2'));
  assert.match(
    JSON.stringify(crawlAuditEvidence, null, 2),
    /Bearer crawl-audit-token|session=crawl-audit-cookie|crawl-audit-api-key|reportPhaseOnlyRedaction|Out-of-scope insertion point fixture/i,
  );
  await fs.writeFile(
    path.join(tempDir, 'crawl-audit-insertion-evidence-package.json'),
    JSON.stringify(crawlAuditEvidence, null, 2),
    'utf8',
  );
} finally {
  await close(target);
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
