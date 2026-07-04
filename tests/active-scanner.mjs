import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const {
  ACTIVE_SCAN_BUILT_IN_CHECKS,
  ProxyEngine,
  buildActiveScanCheckPackEvidencePackage,
} = require('../dist-electron/proxyEngine.js');

const tempDir = path.resolve('.gitignored/test-artifacts/active-scanner', `proxyforge-active-scan-${Date.now()}-${process.pid}`);
await fs.mkdir(tempDir, { recursive: true });

let target;
try {
  target = http.createServer((request, response) => {
    const probeUrl = new URL(request.url ?? '/', 'http://127.0.0.1');
    const bodyParts = [`path=${request.url}`];
    if (request.headers['x-forwarded-host']) bodyParts.push(String(request.headers['x-forwarded-host']));
    if (request.headers['x-proxyforge-auth-state']) bodyParts.push('role=support_admin');
    if (request.headers['x-proxyforge-token-audit']) bodyParts.push('token=eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic3VwcG9ydF9hZG1pbiJ9.signature');
    if (request.headers['x-proxyforge-active-scan'] === 'graphql-introspection') bodyParts.push('__schema queryType mutationType');
    if (probeUrl.searchParams.get('pf_xss')) bodyParts.push(probeUrl.searchParams.get('pf_xss'));
    if (/proxyforge_sql_probe/.test(probeUrl.searchParams.get('pf_id') ?? '')) bodyParts.push('SQL syntax error near proxyforge_sql_probe');
    if (probeUrl.searchParams.get('file')?.includes('etc/passwd')) bodyParts.push('root:x:0:0:root:/root:/bin/bash');
    if (/proxyforge_command_probe/.test(probeUrl.searchParams.get('cmd') ?? '')) bodyParts.push('uid=1000(proxyforge) gid=1000(proxyforge) proxyforge_command_probe');

    if (probeUrl.searchParams.get('next') === 'https://proxyforge.invalid/redirect-proof') {
      response.writeHead(302, {
        location: 'https://proxyforge.invalid/redirect-proof',
        'content-type': 'text/html',
      });
      response.end('<html>redirecting</html>');
      return;
    }

    if (request.method === 'OPTIONS') {
      response.writeHead(204, {
        allow: 'GET, POST, DELETE',
        'access-control-allow-methods': 'GET, POST, DELETE',
      });
      response.end();
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
    response.end(`<html>${bodyParts.join(' ')}</html>`);
  });
  const targetPort = await listen(target);

  const proxy = new ProxyEngine(
    () => undefined,
    new CertificateAuthorityManager(path.join(tempDir, 'certs')),
  );

  const rawRequest = [
    'GET /profile HTTP/1.1',
    `Host: 127.0.0.1:${targetPort}`,
    'Authorization: Bearer active-scan-baseline-token',
    'Cookie: session=active-scan-cookie; pref=full-fidelity',
    'X-API-Key: active-scan-api-key',
    'Accept: text/html',
    '',
    '',
  ].join('\n');

  const blockedRequest = {
    rawRequest,
    targetUrl: `http://127.0.0.1:${targetPort}/profile`,
    scopeAllowlist: ['example.invalid'],
    checks: ['security-headers'],
    throttleMs: 0,
    maxRequests: 4,
  };
  const blocked = await proxy.runActiveScan({
    ...blockedRequest,
  });
  assert.equal(blocked.blocked, true);
  assert.equal(blocked.totalRequests, 0);

  const activeScanRequest = {
    rawRequest,
    targetUrl: `http://127.0.0.1:${targetPort}/profile`,
    scopeAllowlist: ['127.0.0.1'],
    checks: ACTIVE_SCAN_BUILT_IN_CHECKS,
    throttleMs: 0,
    maxRequests: ACTIVE_SCAN_BUILT_IN_CHECKS.length,
  };
  const summary = await proxy.runActiveScan(activeScanRequest);

  assert.equal(summary.blocked, false);
  assert.equal(summary.totalRequests, ACTIVE_SCAN_BUILT_IN_CHECKS.length + 1);
  assert(summary.findings.some((finding) => finding.title === 'HTML response missing Content-Security-Policy'));
  assert(summary.findings.some((finding) => finding.title === 'CORS policy trusts scanner-controlled origin'));
  assert(summary.findings.some((finding) => finding.title === 'Untrusted cache-routing header reflected'));
  assert(summary.findings.some((finding) => finding.title === 'OPTIONS response advertises state-changing methods'));
  assert(summary.findings.some((finding) => finding.title === 'Authenticated state comparison preserved privileged response'));
  assert(summary.findings.some((finding) => finding.title === 'Token or privileged claim material exposed'));
  assert(summary.findings.some((finding) => finding.title === 'GraphQL introspection data exposed'));
  assert(summary.findings.some((finding) => finding.title === 'Reflected script payload returned unencoded'));
  assert(summary.findings.some((finding) => finding.title === 'SQL injection probe exposed database error evidence'));
  assert(summary.findings.some((finding) => finding.title === 'Path traversal probe reached file-like content'));
  assert(summary.findings.some((finding) => finding.title === 'Open redirect accepts scanner-controlled destination'));
  assert(summary.findings.some((finding) => finding.title === 'Command injection probe produced execution-like output'));
  assert(summary.findings.every((finding) => finding.dedupeKey));
  assert(summary.findings.every((finding) => finding.confidenceReason));
  assert(summary.exchanges.every((exchange) => exchange.source === 'scanner'));
  assert(summary.exchanges.every((exchange) => exchange.tags.includes('active-scan')));

  const checkPackEvidence = buildActiveScanCheckPackEvidencePackage(activeScanRequest, summary, {
    blockedSummary: blocked,
    generatedAt: '2026-05-25T15:00:00.000Z',
    checkPacks: [
      {
        id: 'built-in-baseline-hardening',
        name: 'Built-in baseline hardening',
        checks: ['security-headers', 'cors-origin', 'cache-key', 'method-options', 'reflected-xss', 'sql-injection', 'path-traversal', 'open-redirect', 'command-injection'],
        source: 'legacy-proxy-parity-built-in',
      },
      {
        id: 'auth-api-graphql-parity',
        name: 'Auth/API/GraphQL parity checks',
        checks: ['authz-diff', 'jwt-claims', 'graphql-introspection', 'oast-ssrf', 'idempotency-key-replay'],
        source: 'operator-check-pack',
      },
    ],
  });
  assert.equal(checkPackEvidence.kind, 'proxyforge-active-scan-check-pack-evidence-package');
  assert.deepEqual(checkPackEvidence.requestedChecks, ACTIVE_SCAN_BUILT_IN_CHECKS);
  assert.equal(checkPackEvidence.requirements.scopeGateBlocksOutOfScope, true);
  assert.equal(checkPackEvidence.requirements.allBuiltInChecksCovered, true);
  assert.equal(checkPackEvidence.requirements.checkPackExpansionCovered, true);
  assert.equal(checkPackEvidence.requirements.rateAndCapControlsRecorded, true);
  assert.equal(checkPackEvidence.requirements.authzTwoLegComparisonCovered, true);
  assert.equal(checkPackEvidence.requirements.findingDedupeConfidenceCovered, true);
  assert.equal(checkPackEvidence.requirements.falsePositiveTuningCovered, true);
  assert.equal(checkPackEvidence.requirements.rawProbeExchangesPreserved, true);
  assert.equal(checkPackEvidence.requirements.operationalSecretsPreserved, true);
  assert.equal(checkPackEvidence.requirements.reportPhaseOnlyRedaction, true);
  assert.equal(checkPackEvidence.secretHandling, 'execution-full-fidelity-secrets-preserved');
  assert.equal(checkPackEvidence.reportRedactionBoundary, 'redact-only-during-report-export');
  assert(checkPackEvidence.operationalSecretSignals.includes('authorization-header'));
  assert(checkPackEvidence.operationalSecretSignals.includes('cookie-header'));
  assert(checkPackEvidence.operationalSecretSignals.includes('x-api-key-header'));
  assert(checkPackEvidence.checkCoverage.every((coverage) => coverage.requested && coverage.executed));
  assert(checkPackEvidence.checkPackMatrix.some((pack) => pack.unsupportedChecks.includes('idempotency-key-replay')));
  assert.match(
    JSON.stringify(checkPackEvidence, null, 2),
    /Bearer active-scan-baseline-token|session=active-scan-cookie|active-scan-api-key|reportPhaseOnlyRedaction|idempotency-key-replay/i,
  );
  await fs.writeFile(
    path.join(tempDir, 'active-scan-check-pack-evidence-package.json'),
    JSON.stringify(checkPackEvidence, null, 2),
    'utf8',
  );

  await close(target);
} catch (error) {
  console.error(`active-scanner: artifacts retained in ${tempDir}`);
  throw error;
} finally {
  if (target?.listening) await close(target);
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
