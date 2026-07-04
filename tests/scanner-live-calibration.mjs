import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const { ProxyEngine } = require('../dist-electron/proxyEngine.js');

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyforge-scanner-calibration-'));

try {
  const target = http.createServer((request, response) => {
    const probeUrl = new URL(request.url ?? '/', 'http://127.0.0.1');
    if (request.url?.startsWith('/not-found')) {
      if (request.method === 'OPTIONS') {
        response.writeHead(404, {
          allow: 'GET, POST, DELETE',
          'content-type': 'text/html',
        });
        response.end('<html>not found</html>');
        return;
      }
      response.writeHead(404, { 'content-type': 'text/html' });
      response.end('<html>not found</html>');
      return;
    }

    if (request.url?.startsWith('/hardened')) {
      request.resume();
      if (request.method === 'OPTIONS') {
        response.writeHead(204, {
          allow: 'GET, POST',
          'access-control-allow-methods': 'GET, POST',
          'access-control-allow-origin': 'https://app.safe.test',
          'access-control-allow-credentials': 'true',
          'x-content-type-options': 'nosniff',
        });
        response.end();
        return;
      }
      response.writeHead(200, {
        'content-type': request.headers.origin ? 'application/json' : 'text/html',
        'content-security-policy': "default-src 'self'",
        'x-content-type-options': 'nosniff',
        'access-control-allow-origin': 'https://app.safe.test',
        'access-control-allow-credentials': 'true',
      });
      response.end(request.headers.origin ? '{"ok":true}' : '<html><h1>safe page</h1></html>');
      return;
    }

    const bodyParts = [`path=${request.url}`];
    if (request.headers['x-forwarded-host']) bodyParts.push(String(request.headers['x-forwarded-host']));
    if (request.headers['x-proxyforge-auth-state']) bodyParts.push('role=support_admin feature=refunds.write');
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

    response.writeHead(200, {
      'content-type': request.headers.origin ? 'application/json' : 'text/html',
      ...(request.headers.origin ? {
        'access-control-allow-origin': request.headers.origin,
        'access-control-allow-credentials': 'true',
      } : {}),
    });
    response.end(`<html>${bodyParts.join(' ')}</html>`);
  });
  const targetPort = await listen(target);
  const proxy = new ProxyEngine(
    () => undefined,
    new CertificateAuthorityManager(path.join(tempDir, 'certs')),
  );

  const checks = ['security-headers', 'cors-origin', 'cache-key', 'method-options', 'authz-diff', 'jwt-claims', 'graphql-introspection', 'reflected-xss', 'sql-injection', 'path-traversal', 'open-redirect', 'command-injection'];
  const vulnerable = await proxy.runActiveScan({
    rawRequest: rawGet(targetPort, '/vulnerable'),
    targetUrl: `http://127.0.0.1:${targetPort}/vulnerable`,
    scopeAllowlist: ['127.0.0.1'],
    checks,
    throttleMs: 0,
    maxRequests: checks.length,
  });

  assert.equal(vulnerable.blocked, false);
  assert.equal(vulnerable.totalRequests, checks.length + 1);
  assert.equal(vulnerable.suppressedFindings.length, 0);
  assert.equal(vulnerable.tuning.profile, 'browser-app-calibration');
  assert(vulnerable.tuning.falsePositiveControls.includes('suppress-error-page-security-header-noise'));
  assert(vulnerable.findings.some((finding) => finding.title === 'HTML response missing Content-Security-Policy'));
  assert(vulnerable.findings.some((finding) => finding.title === 'CORS policy trusts scanner-controlled origin'));
  assert(vulnerable.findings.some((finding) => finding.title === 'Authenticated state comparison preserved privileged response'));
  assert(vulnerable.findings.some((finding) => finding.title === 'GraphQL introspection data exposed'));
  assert(vulnerable.findings.some((finding) => finding.title === 'Reflected script payload returned unencoded'));
  assert(vulnerable.findings.some((finding) => finding.title === 'SQL injection probe exposed database error evidence'));
  assert(vulnerable.findings.some((finding) => finding.title === 'Path traversal probe reached file-like content'));
  assert(vulnerable.findings.some((finding) => finding.title === 'Open redirect accepts scanner-controlled destination'));
  assert(vulnerable.findings.some((finding) => finding.title === 'Command injection probe produced execution-like output'));
  assert.equal(new Set(vulnerable.findings.map((finding) => finding.dedupeKey)).size, vulnerable.findings.length);

  const hardened = await proxy.runActiveScan({
    rawRequest: rawGet(targetPort, '/hardened'),
    targetUrl: `http://127.0.0.1:${targetPort}/hardened`,
    scopeAllowlist: ['127.0.0.1'],
    checks,
    throttleMs: 0,
    maxRequests: checks.length,
  });

  assert.equal(hardened.blocked, false);
  assert.equal(hardened.totalRequests, checks.length + 1);
  assert.deepEqual(hardened.findings, []);
  assert.deepEqual(hardened.suppressedFindings, []);
  assert.equal(hardened.tuning.suppressedFindingCount, 0);

  const noisyErrorPage = await proxy.runActiveScan({
    rawRequest: rawGet(targetPort, '/not-found'),
    targetUrl: `http://127.0.0.1:${targetPort}/not-found`,
    scopeAllowlist: ['127.0.0.1'],
    checks: ['security-headers', 'method-options'],
    throttleMs: 0,
    maxRequests: 2,
  });

  assert.equal(noisyErrorPage.blocked, false);
  assert.equal(noisyErrorPage.totalRequests, 2);
  assert.deepEqual(noisyErrorPage.findings, []);
  assert.equal(noisyErrorPage.suppressedFindings.length, 2);
  assert(noisyErrorPage.suppressedFindings.some((finding) => finding.reason === 'error-response-security-header-noise'));
  assert(noisyErrorPage.suppressedFindings.some((finding) => finding.reason === 'error-response-method-advertising-noise'));
  assert.equal(noisyErrorPage.tuning.suppressedFindingCount, 2);

  await close(target);
  console.log('scanner-live-calibration: verified vulnerable findings, hardened no-finding path, and noisy error-page suppression');
} finally {
  await fs.rm(tempDir, { recursive: true, force: true });
}

function rawGet(port, route) {
  return [
    `GET ${route} HTTP/1.1`,
    `Host: 127.0.0.1:${port}`,
    'Accept: text/html',
    'Authorization: Bearer scanner-calibration-token',
    '',
    '',
  ].join('\n');
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
