import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';
import path from 'node:path';
import { startVulnerableApp } from './fixtures/vulnerable-app/server.mjs';

const require = createRequire(import.meta.url);
const { CertificateAuthorityManager } = require('../dist-electron/certManager.js');
const { ProxyEngine } = require('../dist-electron/proxyEngine.js');
const { applySessionProfileToRawRequest } = require('../dist-electron/sessionEngine.js');

const app = await startVulnerableApp();
const proxy = new ProxyEngine(
  () => undefined,
  new CertificateAuthorityManager(path.join(process.cwd(), '.gitignored', 'session-replay-certs')),
);

try {
  const login = await directRequest(`${app.httpUrl}/login`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'username=session-replay&role=admin',
  });
  assert.equal(login.statusCode, 200);
  const cookies = cookieHeader(login.headers['set-cookie']);
  assert.match(cookies, /pf_session=/);
  assert.match(cookies, /pf_csrf=/);

  const sessionProfile = {
    id: 'runtime-session-admin',
    name: 'Runtime Admin Session',
    headerText: [
      'Authorization: Bearer runtime-session-secret-token',
      'X-API-Key: runtime-session-secret-key',
    ].join('\n'),
    cookieText: cookies,
  };

  const rawProfileRequest = [
    'GET /api/profile HTTP/1.1',
    hostHeader(app.httpUrl),
    'Accept: application/json',
    '',
    '',
  ].join('\r\n');

  const mergedPreview = applySessionProfileToRawRequest([
    'GET /api/profile HTTP/1.1',
    hostHeader(app.httpUrl),
    'Authorization: Bearer stale-token',
    'Cookie: stale=1; pf_session=old',
    '',
    '',
  ].join('\r\n'), sessionProfile, { mode: 'merge', target: 'headers-and-cookies' });
  assert.equal(mergedPreview.trace.applied, true);
  assert(mergedPreview.trace.replacedHeaders.includes('authorization'));
  assert(mergedPreview.trace.replacedCookies.includes('pf_session'));
  assert(mergedPreview.trace.addedCookies.includes('pf_csrf'));
  assert(mergedPreview.trace.operationalSecretSignals.includes('authorization-header'));
  assert.match(mergedPreview.rawRequest, /Authorization: Bearer runtime-session-secret-token/);
  assert.match(mergedPreview.rawRequest, /X-API-Key: runtime-session-secret-key/);
  assert.match(mergedPreview.rawRequest, /Cookie: stale=1; pf_session=sid_/);

  const replacedPreview = applySessionProfileToRawRequest([
    'GET /api/profile HTTP/1.1',
    hostHeader(app.httpUrl),
    'Cookie: stale=1; pf_session=old',
    '',
    '',
  ].join('\r\n'), sessionProfile, { mode: 'replace', target: 'cookies' });
  assert.doesNotMatch(replacedPreview.rawRequest, /stale=1/);
  assert.match(replacedPreview.rawRequest, /pf_session=sid_/);

  const replayed = await proxy.replay({
    rawRequest: rawProfileRequest,
    targetUrl: `${app.httpUrl}/api/profile`,
    scopeAllowlist: ['127.0.0.1'],
    sessionProfile,
    sessionOptions: { mode: 'merge', target: 'headers-and-cookies' },
    settings: {
      redirectMode: 'manual',
      maxRedirects: 0,
      connectionMode: 'close',
      timeoutMs: 1500,
    },
  });
  assert.equal(replayed.status, 200);
  assert(replayed.tags.includes('session-profile'));
  assert.match(replayed.notes, /Runtime Admin Session/);
  assert.match(replayed.requestRaw, /Authorization: Bearer runtime-session-secret-token/);
  assert.match(replayed.requestRaw, /X-API-Key: runtime-session-secret-key/);
  assert.match(replayed.requestRaw, /Cookie: pf_session=sid_/);
  assert.match(replayed.responseRaw, /fixture-token-/);

  const intruder = await proxy.runIntruderAttack({
    rawRequest: rawProfileRequest.replace('/api/profile', '/api/profile?candidate=§role§'),
    targetUrl: `${app.httpUrl}/api/profile?candidate=role`,
    payloads: ['admin'],
    attackMode: 'sniper',
    scopeAllowlist: ['127.0.0.1'],
    throttleMs: 0,
    grepTerms: ['fixture-token'],
    maxPayloadRequests: 1,
    sessionProfile,
    sessionOptions: { mode: 'merge', target: 'headers-and-cookies' },
  });
  assert.equal(intruder.blocked, false);
  assert.equal(intruder.results.length, 1);
  assert(intruder.results[0].tags.includes('session-profile'));
  assert(intruder.results[0].grepMatches.includes('fixture-token'));
  assert.match(intruder.results[0].requestRaw, /runtime-session-secret-token/);
  assert.match(intruder.results[0].requestRaw, /pf_session=sid_/);

  const activeScan = await proxy.runActiveScan({
    rawRequest: rawProfileRequest,
    targetUrl: `${app.httpUrl}/api/profile`,
    scopeAllowlist: ['127.0.0.1'],
    checks: ['security-headers'],
    throttleMs: 0,
    maxRequests: 1,
    sessionProfile,
    sessionOptions: { mode: 'merge', target: 'headers-and-cookies' },
  });
  assert.equal(activeScan.blocked, false);
  assert.equal(activeScan.exchanges.length, 1);
  assert.match(activeScan.exchanges[0].requestRaw, /Authorization: Bearer runtime-session-secret-token/);
  assert.match(activeScan.exchanges[0].requestRaw, /Cookie: pf_session=sid_/);
  assert.match(activeScan.exchanges[0].responseRaw, /fixture-token-/);

  console.log('session-replay-engine: verified backend session header/cookie injection for Repeater, Intruder, and active Scanner with full raw secret preservation');
} finally {
  await proxy.stop().catch(() => undefined);
  await app.close();
}

function directRequest(urlString, options) {
  const url = new URL(urlString);
  const body = options.body ? Buffer.from(options.body, 'utf8') : undefined;
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port,
        method: options.method,
        path: `${url.pathname}${url.search}`,
        headers: {
          host: url.host,
          connection: 'close',
          ...(body ? { 'content-length': body.length } : {}),
          ...(options.headers ?? {}),
        },
      },
      (response) => {
        const chunks = [];
        response.on('data', (chunk) => chunks.push(chunk));
        response.on('end', () => resolve({
          statusCode: response.statusCode,
          headers: response.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        }));
      },
    );
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  });
}

function hostHeader(urlString) {
  return `Host: ${new URL(urlString).host}`;
}

function cookieHeader(setCookieHeaders = []) {
  return setCookieHeaders.map((value) => value.split(';')[0]).join('; ');
}
