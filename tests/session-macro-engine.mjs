import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import http from 'node:http';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  applyMacroProfileToToolRequest,
  buildSessionMacroEvidencePackage,
  runSessionMacro,
} = require('../dist-electron/sessionMacroEngine.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/session-macro-engine', `${Date.now()}-${process.pid}`);
await fs.mkdir(artifactRoot, { recursive: true });

const observedRequests = [];
const server = http.createServer((request, response) => {
  const chunks = [];
  request.on('data', (chunk) => chunks.push(chunk));
  request.on('end', () => {
    observedRequests.push({
      method: request.method,
      url: request.url,
      authorization: request.headers.authorization,
      cookie: request.headers.cookie,
      macroSecret: request.headers['x-macro-secret'],
      body: Buffer.concat(chunks).toString('utf8'),
    });
    if (request.url !== '/login') {
      response.writeHead(404, { 'content-type': 'text/plain' });
      response.end('missing');
      return;
    }
    response.writeHead(200, {
      'content-type': 'text/html',
      'set-cookie': [
        'session=macro-session-secret; Path=/; HttpOnly; SameSite=Lax',
        'macro_refresh=macro-refresh-secret; Path=/; SameSite=Lax',
      ],
      'x-macro-lane': 'session-token-refresh',
    });
    response.end('<form><input type="hidden" name="csrf" value="macro-csrf-secret"><input name="nonce" value="macro-nonce-secret"></form>');
  });
});

try {
  const port = await listen(server);
  const profile = {
    id: 'macro-profile-support',
    name: 'Macro Support Session',
    role: 'support',
    targetUrl: `http://127.0.0.1:${port}/app`,
    source: 'traffic',
    status: 'stale',
    headerText: 'Authorization: Bearer macro-stale-token\nX-API-Key: macro-api-secret',
    cookieText: 'session=macro-expired-session; theme=dark',
    createdAt: '2026-05-26T00:10:00.000Z',
    updatedAt: '2026-05-26T00:10:00.000Z',
    headerCount: 0,
    cookieCount: 0,
    notes: 'Session macro regression profile.',
  };
  const macro = {
    id: 'macro-login-refresh',
    name: 'Login CSRF refresh',
    scopeAllowlist: ['127.0.0.1'],
    steps: [{
      id: 'step-login',
      name: 'Fetch login form',
      method: 'GET',
      url: `http://127.0.0.1:${port}/login`,
      headers: {
        'X-Macro-Secret': 'macro-step-secret',
      },
      extractors: [
        {
          id: 'extract-csrf',
          name: 'Hidden CSRF field',
          source: 'body',
          pattern: 'name="csrf" value="([^"]+)"',
          target: 'header',
          targetName: 'X-CSRF-Token',
        },
        {
          id: 'extract-nonce-cookie',
          name: 'Nonce cookie bridge',
          source: 'body',
          pattern: 'name="nonce" value="([^"]+)"',
          target: 'cookie',
          targetName: 'macro_nonce',
        },
      ],
    }],
  };

  const result = await runSessionMacro({ macro, profile, timeoutMs: 2000 });
  assert.equal(result.status, 'complete');
  assert.equal(result.steps.length, 1);
  assert.equal(result.steps[0].statusCode, 200);
  assert.equal(result.extractedTokenCount, 2);
  assert.equal(result.setCookieCount, 2);
  assert(result.operationalSecretSignals.includes('authorization-header'));
  assert(result.operationalSecretSignals.includes('cookie-header'));
  assert.equal(result.rawExecutorMaterialPreserved, true);
  assert.match(result.profile.headerText, /X-CSRF-Token: macro-csrf-secret/);
  assert.match(result.profile.cookieText, /session=macro-session-secret/);
  assert.match(result.profile.cookieText, /macro_refresh=macro-refresh-secret/);
  assert.match(result.profile.cookieText, /macro_nonce=macro-nonce-secret/);
  assert.match(result.steps[0].rawRequest, /Authorization: Bearer macro-stale-token/);
  assert.match(result.steps[0].rawRequest, /Cookie: session=macro-expired-session/);
  assert.match(result.steps[0].rawResponse, /macro-csrf-secret|Set-Cookie: session=macro-session-secret/);

  assert.equal(observedRequests.length, 1);
  assert.equal(observedRequests[0].authorization, 'Bearer macro-stale-token');
  assert.match(observedRequests[0].cookie, /macro-expired-session/);
  assert.equal(observedRequests[0].macroSecret, 'macro-step-secret');

  const repeaterApplied = applyMacroProfileToToolRequest([
    'POST /csrf/transfer HTTP/1.1',
    `Host: 127.0.0.1:${port}`,
    'Cookie: stale=1',
    '',
    '{"amount":10}',
  ].join('\r\n'), `http://127.0.0.1:${port}/csrf/transfer`, result.profile);
  assert.match(repeaterApplied.rawRequest, /X-CSRF-Token: macro-csrf-secret/);
  assert.match(repeaterApplied.rawRequest, /session=macro-session-secret/);
  assert.match(repeaterApplied.rawRequest, /macro_nonce=macro-nonce-secret/);

  const intruderApplied = applyMacroProfileToToolRequest([
    'GET /api/profile?role=§role§ HTTP/1.1',
    `Host: 127.0.0.1:${port}`,
    '',
    '',
  ].join('\r\n'), `http://127.0.0.1:${port}/api/profile?role=admin`, result.profile);
  assert.match(intruderApplied.rawRequest, /X-CSRF-Token: macro-csrf-secret/);
  assert.match(intruderApplied.rawRequest, /session=macro-session-secret/);

  const scannerApplied = applyMacroProfileToToolRequest([
    'GET /api/profile HTTP/1.1',
    `Host: 127.0.0.1:${port}`,
    '',
    '',
  ].join('\r\n'), `http://127.0.0.1:${port}/api/profile`, result.profile);
  assert.match(scannerApplied.rawRequest, /Authorization: Bearer macro-stale-token/);
  assert.match(scannerApplied.rawRequest, /session=macro-session-secret/);

  const evidence = buildSessionMacroEvidencePackage({
    macro,
    result,
    generatedAt: '2026-05-26T00:12:00.000Z',
    appliedRequests: [
      { tool: 'repeater', targetUrl: `http://127.0.0.1:${port}/csrf/transfer`, rawRequest: repeaterApplied.rawRequest, trace: repeaterApplied.trace },
      { tool: 'intruder', targetUrl: `http://127.0.0.1:${port}/api/profile?role=admin`, rawRequest: intruderApplied.rawRequest, trace: intruderApplied.trace },
      { tool: 'scanner', targetUrl: `http://127.0.0.1:${port}/api/profile`, rawRequest: scannerApplied.rawRequest, trace: scannerApplied.trace },
    ],
  });
  assert.equal(evidence.kind, 'proxyforge-session-macro-evidence-package');
  assert.equal(evidence.requirements.scopedExecutionCovered, true);
  assert.equal(evidence.requirements.macroStepExecutionCovered, true);
  assert.equal(evidence.requirements.tokenExtractionCovered, true);
  assert.equal(evidence.requirements.cookieRefreshCovered, true);
  assert.equal(evidence.requirements.repeaterReady, true);
  assert.equal(evidence.requirements.intruderReady, true);
  assert.equal(evidence.requirements.scannerReady, true);
  assert.equal(evidence.requirements.rawOperationalSecretsPreserved, true);
  assert.equal(evidence.reportRedactionBoundary, 'redact-only-during-report-export');
  assert.match(evidence.content, /macro-stale-token|macro-api-secret|macro-csrf-secret|macro-session-secret|macro-nonce-secret/);

  await fs.writeFile(path.join(artifactRoot, 'session-macro-evidence-package.json'), evidence.content, 'utf8');
  console.log('session-macro-engine: executed scoped macro refresh, extracted tokens, merged cookies, and applied refreshed session to Repeater, Intruder, and Scanner requests');
} finally {
  await close(server).catch(() => undefined);
}

async function listen(target) {
  await new Promise((resolve, reject) => {
    target.once('error', reject);
    target.listen(0, '127.0.0.1', resolve);
  });
  return target.address().port;
}

async function close(target) {
  await new Promise((resolve, reject) => {
    target.close((error) => {
      if (error && error.code !== 'ERR_SERVER_NOT_RUNNING') reject(error);
      else resolve();
    });
  });
}
