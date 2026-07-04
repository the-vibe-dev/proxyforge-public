import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import http from 'node:http';

const require = createRequire(import.meta.url);
const { refreshSessionProfile } = require('../dist-electron/sessionProfileRefresh.js');

const refreshRequests = [];
const server = http.createServer((request, response) => {
  refreshRequests.push({
    url: request.url,
    authorization: request.headers.authorization,
    cookie: request.headers.cookie,
  });
  if (request.url !== '/session/refresh') {
    response.writeHead(404, { 'content-type': 'text/plain' });
    response.end('missing');
    return;
  }
  response.writeHead(204, {
    'set-cookie': [
      'session=live-session; Path=/; HttpOnly; SameSite=Lax; Expires=Wed, 31 Dec 2036 23:59:59 GMT',
      'csrf=live-csrf; Path=/; SameSite=Lax',
    ],
    'x-refresh-lane': 'session-profile',
  });
  response.end();
});

try {
  const port = await listen(server);
  const profile = {
    id: 'session-live-refresh',
    name: 'Live Refresh Operator',
    role: 'support',
    targetUrl: `http://127.0.0.1:${port}/app`,
    refreshUrl: `http://127.0.0.1:${port}/session/refresh`,
    source: 'browser',
    status: 'stale',
    headerText: 'Authorization: Bearer stale-token\nX-ProxyForge-Role: support',
    cookieText: 'session=expired-session; theme=dark',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    headerCount: 0,
    cookieCount: 0,
    notes: 'Needs live refresh validation.',
  };

  const result = await refreshSessionProfile({ profile, timeoutMs: 2000 });
  assert.equal(result.status, 'refreshed');
  assert.equal(result.statusCode, 204);
  assert.equal(result.setCookieCount, 2);
  assert.equal(result.profile.status, 'ready');
  assert.equal(result.profile.refreshStatus, 'refreshed');
  assert.match(result.profile.refreshMessage, /Refreshed 2 cookie values/);
  assert.match(result.profile.cookieText, /session=live-session/);
  assert.match(result.profile.cookieText, /csrf=live-csrf/);
  assert.match(result.profile.cookieText, /theme=dark/);
  assert.match(result.profile.expiresAt ?? '', /^2036-12-31/);
  assert.equal(result.cookieCount, 3);
  assert.equal(result.headerCount, 3);
  assert.match(result.rawResponseHead, /Set-Cookie: session=live-session/i);

  assert.equal(refreshRequests.length, 1);
  assert.equal(refreshRequests[0].url, '/session/refresh');
  assert.equal(refreshRequests[0].authorization, 'Bearer stale-token');
  assert.match(refreshRequests[0].cookie, /session=expired-session/);

  await close(server);
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
