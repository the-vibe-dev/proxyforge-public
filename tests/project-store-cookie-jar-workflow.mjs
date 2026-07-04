import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { ProjectStore } = require('../dist-electron/projectStore.js');
const {
  SharedCookieJar,
  buildSharedCookieJarEvidencePackage,
} = require('../dist-electron/sessionEngine.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-cookie-jar-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'cookie-jar-workflow.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

const jar = new SharedCookieJar();
const captures = [
  jar.captureFromSetCookie([
    'pf_session=store-session-secret; Path=/; HttpOnly; Secure; SameSite=Lax',
    'pf_csrf=store-csrf-secret; Path=/csrf; SameSite=Lax',
    'global_shop=store-global-secret; Domain=.shop.local; Path=/; Secure',
  ], 'https://app.shop.local/login', 'proxy-response'),
  jar.captureFromCookieHeader('api_seen=store-api-secret; theme=dark', 'https://api.shop.local/api/profile', 'proxy-request'),
];

const store = await ProjectStore.create(projectDir, {
  projectName: 'Project Store Cookie Jar Workflow',
  projectId: 'project-store-cookie-jar-workflow',
});
await store.upsertSessionCookies(jar.all());
store.close();

let reopened;
try {
  reopened = await ProjectStore.open(projectDir);
  const stats = reopened.stats();
  assert.equal(stats.sessionCookieCount, 5);

  const cookies = reopened.listSessionCookies({ limit: 20 });
  assert.equal(cookies.length, 5);
  assert.deepEqual(cookies.map((cookie) => `${cookie.domain}${cookie.path}:${cookie.name}`), [
    'api.shop.local/api:api_seen',
    'api.shop.local/api:theme',
    'app.shop.local/:pf_session',
    'app.shop.local/csrf:pf_csrf',
    'shop.local/:global_shop',
  ]);

  const session = reopened.getSessionCookie('app.shop.local', '/', 'pf_session');
  assert(session);
  assert.equal(session.secure, true);
  assert.equal(session.httpOnly, true);
  assert.equal(session.hostOnly, true);
  assert.equal(session.valueSha256, sha256('store-session-secret'));
  assert.equal(session.value, 'store-session-secret');

  const secretMatches = reopened.listSessionCookies({ text: 'store-api-secret' });
  assert.equal(secretMatches.length, 1);
  assert.equal(secretMatches[0].name, 'api_seen');

  const domainCookies = reopened.listSessionCookies({ hostOnly: false });
  assert.equal(domainCookies.length, 1);
  assert.equal(domainCookies[0].name, 'global_shop');

  const persistedJar = new SharedCookieJar(cookies);
  const repeaterApplied = persistedJar.applyToRawRequest([
    'POST /csrf/transfer HTTP/1.1',
    'Host: app.shop.local',
    'Cookie: stale=1; pf_session=old',
    '',
    '{"amount":10}',
  ].join('\r\n'), 'https://app.shop.local/csrf/transfer', { mode: 'merge' });
  assert.match(repeaterApplied.rawRequest, /pf_session=store-session-secret/);
  assert.match(repeaterApplied.rawRequest, /pf_csrf=store-csrf-secret/);
  assert.match(repeaterApplied.rawRequest, /global_shop=store-global-secret/);

  const intruderApplied = persistedJar.applyToRawRequest([
    'GET /api/profile?role=§role§ HTTP/1.1',
    'Host: api.shop.local',
    '',
    '',
  ].join('\r\n'), 'https://api.shop.local/api/profile?role=admin', { mode: 'merge' });
  assert.match(intruderApplied.rawRequest, /api_seen=store-api-secret/);
  assert.match(intruderApplied.rawRequest, /global_shop=store-global-secret/);
  assert.doesNotMatch(intruderApplied.rawRequest, /pf_session=store-session-secret/);

  const scannerApplied = persistedJar.applyToRawRequest([
    'GET /csrf/transfer HTTP/1.1',
    'Host: app.shop.local',
    'Cookie: old=1',
    '',
    '',
  ].join('\r\n'), 'https://app.shop.local/csrf/transfer', { mode: 'replace' });
  assert.doesNotMatch(scannerApplied.rawRequest, /old=1/);
  assert.match(scannerApplied.rawRequest, /pf_session=store-session-secret/);
  assert.match(scannerApplied.rawRequest, /pf_csrf=store-csrf-secret/);

  const projectEvidence = reopened.exportSessionCookieJarEvidence({ limit: 20 });
  assert.equal(projectEvidence.kind, 'proxyforge-project-store-cookie-jar-evidence-package');
  assert.equal(projectEvidence.stats.cookieCount, 5);
  assert.equal(projectEvidence.stats.domainCount, 3);
  assert.equal(projectEvidence.stats.secureCount, 4);
  assert.equal(projectEvidence.stats.hostOnlyCount, 4);
  assert.equal(projectEvidence.requirements.cookiesPersisted, true);
  assert.equal(projectEvidence.requirements.domainPathRulesRepresented, true);
  assert.equal(projectEvidence.requirements.secureCookiesRepresented, true);
  assert.equal(projectEvidence.requirements.hostOnlyAndDomainCookiesRepresented, true);
  assert.equal(projectEvidence.requirements.rawOperationalSecretsPreserved, true);
  assert.equal(projectEvidence.reportRedactionBoundary, 'redact-only-during-report-export');
  assert.match(projectEvidence.content, /store-session-secret|store-csrf-secret|store-global-secret|store-api-secret/);

  const runtimeEvidence = buildSharedCookieJarEvidencePackage({
    jar: persistedJar,
    captures,
    generatedAt: '2026-05-26T00:05:00.000Z',
    appliedRequests: [
      { tool: 'repeater', targetUrl: 'https://app.shop.local/csrf/transfer', rawRequest: repeaterApplied.rawRequest, trace: repeaterApplied.trace },
      { tool: 'intruder', targetUrl: 'https://api.shop.local/api/profile?role=admin', rawRequest: intruderApplied.rawRequest, trace: intruderApplied.trace },
      { tool: 'scanner', targetUrl: 'https://app.shop.local/csrf/transfer', rawRequest: scannerApplied.rawRequest, trace: scannerApplied.trace },
    ],
  });
  assert.equal(runtimeEvidence.requirements.repeaterReady, true);
  assert.equal(runtimeEvidence.requirements.intruderReady, true);
  assert.equal(runtimeEvidence.requirements.scannerReady, true);
  assert.match(runtimeEvidence.content, /store-session-secret|store-csrf-secret|store-api-secret/);

  await fs.writeFile(path.join(artifactRoot, 'project-store-cookie-jar-evidence-package.json'), projectEvidence.content, 'utf8');
  await fs.writeFile(path.join(artifactRoot, 'shared-cookie-jar-reopened-evidence-package.json'), runtimeEvidence.content, 'utf8');
  console.log(`project-store-cookie-jar-workflow: persisted and reopened ${cookies.length} shared cookie(s) for Repeater, Intruder, and Scanner in ${projectDir}`);
} finally {
  reopened?.close();
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}
