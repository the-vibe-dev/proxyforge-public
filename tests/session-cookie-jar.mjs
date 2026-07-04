import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const {
  SharedCookieJar,
  buildSharedCookieJarEvidencePackage,
} = require('../dist-electron/sessionEngine.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/session-cookie-jar', `${Date.now()}-${process.pid}`);
await fs.mkdir(artifactRoot, { recursive: true });

const jar = new SharedCookieJar();
const captures = [];
captures.push(jar.captureFromSetCookie([
  'pf_session=jar-session-secret; Path=/; HttpOnly; Secure; SameSite=Lax',
  'pf_csrf=jar-csrf-secret; Path=/csrf; SameSite=Lax',
  'global_shop=jar-global-secret; Domain=.shop.local; Path=/; Secure',
  'expired=gone; Max-Age=0; Path=/',
], 'https://app.shop.local/login', 'proxy-response'));
captures.push(jar.captureFromCookieHeader(
  'api_seen=jar-api-secret; theme=dark',
  'https://api.shop.local/api/profile',
  'proxy-request',
));

assert.equal(jar.size, 5);
assert.deepEqual(captures[0].addedCookies, ['pf_session', 'pf_csrf', 'global_shop']);
assert.deepEqual(captures[0].updatedCookies, ['expired']);
assert(captures[0].operationalSecretSignals.includes('session-cookie'));
assert(captures[0].operationalSecretSignals.includes('csrf-cookie'));
assert(captures[1].operationalSecretSignals.includes('operational-secret-material'));

const appCsrfCookie = jar.cookieHeaderForUrl('https://app.shop.local/csrf/transfer');
assert.match(appCsrfCookie, /pf_session=jar-session-secret/);
assert.match(appCsrfCookie, /pf_csrf=jar-csrf-secret/);
assert.match(appCsrfCookie, /global_shop=jar-global-secret/);
assert.doesNotMatch(appCsrfCookie, /api_seen=jar-api-secret/);

const appHttpCookie = jar.cookieHeaderForUrl('http://app.shop.local/csrf/transfer');
assert.doesNotMatch(appHttpCookie, /pf_session=jar-session-secret/);
assert.match(appHttpCookie, /pf_csrf=jar-csrf-secret/);
assert.doesNotMatch(appHttpCookie, /global_shop=jar-global-secret/);

const apiCookie = jar.cookieHeaderForUrl('https://api.shop.local/api/profile');
assert.match(apiCookie, /api_seen=jar-api-secret/);
assert.match(apiCookie, /theme=dark/);
assert.match(apiCookie, /global_shop=jar-global-secret/);
assert.doesNotMatch(apiCookie, /pf_session=jar-session-secret/);

const repeaterApplied = jar.applyToRawRequest([
  'POST /csrf/transfer HTTP/1.1',
  'Host: app.shop.local',
  'Cookie: stale=1; pf_session=old',
  'Content-Type: application/json',
  '',
  '{"amount":10}',
].join('\r\n'), 'https://app.shop.local/csrf/transfer', { mode: 'merge' });
assert.equal(repeaterApplied.trace.applied, true);
assert(repeaterApplied.trace.replacedCookies.includes('pf_session'));
assert(repeaterApplied.trace.addedCookies.includes('pf_csrf'));
assert(repeaterApplied.trace.addedCookies.includes('global_shop'));
assert.match(repeaterApplied.rawRequest, /stale=1/);
assert.match(repeaterApplied.rawRequest, /pf_session=jar-session-secret/);
assert.match(repeaterApplied.rawRequest, /pf_csrf=jar-csrf-secret/);

const intruderApplied = jar.applyToRawRequest([
  'GET /api/profile?role=§role§ HTTP/1.1',
  'Host: api.shop.local',
  '',
  '',
].join('\r\n'), 'https://api.shop.local/api/profile?role=admin', { mode: 'merge' });
assert.match(intruderApplied.rawRequest, /api_seen=jar-api-secret/);
assert.match(intruderApplied.rawRequest, /global_shop=jar-global-secret/);
assert.doesNotMatch(intruderApplied.rawRequest, /pf_session=jar-session-secret/);

const scannerApplied = jar.applyToRawRequest([
  'GET /csrf/transfer HTTP/1.1',
  'Host: app.shop.local',
  'Cookie: old=1',
  '',
  '',
].join('\r\n'), 'https://app.shop.local/csrf/transfer', { mode: 'replace' });
assert.doesNotMatch(scannerApplied.rawRequest, /old=1/);
assert.match(scannerApplied.rawRequest, /pf_session=jar-session-secret/);
assert.match(scannerApplied.rawRequest, /pf_csrf=jar-csrf-secret/);

const evidence = buildSharedCookieJarEvidencePackage({
  jar,
  captures,
  generatedAt: '2026-05-25T23:55:00.000Z',
  appliedRequests: [
    { tool: 'repeater', targetUrl: 'https://app.shop.local/csrf/transfer', rawRequest: repeaterApplied.rawRequest, trace: repeaterApplied.trace },
    { tool: 'intruder', targetUrl: 'https://api.shop.local/api/profile?role=admin', rawRequest: intruderApplied.rawRequest, trace: intruderApplied.trace },
    { tool: 'scanner', targetUrl: 'https://app.shop.local/csrf/transfer', rawRequest: scannerApplied.rawRequest, trace: scannerApplied.trace },
  ],
});
assert.equal(evidence.kind, 'proxyforge-shared-cookie-jar-evidence-package');
assert.equal(evidence.cookieCount, 5);
assert.equal(evidence.requirements.setCookieCaptureCovered, true);
assert.equal(evidence.requirements.requestCookieCaptureCovered, true);
assert.equal(evidence.requirements.domainPathRulesCovered, true);
assert.equal(evidence.requirements.secureTransportRulesCovered, true);
assert.equal(evidence.requirements.repeaterReady, true);
assert.equal(evidence.requirements.intruderReady, true);
assert.equal(evidence.requirements.scannerReady, true);
assert.equal(evidence.requirements.rawOperationalSecretsPreserved, true);
assert.equal(evidence.reportRedactionBoundary, 'redact-only-during-report-export');
assert.match(evidence.content, /jar-session-secret|jar-csrf-secret|jar-global-secret|jar-api-secret/);

await fs.writeFile(path.join(artifactRoot, 'shared-cookie-jar-evidence-package.json'), evidence.content, 'utf8');
console.log(`session-cookie-jar: captured ${jar.size} cookies and applied scoped jar material to Repeater, Intruder, and Scanner requests`);
