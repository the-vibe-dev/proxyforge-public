import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { createRequire } from 'node:module';
import { createCipheriv, pbkdf2Sync } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';

const require = createRequire(import.meta.url);
const { buildFirefoxProxyPrefs, buildLaunchPlan, buildManagedBrowserLaunchMatrix } = require('../dist-electron/browserLauncher.js');
const { buildBrowserCookieReadinessReport, extractBrowserCookies } = require('../dist-electron/browserCookies.js');

const tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'proxyforge-browser-launcher-'));

try {
  const chromiumProfile = path.join(tempDir, 'chromium-profile');
  const chromiumPlan = await buildLaunchPlan({
    candidate: { family: 'chromium', name: 'Chromium Test', command: '/opt/chromium' },
    targetUrl: 'https://app.shop.local/login',
    proxyHost: '127.0.0.1',
    proxyPort: 8080,
    profilePath: chromiumProfile,
    ignoreCertificateErrors: true,
  });

  assert.equal(chromiumPlan.candidate.family, 'chromium');
  assert(chromiumPlan.args.includes(`--user-data-dir=${chromiumProfile}`));
  assert(chromiumPlan.args.includes('--proxy-server=http=127.0.0.1:8080;https=127.0.0.1:8080'));
  assert(chromiumPlan.args.includes('--ignore-certificate-errors'));
  assert.equal(chromiumPlan.args.at(-1), 'https://app.shop.local/login');

  const firefoxProfile = path.join(tempDir, 'firefox-profile');
  await fs.mkdir(firefoxProfile, { recursive: true });
  const firefoxPlan = await buildLaunchPlan({
    candidate: { family: 'firefox', name: 'Firefox Test', command: '/opt/firefox' },
    targetUrl: 'https://app.shop.local/login',
    proxyHost: '127.0.0.1',
    proxyPort: 8081,
    profilePath: firefoxProfile,
    ignoreCertificateErrors: false,
  });

  assert.deepEqual(firefoxPlan.args, ['-no-remote', '-new-instance', '-profile', firefoxProfile, 'https://app.shop.local/login']);
  const firefoxPrefs = await fs.readFile(path.join(firefoxProfile, 'user.js'), 'utf8');
  assert.match(firefoxPrefs, /network\.proxy\.type", 1/);
  assert.match(firefoxPrefs, /network\.proxy\.ssl", "127\.0\.0\.1"/);
  assert.match(firefoxPrefs, /network\.proxy\.ssl_port", 8081/);
  assert.match(buildFirefoxProxyPrefs('127.0.0.1', 8081), /security\.enterprise_roots\.enabled", true/);

  const launchMatrix = buildManagedBrowserLaunchMatrix({
    targetUrl: 'app.shop.local/login',
    proxyHost: '127.0.0.1',
    proxyPort: 8080,
    profileBaseDir: '${PROXYFORGE_USER_DATA}/browser-profiles',
    platforms: ['linux', 'win32'],
    families: ['chromium', 'chrome', 'edge', 'firefox'],
    createdAt: '2026-05-24T17:00:00.000Z',
  });
  assert.equal(launchMatrix.reportReady, true);
  assert.equal(launchMatrix.entryCount, 8);
  assert.equal(launchMatrix.linuxEntryCount, 4);
  assert.equal(launchMatrix.windowsEntryCount, 4);
  assert.equal(launchMatrix.firefoxEntryCount, 2);
  assert.equal(launchMatrix.chromiumEntryCount, 6);
  assert.match(launchMatrix.summary, /Linux\/Windows launch profile/i);
  assert.match(launchMatrix.content, /proxyforge-managed-browser-launch-matrix|Google Chrome|Microsoft Edge|Firefox|chromium-network-sqlite|firefox-sqlite/);
  const windowsEdge = launchMatrix.entries.find((entry) => entry.platform === 'win32' && entry.family === 'edge');
  assert(windowsEdge, 'expected Windows Edge launch matrix entry');
  assert.equal(windowsEdge.evidence.windowsPathCovered, true);
  assert(windowsEdge.args.some((arg) => arg.includes('--proxy-server=http=127.0.0.1:8080;https=127.0.0.1:8080')));
  assert(windowsEdge.args.some((arg) => arg.startsWith('--user-data-dir=')));
  const linuxFirefox = launchMatrix.entries.find((entry) => entry.platform === 'linux' && entry.family === 'firefox');
  assert(linuxFirefox, 'expected Linux Firefox launch matrix entry');
  assert.equal(linuxFirefox.proxyMode, 'firefox-prefs');
  assert.equal(linuxFirefox.certificateMode, 'enterprise-roots');
  assert.equal(linuxFirefox.cookieStore, 'firefox-sqlite');
  assert.equal(linuxFirefox.evidence.proxyConfigured, true);
  assert.equal(linuxFirefox.evidence.certWorkflowReady, true);
  assert.equal(linuxFirefox.evidence.cookieExtractionReady, true);

  const chromiumCookieDir = path.join(chromiumProfile, 'Default', 'Network');
  await fs.mkdir(chromiumCookieDir, { recursive: true });
  const chromiumKey = Buffer.from('00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff', 'hex');
  await fs.writeFile(path.join(chromiumProfile, 'Local State'), JSON.stringify({
    os_crypt: {
      encrypted_key: chromiumKey.toString('base64'),
    },
  }), 'utf8');
  const encryptedRefreshCookie = encryptChromiumCookie(chromiumKey, 'chrome-refresh');
  const encryptedLegacyCookie = encryptChromiumLegacyCookie('peanuts', 'legacy-linux-session');
  const chromiumCookieDb = new DatabaseSync(path.join(chromiumCookieDir, 'Cookies'));
  chromiumCookieDb.exec(`
    create table cookies (
      host_key text,
      name text,
      value text,
      encrypted_value blob,
      path text,
      expires_utc integer,
      is_secure integer,
      is_httponly integer,
      samesite integer
    );
    insert into cookies values ('.shop.local', 'session', 'chrome-session', x'', '/', 0, 1, 1, 1);
    insert into cookies values ('app.shop.local', 'csrf', 'chrome-csrf', x'', '/', 0, 1, 0, 1);
    insert into cookies values ('app.shop.local', 'refresh', '', x'${encryptedRefreshCookie.toString('hex')}', '/', 0, 1, 1, 1);
    insert into cookies values ('app.shop.local', 'legacy', '', x'${encryptedLegacyCookie.toString('hex')}', '/', 0, 1, 1, 1);
    insert into cookies values ('app.shop.local', 'encrypted', '', x'010203', '/', 0, 1, 1, 1);
    insert into cookies values ('api.other.local', 'other', 'skip-me', x'', '/', 0, 1, 0, 1);
  `);
  chromiumCookieDb.close();

  const chromiumCookies = await extractBrowserCookies({
    targetUrl: 'https://app.shop.local/dashboard',
    browser: 'chromium',
    profilePath: chromiumProfile,
  });
  assert.equal(chromiumCookies.status, 'partial');
  assert.equal(chromiumCookies.cookieCount, 4);
  assert.equal(chromiumCookies.decryptedCount, 2);
  assert.equal(chromiumCookies.encryptedCount, 1);
  assert.equal(chromiumCookies.cookieHeader, 'session=chrome-session; csrf=chrome-csrf; refresh=chrome-refresh; legacy=legacy-linux-session');
  assert(!chromiumCookies.cookieHeader.includes('skip-me'));

  const firefoxCookieDb = new DatabaseSync(path.join(firefoxProfile, 'cookies.sqlite'));
  firefoxCookieDb.exec(`
    create table moz_cookies (
      host text,
      name text,
      value text,
      path text,
      expiry integer,
      isSecure integer,
      isHttpOnly integer,
      sameSite integer
    );
    insert into moz_cookies values ('.shop.local', 'session', 'firefox-session', '/', 2147483647, 1, 1, 1);
    insert into moz_cookies values ('app.shop.local', 'theme', 'dark', '/', 2147483647, 0, 0, 0);
    insert into moz_cookies values ('app.shop.local', 'admin-only', 'skip-path', '/admin', 2147483647, 1, 0, 1);
  `);
  firefoxCookieDb.close();

  const firefoxCookies = await extractBrowserCookies({
    targetUrl: 'https://app.shop.local/dashboard',
    browser: 'firefox',
    profilePath: firefoxProfile,
  });
  assert.equal(firefoxCookies.status, 'complete');
  assert.equal(firefoxCookies.cookieCount, 2);
  assert.equal(firefoxCookies.cookieHeader, 'session=firefox-session; theme=dark');
  assert(!firefoxCookies.cookieHeader.includes('skip-path'));

  const readinessReport = await buildBrowserCookieReadinessReport({
    targetUrl: 'https://app.shop.local/dashboard',
    browser: 'auto',
    profilePath: tempDir,
  }, '2026-05-24T17:15:00.000Z');
  assert.equal(readinessReport.reportReady, true);
  assert.equal(readinessReport.sqliteAvailable, true);
  assert.equal(readinessReport.databaseCount >= 2, true);
  assert.equal(readinessReport.chromiumDatabaseCount >= 1, true);
  assert.equal(readinessReport.firefoxDatabaseCount >= 1, true);
  assert.equal(readinessReport.capabilityCount, 5);
  assert.equal(readinessReport.readyCapabilityCount >= 3, true);
  assert.equal(readinessReport.hostVerificationRequiredCount >= 1, true);
  assert.match(readinessReport.summary, /Cookie readiness found/i);
  assert.match(readinessReport.content, /proxyforge-browser-cookie-readiness-report|Chromium AES-GCM|Windows DPAPI|Linux Secret Service|Firefox cookies\.sqlite/i);
  assert.doesNotMatch(readinessReport.content, /chrome-refresh|legacy-linux-session|firefox-session|0011223344556677/i);
  const aesCapability = readinessReport.capabilities.find((capability) => capability.id === 'chromium-local-state-aes-gcm');
  assert(aesCapability, 'expected Chromium AES-GCM capability');
  assert.equal(aesCapability.status, 'ready');
  assert.match(aesCapability.secretHandling, /key presence|excluded|not/i);
  const dpapiCapability = readinessReport.capabilities.find((capability) => capability.id === 'chromium-windows-dpapi');
  assert(dpapiCapability, 'expected Windows DPAPI capability');
  assert.equal(dpapiCapability.status, 'needs-host-verification');
  const firefoxCapability = readinessReport.capabilities.find((capability) => capability.id === 'firefox-sqlite');
  assert(firefoxCapability, 'expected Firefox capability');
  assert.equal(firefoxCapability.status, 'ready');
} finally {
  await fs.rm(tempDir, { recursive: true, force: true });
}

function encryptChromiumCookie(key, value) {
  const nonce = Buffer.from('0102030405060708090a0b0c', 'hex');
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const encrypted = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  return Buffer.concat([Buffer.from('v10'), nonce, encrypted, cipher.getAuthTag()]);
}

function encryptChromiumLegacyCookie(password, value) {
  const key = pbkdf2Sync(password, 'saltysalt', 1, 16, 'sha1');
  const cipher = createCipheriv('aes-128-cbc', key, Buffer.alloc(16, 0x20));
  return Buffer.concat([Buffer.from('v10'), cipher.update(value, 'utf8'), cipher.final()]);
}
