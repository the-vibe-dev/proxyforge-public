import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'parseProjectSnapshotContent',
  'parseProjectImportContent',
  'buildProjectMigrationReview',
  'buildProjectParityEvidencePackage',
];
const enginePath = path.resolve('electron/projectSnapshotEngine.ts');
const projectEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof projectEngine[name] !== 'function');
assert.deepEqual(missingExports, [], `project-parity-engine: missing export(s): ${missingExports.join(', ')}`);

const now = '2026-05-25T23:35:00.000Z';
const legacyContent = JSON.stringify(buildLegacyProject(), null, 2);
const migratedSnapshot = projectEngine.parseProjectSnapshotContent(legacyContent, now);
const migrationReview = projectEngine.buildProjectMigrationReview(legacyContent, now);

assert.equal(migratedSnapshot.version, 1);
assert.equal(migratedSnapshot.projectName, 'Shop Authz Migration');
assert.equal(JSON.stringify(migratedSnapshot.scopeAllowlist), JSON.stringify(['app.shop.local', 'api.shop.local']));
assert.equal(migratedSnapshot.exchanges.length, 2);
assert.match(migratedSnapshot.exchanges[0].requestRaw, /Authorization: Bearer project-secret-token/);
assert.equal(migratedSnapshot.sessionProfiles.length, 2);
assert.equal(
  JSON.stringify([...migrationReview.migratedFields].sort()),
  JSON.stringify(['sessions->sessionProfiles', 'targets->scopeAllowlist', 'traffic->exchanges'].sort()),
);

const legacyProxyRequestRaw = [
  'POST /api/imported/refund HTTP/1.1',
  'Host: legacy-proxy.shop.local',
  'Authorization: Bearer legacy-proxy-project-token',
  'Cookie: legacy_proxy_session=legacy-proxy-cookie',
  '',
  '{"amount":777,"apiKey":"legacy-extension-api-key"}',
].join('\r\n');
const legacyProxyResponseRaw = [
  'HTTP/1.1 202 Accepted',
  'Content-Type: application/json',
  '',
  '{"accepted":true,"token":"legacy-proxy-project-token"}',
].join('\r\n');
const legacyProxyXmlContent = [
  '<?xml version="1.0"?>',
  '<items>',
  '  <item>',
  '    <time>2026-05-25T23:36:00.000Z</time>',
  '    <url>https://legacy-proxy.shop.local/api/imported/refund</url>',
  '    <host>legacy-proxy.shop.local</host>',
  '    <port>443</port>',
  '    <protocol>https</protocol>',
  '    <method>POST</method>',
  '    <path>/api/imported/refund</path>',
  '    <status>202</status>',
  '    <mimetype>JSON</mimetype>',
  `    <request base64="true">${Buffer.from(legacyProxyRequestRaw).toString('base64')}</request>`,
  `    <response base64="true">${Buffer.from(legacyProxyResponseRaw).toString('base64')}</response>`,
  '  </item>',
  '</items>',
].join('\n');
const legacyProxyImport = projectEngine.parseProjectImportContent(legacyProxyXmlContent, now);
const legacyProxyReview = projectEngine.buildProjectMigrationReview(legacyProxyXmlContent, now);
assert.equal(legacyProxyImport.sourceFormat, 'legacy-proxy-xml');
assert.equal(legacyProxyImport.snapshot.exchanges.length, 1);
assert.equal(legacyProxyImport.snapshot.scopeAllowlist[0], 'legacy-proxy.shop.local');
assert.match(legacyProxyImport.snapshot.exchanges[0].requestRaw, /Authorization: Bearer legacy-proxy-project-token/);
assert.match(legacyProxyImport.snapshot.exchanges[0].responseRaw, /legacy-proxy-project-token/);
assert.equal(legacyProxyReview.sourceFormat, 'legacy-proxy-xml');
assert(legacyProxyReview.migratedFields.includes('legacy-proxy-xml->exchanges'));

const harContent = JSON.stringify({
  log: {
    entries: [{
      startedDateTime: '2026-05-25T23:37:00.000Z',
      time: 321,
      request: {
        method: 'POST',
        url: 'https://har.shop.local/api/search?q=har-secret',
        headers: [
          { name: 'Authorization', value: 'Bearer har-project-token' },
          { name: 'Cookie', value: 'har_session=har-cookie' },
        ],
        postData: { text: '{"apiKey":"har-api-key"}' },
      },
      response: {
        status: 207,
        statusText: 'Multi-Status',
        headers: [{ name: 'Content-Type', value: 'application/json' }],
        content: {
          mimeType: 'application/json',
          encoding: 'base64',
          text: Buffer.from('{"echo":"har-project-token","cookie":"har-cookie"}').toString('base64'),
        },
      },
    }],
  },
}, null, 2);
const harImport = projectEngine.parseProjectImportContent(harContent, now);
assert.equal(harImport.sourceFormat, 'har');
assert.equal(harImport.snapshot.exchanges[0].host, 'har.shop.local');
assert.equal(harImport.snapshot.exchanges[0].status, 207);
assert.match(harImport.snapshot.exchanges[0].requestRaw, /Bearer har-project-token/);
assert.match(harImport.snapshot.exchanges[0].responseRaw, /har-cookie/);

const rawHttpContent = [
  'GET /raw/import?q=raw-secret HTTP/1.1',
  'Host: raw.shop.local',
  'Authorization: Bearer raw-project-token',
  '',
  '',
  '--- response ---',
  'HTTP/1.1 200 OK',
  'Content-Type: text/plain',
  '',
  'raw-project-token raw-cookie',
].join('\n');
const rawImport = projectEngine.parseProjectImportContent(rawHttpContent, now);
assert.equal(rawImport.sourceFormat, 'raw-http');
assert.equal(rawImport.snapshot.exchanges[0].url, 'https://raw.shop.local/raw/import?q=raw-secret');
assert.match(rawImport.snapshot.exchanges[0].requestRaw, /Bearer raw-project-token/);
assert.match(rawImport.snapshot.exchanges[0].responseRaw, /raw-cookie/);

const jsonlContent = [
  JSON.stringify({ payload: { exchange: {
    id: 'hx-jsonl-import',
    requestRaw: 'POST /jsonl HTTP/1.1\r\nHost: jsonl.shop.local\r\nX-API-Key: jsonl-api-key\r\n\r\njsonl-secret',
    responseRaw: 'HTTP/1.1 201 Created\r\nContent-Type: application/json\r\n\r\n{"key":"jsonl-api-key"}',
  } } }),
  JSON.stringify({ exchange: {
    id: 'hx-jsonl-import-2',
    requestRaw: 'GET /jsonl/second HTTP/1.1\r\nHost: jsonl.shop.local\r\nCookie: jsonl_session=jsonl-cookie\r\n\r\n',
    responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\njsonl-cookie',
  } }),
].join('\n');
const jsonlImport = projectEngine.parseProjectImportContent(jsonlContent, now);
assert.equal(jsonlImport.sourceFormat, 'agent-jsonl');
assert.equal(jsonlImport.snapshot.exchanges[0].method, 'POST');
assert.equal(jsonlImport.snapshot.exchanges[0].host, 'jsonl.shop.local');
assert.match(jsonlImport.snapshot.exchanges[0].requestRaw, /jsonl-api-key/);

const savedSnapshot = {
  ...migratedSnapshot,
  savedAt: now,
  selectedSessionProfileId: 'session-browser-admin',
  browserLaunches: [
    {
      id: 'browser-launch-linux-chrome',
      status: 'launched',
      browser: 'chrome',
      browserName: 'Google Chrome',
      targetUrl: 'https://app.shop.local/admin',
      proxyHost: '127.0.0.1',
      proxyPort: 8080,
      profilePath: '/tmp/proxyforge-browser-profiles/linux-chrome',
      command: '/usr/bin/google-chrome-stable',
      args: ['--user-data-dir=/tmp/proxyforge-browser-profiles/linux-chrome', '--proxy-server=http=127.0.0.1:8080;https=127.0.0.1:8080'],
      startedAt: now,
      message: 'Chrome launched through ProxyForge.',
    },
  ],
};
const exportedProjectContent = JSON.stringify(savedSnapshot, null, 2);
const importedSnapshot = projectEngine.parseProjectSnapshotContent(exportedProjectContent, now);
const restoredSnapshot = projectEngine.parseProjectSnapshotContent(exportedProjectContent, now);
const parityPackage = projectEngine.buildProjectParityEvidencePackage({
  savedSnapshot,
  restoredSnapshot,
  exportedProjectContent,
  importedProjectContent: exportedProjectContent,
  importedSnapshot,
  projectFileArtifact: {
    fileName: 'shop-authz-migration.proxyforge.json',
    path: '/tmp/shop-authz-migration.proxyforge.json',
    exportedAt: now,
    projectName: savedSnapshot.projectName,
    exchangeCount: savedSnapshot.exchanges.length,
    scopeCount: savedSnapshot.scopeAllowlist.length,
    sizeBytes: Buffer.byteLength(exportedProjectContent, 'utf8'),
  },
  migrationReviews: [migrationReview, legacyProxyReview],
  browserLaunchMatrix: buildBrowserLaunchMatrix(),
  cookieReadinessReport: buildCookieReadinessReport(),
  browserCookieCaptures: [
    {
      id: 'cookie-capture-project-1',
      status: 'partial',
      targetUrl: 'https://app.shop.local/admin',
      browser: 'chromium',
      profilePath: '/tmp/proxyforge-browser-profiles/linux-chrome',
      cookieHeader: 'session=project-session; refresh=project-refresh; csrf=project-csrf',
      cookieCount: 3,
      decryptedCount: 2,
      encryptedCount: 1,
      skippedCount: 0,
      cookies: [
        { name: 'session', value: 'project-session', domain: '.shop.local', path: '/', source: 'chromium' },
        { name: 'refresh', value: 'project-refresh', domain: 'app.shop.local', path: '/', source: 'chromium' },
        { name: 'csrf', value: 'project-csrf', domain: 'app.shop.local', path: '/', source: 'chromium' },
      ],
      message: 'Extracted 3 cookies for app.shop.local; decrypted 2; 1 encrypted value could not be read.',
    },
  ],
  operationalSecretSamples: ['project-secret-token', 'project-session', 'project-api-key', 'project-refresh'],
  exportedAt: now,
});
const parityContent = JSON.parse(parityPackage.content);

assert.equal(parityPackage.kind, 'proxyforge-project-parity-evidence-package');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.reportReady, true);
assert(Object.values(parityPackage.requirements).every(Boolean), 'all Project parity requirements should be true');
assert.equal(parityPackage.exchangeCount, 2);
assert.equal(parityPackage.scopeCount, 2);
assert.equal(parityPackage.sessionProfileCount, 2);
assert.equal(parityPackage.browserLaunchProfileCount, 8);
assert.equal(parityContent.kind, 'proxyforge-project-parity-evidence-package');
assert.match(parityPackage.content, /shop-authz-migration\.proxyforge\.json/);
assert.match(parityPackage.content, /targets->scopeAllowlist|traffic->exchanges|sessions->sessionProfiles/);
assert.match(parityPackage.content, /legacy-proxy-xml->exchanges/);
assert.match(parityPackage.content, /proxyforge-managed-browser-launch-matrix|linux|win32|firefox|chromium/);
assert.match(parityPackage.content, /proxyforge-browser-cookie-readiness-report|chromium-local-state-aes-gcm|chromium-windows-dpapi|chromium-linux-secret-service|firefox-sqlite/);
assert.match(parityPackage.content, /Authorization: Bearer project-secret-token/);
assert.match(parityPackage.content, /session=project-session/);
assert.match(parityPackage.content, /X-API-Key: project-api-key/);
assert.match(parityPackage.content, /project-refresh/);
assert.match(parityPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/project-parity-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'project-parity-evidence-package.json'), parityPackage.content);
await fs.writeFile(path.join(artifactDir, 'project-import-interop.json'), JSON.stringify({
  legacyProxyXml: legacyProxyImport,
  har: harImport,
  rawHttp: rawImport,
  jsonl: jsonlImport,
}, null, 2));

console.log('project-parity-engine: exercised project save/restore, .proxyforge.json migration, legacy proxy XML/HAR/raw HTTP/JSONL project import interop, browser launch profiles, cookie readiness, and full-fidelity project evidence');

async function loadEngine(filePath) {
  const source = await fs.readFile(filePath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: filePath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    Buffer,
    console,
    require,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: filePath });
  return module.exports;
}

function normalizeModuleExports(moduleExports) {
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}

function buildLegacyProject() {
  return {
    kind: 'proxyforge-project-legacy',
    schemaVersion: 0,
    name: 'Shop Authz Migration',
    targets: ['app.shop.local', 'api.shop.local'],
    traffic: [
      {
        id: 'hx-project-authz',
        method: 'POST',
        host: 'app.shop.local',
        path: '/api/admin/refunds',
        statusCode: 403,
        contentType: 'application/json',
        risk: 'high',
        request: [
          'POST /api/admin/refunds HTTP/1.1',
          'Host: app.shop.local',
          'Authorization: Bearer project-secret-token',
          'Cookie: session=project-session; refresh=project-refresh',
          'X-API-Key: project-api-key',
          '',
          '{"amount":1999,"token":"project-secret-token"}',
        ].join('\r\n'),
        response: [
          'HTTP/1.1 403 Forbidden',
          'Content-Type: application/json',
          '',
          '{"error":"forbidden","session":"project-session"}',
        ].join('\r\n'),
        tags: ['authz', 'project'],
      },
      {
        id: 'hx-project-profile',
        method: 'GET',
        host: 'api.shop.local',
        path: '/api/profile',
        statusCode: 200,
        contentType: 'application/json',
        risk: 'medium',
        request: [
          'GET /api/profile HTTP/1.1',
          'Host: api.shop.local',
          'Cookie: session=project-session',
          '',
          '',
        ].join('\r\n'),
        response: [
          'HTTP/1.1 200 OK',
          'Content-Type: application/json',
          '',
          '{"user":"admin","refresh":"project-refresh"}',
        ].join('\r\n'),
        tags: ['profile'],
      },
    ],
    sessions: [
      {
        id: 'session-browser-admin',
        name: 'Browser admin',
        role: 'admin',
        targetUrl: 'https://app.shop.local/admin',
        source: 'browser',
        status: 'ready',
        headers: 'Authorization: Bearer project-secret-token\r\nX-API-Key: project-api-key',
        cookies: 'session=project-session; refresh=project-refresh',
        notes: 'Captured from managed browser profile.',
      },
      {
        id: 'session-traffic-customer',
        name: 'Traffic customer',
        role: 'customer',
        targetUrl: 'https://app.shop.local/account',
        source: 'traffic',
        status: 'stale',
        headers: 'X-API-Key: project-api-key',
        cookies: 'session=project-session',
        notes: 'Needs refresh before replay.',
      },
    ],
    selectedSessionProfileId: 'session-browser-admin',
  };
}

function buildBrowserLaunchMatrix() {
  const entries = ['linux', 'win32'].flatMap((platform) => ['chromium', 'chrome', 'edge', 'firefox'].map((family) => ({
    platform,
    family,
    profilePath: platform === 'win32'
      ? `C:\\Users\\analyst\\AppData\\Local\\ProxyForge\\browser-profiles\\${family}`
      : `/tmp/proxyforge-browser-profiles/${family}`,
    proxyMode: family === 'firefox' ? 'firefox-prefs' : 'command-line',
    cookieStore: family === 'firefox' ? 'firefox-sqlite' : 'chromium-network-sqlite',
    certificateMode: family === 'firefox' ? 'enterprise-roots' : 'ignore-errors-flag',
    evidence: {
      isolatedProfile: true,
      proxyConfigured: true,
      certWorkflowReady: true,
      cookieExtractionReady: true,
      windowsPathCovered: platform === 'win32',
      linuxPathCovered: platform === 'linux',
    },
  })));
  const payload = {
    kind: 'proxyforge-managed-browser-launch-matrix',
    reportReady: true,
    entryCount: entries.length,
    linuxEntryCount: entries.filter((entry) => entry.platform === 'linux').length,
    windowsEntryCount: entries.filter((entry) => entry.platform === 'win32').length,
    firefoxEntryCount: entries.filter((entry) => entry.family === 'firefox').length,
    chromiumEntryCount: entries.filter((entry) => entry.family !== 'firefox').length,
    entries,
  };
  return { ...payload, content: JSON.stringify(payload, null, 2) };
}

function buildCookieReadinessReport() {
  const capabilities = [
    { id: 'chromium-local-state-aes-gcm', status: 'ready', platform: 'cross-platform', secretHandling: 'key bytes excluded from reports' },
    { id: 'chromium-windows-dpapi', status: 'needs-host-verification', platform: 'win32', secretHandling: 'DPAPI key bytes stay in memory' },
    { id: 'chromium-linux-secret-service', status: 'available', platform: 'linux', secretHandling: 'Secret Service output stays transient' },
    { id: 'chromium-linux-legacy', status: 'ready', platform: 'linux', secretHandling: 'legacy key excluded from reports' },
    { id: 'firefox-sqlite', status: 'ready', platform: 'cross-platform', secretHandling: 'cookie values stay executor-only' },
  ];
  const payload = {
    kind: 'proxyforge-browser-cookie-readiness-report',
    reportReady: true,
    sqliteAvailable: true,
    databaseCount: 2,
    chromiumDatabaseCount: 1,
    firefoxDatabaseCount: 1,
    capabilityCount: capabilities.length,
    readyCapabilityCount: 4,
    hostVerificationRequiredCount: 1,
    capabilities,
  };
  return { ...payload, content: JSON.stringify(payload, null, 2) };
}
