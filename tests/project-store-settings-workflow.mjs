import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';

const require = createRequire(import.meta.url);
const { ProjectStore } = require('../dist-electron/projectStore.js');

const artifactRoot = path.resolve('.gitignored/test-artifacts/project-store-settings-workflow', `${Date.now()}-${process.pid}`);
const projectDir = path.join(artifactRoot, 'settings-workflow.proxyforge');
await fs.mkdir(artifactRoot, { recursive: true });

const store = await ProjectStore.create(projectDir, {
  projectName: 'Project Store Settings Workflow',
  projectId: 'project-store-settings-workflow',
});

await store.upsertProjectSettings([
  {
    category: 'scope',
    key: 'default-scope',
    source: 'settings-regression',
    value: {
      include: ['app.shop.local', 'api.shop.local'],
      exclude: ['*.third-party.local'],
      defaultAction: 'block-active',
    },
  },
  {
    category: 'proxy',
    key: 'listener-main',
    source: 'settings-regression',
    value: {
      listenHost: '127.0.0.1',
      listenPort: 8080,
      upstreamProxy: {
        url: 'http://upstream.proxy.local:8081',
        authorization: 'Bearer settings-proxy-upstream-token',
        noProxy: ['localhost', '127.0.0.1'],
      },
      mitm: {
        projectCaFingerprint: 'settings-project-ca-fingerprint',
        browserTrustMode: 'project-ca-required',
      },
    },
  },
  {
    category: 'scanner',
    key: 'active-profile',
    source: 'settings-regression',
    value: {
      insertionPointPolicy: ['query', 'body', 'json', 'header', 'cookie'],
      activeChecks: ['reflected-xss', 'ssrf-oast', 'authz-diff'],
      maxRequestsPerHost: 125,
      throttleMs: 25,
    },
  },
  {
    category: 'sessions',
    key: 'admin-role',
    source: 'settings-regression',
    value: {
      selectedSessionProfileId: 'session-admin-settings',
      profiles: [{
        id: 'session-admin-settings',
        role: 'admin',
        headerText: 'Authorization: Bearer settings-session-token',
        cookieText: 'session=settings-session; csrf=settings-csrf',
        refreshUrl: 'https://app.shop.local/session/refresh',
      }],
    },
  },
  {
    category: 'oast',
    key: 'local-collaborator',
    source: 'settings-regression',
    value: {
      listenerId: 'settings-oast-runtime',
      protocols: ['http', 'dns', 'smtp'],
      signingKeyId: 'settings-oast-signing-key',
      relayToken: 'settings-oast-relay-token',
      retentionHours: 72,
    },
  },
  {
    category: 'reports',
    key: 'submission-export',
    enabled: false,
    source: 'settings-regression',
    value: {
      formats: ['markdown', 'html', 'json', 'pdf', 'bundle'],
      redactionBoundary: 'report-export-only',
      defaultRedactions: ['Authorization', 'Cookie', 'X-API-Key'],
      verifier: 'hmac-sha256',
    },
  },
  {
    category: 'network',
    key: 'timeouts-and-dns',
    source: 'settings-regression',
    value: {
      timeoutMs: 15000,
      dnsMode: 'system-plus-oast',
      tlsVerification: 'project-ca',
      proxyCredentials: {
        username: 'settings-network-user',
        password: 'settings-network-password',
      },
    },
  },
]);

const initialProxy = store.getProjectSetting('proxy', 'listener-main');
assert(initialProxy);
assert.equal(initialProxy.source, 'settings-regression');
assert.match(JSON.stringify(initialProxy.value), /settings-proxy-upstream-token/);
const initialProxyHash = initialProxy.valueSha256;

await store.upsertProjectSetting({
  category: 'proxy',
  key: 'listener-main',
  source: 'settings-regression-update',
  value: {
    listenHost: '127.0.0.1',
    listenPort: 8080,
    upstreamProxy: {
      url: 'http://upstream.proxy.local:8081',
      authorization: 'Bearer settings-proxy-upstream-token-rotated',
      noProxy: ['localhost', '127.0.0.1', 'metadata.local'],
    },
    mitm: {
      projectCaFingerprint: 'settings-project-ca-fingerprint',
      browserTrustMode: 'project-ca-required',
    },
  },
});

store.close();

let reopened;
try {
  reopened = await ProjectStore.open(projectDir);
  const stats = reopened.stats();
  assert.equal(stats.projectSettingCount, 7);

  const settings = reopened.listProjectSettings({ limit: 20 });
  assert.equal(settings.length, 7);
  assert.deepEqual(settings.map((setting) => setting.category), ['network', 'oast', 'proxy', 'reports', 'scanner', 'scope', 'sessions']);

  const proxy = reopened.getProjectSetting('proxy', 'listener-main');
  assert(proxy);
  assert.equal(proxy.source, 'settings-regression-update');
  assert.notEqual(proxy.valueSha256, initialProxyHash);
  assert.match(JSON.stringify(proxy.value), /settings-proxy-upstream-token-rotated|metadata\.local/);
  assert.equal(proxy.valueSha256, sha256(canonicalize(proxy.value)));

  const sessionMatches = reopened.listProjectSettings({ text: 'settings-session-token' });
  assert.equal(sessionMatches.length, 1);
  assert.equal(sessionMatches[0].category, 'sessions');
  assert.match(JSON.stringify(sessionMatches[0].value), /settings-session; csrf=settings-csrf/);

  const disabled = reopened.listProjectSettings({ enabled: false });
  assert.equal(disabled.length, 1);
  assert.equal(disabled[0].category, 'reports');

  const packageResult = reopened.exportProjectSettingsEvidence({ limit: 20 });
  assert.equal(packageResult.kind, 'proxyforge-project-store-settings-evidence-package');
  assert.equal(packageResult.stats.settingCount, 7);
  assert.equal(packageResult.stats.categoryCount, 7);
  assert.equal(packageResult.stats.enabledCount, 6);
  assert.equal(packageResult.stats.disabledCount, 1);
  assert.equal(packageResult.requirements.scopeSettingsIncluded, true);
  assert.equal(packageResult.requirements.proxySettingsIncluded, true);
  assert.equal(packageResult.requirements.scannerSettingsIncluded, true);
  assert.equal(packageResult.requirements.sessionSettingsIncluded, true);
  assert.equal(packageResult.requirements.oastSettingsIncluded, true);
  assert.equal(packageResult.requirements.reportSettingsIncluded, true);
  assert.equal(packageResult.requirements.networkSettingsIncluded, true);
  assert.equal(packageResult.requirements.rawOperationalSecretsPreserved, true);
  assert.equal(packageResult.requirements.restartReady, true);
  assert.equal(packageResult.reportRedactionBoundary, 'redact-only-during-report-export');
  assert.match(packageResult.content, /settings-proxy-upstream-token-rotated|settings-session-token|settings-oast-relay-token|settings-network-password/);

  await fs.writeFile(path.join(artifactRoot, 'project-store-settings-evidence-package.json'), packageResult.content, 'utf8');
  console.log(`project-store-settings-workflow: persisted ${settings.length} project settings across ${packageResult.stats.categoryCount} categories with restart/export proof in ${projectDir}`);
} finally {
  reopened?.close();
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalize(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).filter((key) => value[key] !== undefined).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalize(value[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}
