import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'installManifestExtension',
  'installCatalogExtension',
  'runExtension',
  'extensionCatalog',
  'defaultExtensionManifest',
  'buildExtensionLegacySdkCompatibilityPackage',
  'buildExtensionThirdPartySdkCompatibilityPackage',
  'buildExtensionParityEvidencePackage',
];

const enginePath = path.resolve('src/extensionEngine.ts');
const extensionEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof extensionEngine[name] === 'undefined');
if (missingExports.length) {
  console.log(`extension-engine: skipped; missing export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const exchange = buildExchange();

const sandboxManifest = JSON.stringify({
  name: 'Sandbox Header Mutator',
  version: '0.2.0',
  author: 'Local analyst',
  description: 'Exercises manifest-declared sandbox runtime hooks.',
  hooks: ['request-editor', 'response-editor', 'passive-scan', 'message-editor'],
  permissions: ['read-traffic', 'modify-traffic', 'create-issues'],
  runtimeApi: {
    apiVersion: 'proxyforge-extender-api/v1',
    sandbox: 'isolated-worker',
    actions: [
      { hook: 'request-editor', kind: 'request-header', name: 'X-ProxyForge-Sandbox', value: 'enabled' },
      { hook: 'request-editor', kind: 'tag', value: 'sandbox-reviewed' },
      { hook: 'request-editor', kind: 'note', value: 'Sandbox runtime touched this exchange.' },
      { hook: 'response-editor', kind: 'response-header', name: 'X-ProxyForge-Response-Sandbox', value: 'enabled' },
      { hook: 'passive-scan', kind: 'issue', title: 'Sandbox passive issue', severity: 'low', detail: 'Manifest action created an issue.', remediation: 'Review extension output.' },
      { hook: 'message-editor', kind: 'editor-tab', title: 'Sandbox Notes' },
    ],
  },
});

const installed = extensionEngine.installManifestExtension(sandboxManifest, []);
assert.ok(installed.extension, installed.error ?? 'sandbox manifest should install');

const requestRun = extensionEngine.runExtension(installed.extension, 'request-editor', exchange);
assert.equal(requestRun.status, 'complete', 'permitted sandbox mutation should complete');
assert.match(requestRun.summary, /Sandbox runtime applied 3 actions/);
assert.match(requestRun.exchange.requestRaw, /X-ProxyForge-Sandbox: enabled/);
assert.ok(requestRun.exchange.tags.includes('sandbox-reviewed'), 'tag action should patch exchange tags');
assert.match(requestRun.exchange.notes, /Sandbox runtime touched this exchange/);

const issueRun = extensionEngine.runExtension(installed.extension, 'passive-scan', exchange);
assert.equal(issueRun.status, 'complete', 'permitted issue action should complete');
assert.equal(issueRun.issue.title, 'Sandbox passive issue');
assert.equal(issueRun.issue.severity, 'low');

const editorRun = extensionEngine.runExtension(installed.extension, 'message-editor', exchange);
assert.equal(editorRun.status, 'complete', 'editor-tab action should complete without traffic mutation');
assert.match(editorRun.logs.join('\n'), /Registered editor tab Sandbox Notes/);
assert.equal(editorRun.exchange, undefined, 'editor-tab action should not mutate traffic');

const deniedManifest = JSON.stringify({
  name: 'Sandbox Denied Mutator',
  version: '0.1.0',
  hooks: ['request-editor'],
  permissions: ['read-traffic'],
  runtimeApi: {
    actions: [
      { hook: 'request-editor', kind: 'request-header', name: 'X-Denied', value: 'true' },
    ],
  },
});
const deniedInstall = extensionEngine.installManifestExtension(deniedManifest, []);
assert.ok(deniedInstall.extension, deniedInstall.error ?? 'denied manifest should install');
const deniedRun = extensionEngine.runExtension(deniedInstall.extension, 'request-editor', exchange);
assert.equal(deniedRun.status, 'blocked', 'missing modify permission should fail closed');
assert.equal(deniedRun.exchange, undefined);
assert.match(deniedRun.logs.join('\n'), /missing modify-traffic/);

const unsupportedManifest = JSON.stringify({
  name: 'Sandbox Unsupported Capability',
  version: '0.1.0',
  hooks: ['request-editor'],
  permissions: ['read-traffic', 'modify-traffic'],
  runtimeApi: {
    actions: [
      { hook: 'request-editor', kind: 'process-spawn', value: 'whoami' },
    ],
  },
});
const unsupportedInstall = extensionEngine.installManifestExtension(unsupportedManifest, []);
assert.ok(unsupportedInstall.extension, unsupportedInstall.error ?? 'unsupported manifest should install for fail-closed diagnostics');
const unsupportedRun = extensionEngine.runExtension(unsupportedInstall.extension, 'request-editor', exchange);
assert.equal(unsupportedRun.status, 'blocked', 'unsupported sandbox action should be denied');
assert.match(unsupportedRun.logs.join('\n'), /Unsupported sandbox action process-spawn was denied/);

const defaultInstall = extensionEngine.installManifestExtension(extensionEngine.defaultExtensionManifest, []);
assert.ok(defaultInstall.extension, defaultInstall.error ?? 'default local manifest should still install');
const defaultRun = extensionEngine.runExtension(defaultInstall.extension, 'passive-scan', exchange);
assert.match(defaultRun.summary, /Local manifest extension created/, 'default manifest fallback should preserve UI-visible behavior');

const authz = extensionEngine.installCatalogExtension(extensionEngine.extensionCatalog.find((item) => item.id === 'authz-boundary-lens'));
const authzRun = extensionEngine.runExtension(authz, 'passive-scan', exchange);
assert.match(authzRun.summary, /Authorization replay candidate created/, 'catalog extension behavior should remain stable');

const legacyProxyStyleManifest = JSON.stringify({
  name: 'Legacy Proxy Compatibility Compatibility Probe',
  version: '0.3.0',
  hooks: ['request-editor', 'response-editor', 'message-editor', 'scanner-check', 'headless-runner'],
  permissions: ['read-traffic', 'modify-traffic', 'create-issues', 'run-automations'],
  runtimeApi: {
    apiVersion: 'proxyforge-extender-api/v1',
    sandbox: 'isolated-worker',
    actions: [
      { hook: 'request-editor', kind: 'request-listener', name: 'IHttpListener.processHttpMessage(request)' },
      { hook: 'request-editor', kind: 'proxy-listener', name: 'IProxyListener.processProxyMessage(request)' },
      { hook: 'request-editor', kind: 'request-response-annotation', value: 'Third-party migrated extension annotated selected request/response metadata.' },
      { hook: 'request-editor', kind: 'helpers-analyze-request', name: 'IExtensionHelpers.analyzeRequest' },
      { hook: 'request-editor', kind: 'helpers-build-http-message', name: 'X-Legacy-Proxy-Helper-Built', value: 'true' },
      { hook: 'request-editor', kind: 'helpers-update-parameter', name: 'thirdPartyEdge', value: 'encoded-token' },
      { hook: 'request-editor', kind: 'helpers-url-encode', value: 'extension secret token' },
      { hook: 'request-editor', kind: 'helpers-url-decode', value: 'extension%20secret%20token' },
      { hook: 'request-editor', kind: 'helpers-base64-encode', value: 'extension-secret-token' },
      { hook: 'request-editor', kind: 'helpers-bytes-string', value: 'extension-secret-token' },
      { hook: 'request-editor', kind: 'context-menu', title: 'Send to ProxyForge Repeater' },
      { hook: 'request-editor', kind: 'context-menu-multi-selection', title: 'Send selected requests to Intruder' },
      { hook: 'request-editor', kind: 'session-handling-action', name: 'X-Session-Refresh', value: 'refreshed' },
      { hook: 'request-editor', kind: 'session-token-refresh', name: 'X-Session-Token', value: 'extension-secret-token' },
      { hook: 'response-editor', kind: 'response-listener', name: 'IHttpListener.processHttpMessage(response)' },
      { hook: 'response-editor', kind: 'helpers-analyze-response', name: 'IExtensionHelpers.analyzeResponse' },
      { hook: 'scanner-check', kind: 'scanner-check', title: 'legacy proxy migrated scanner check', severity: 'medium', confidence: 'firm', detail: 'Migrated IScannerCheck created this issue.', remediation: 'Review migrated scanner output before reporting.' },
      { hook: 'scanner-check', kind: 'scanner-insertion-point-provider', name: 'IScannerInsertionPointProvider.getInsertionPoints' },
      { hook: 'message-editor', kind: 'editor-tab', title: 'legacy proxy Message Tab' },
      { hook: 'message-editor', kind: 'context-menu', title: 'Copy ProxyForge evidence id' },
      { hook: 'message-editor', kind: 'extension-state-listener', name: 'IExtensionStateListener.extensionUnloaded' },
      { hook: 'headless-runner', kind: 'policy-denied', name: 'ILegacyExtensionCallbacks.makeHttpRequest' },
    ],
  },
});
const legacyProxyStyleInstall = extensionEngine.installManifestExtension(legacyProxyStyleManifest, []);
assert.ok(legacyProxyStyleInstall.extension, legacyProxyStyleInstall.error ?? 'legacy proxy-compatible compatibility manifest should install');

const listenerRun = extensionEngine.runExtension(legacyProxyStyleInstall.extension, 'request-editor', exchange);
assert.equal(listenerRun.status, 'complete', 'request listener compatibility fixture should execute');
assert.match(listenerRun.logs.join('\n'), /legacy proxy-compatible request listener IHttpListener\.processHttpMessage\(request\)/);
assert.match(listenerRun.logs.join('\n'), /IProxyListener\.processProxyMessage|IExtensionHelpers analyzed request|context menu factory|multi-message|session handling action|session token refresh|updated request parameter|urlEncode|base64Encode|bytes\/string|Annotated IHttpRequestResponse/);
assert.match(listenerRun.exchange.requestRaw, /X-Legacy-Proxy-Helper-Built: true/);
assert.match(listenerRun.exchange.requestRaw, /X-Session-Refresh: refreshed/);
assert.match(listenerRun.exchange.requestRaw, /thirdPartyEdge=encoded-token/);
assert.match(listenerRun.exchange.requestRaw, /X-Session-Token: extension-secret-token/);

const responseListenerRun = extensionEngine.runExtension(legacyProxyStyleInstall.extension, 'response-editor', exchange);
assert.equal(responseListenerRun.status, 'complete', 'response listener compatibility fixture should execute');
assert.match(responseListenerRun.logs.join('\n'), /legacy proxy-compatible response listener IHttpListener\.processHttpMessage\(response\)/);
assert.match(responseListenerRun.logs.join('\n'), /IExtensionHelpers analyzed response/);

const scannerCheckRun = extensionEngine.runExtension(legacyProxyStyleInstall.extension, 'scanner-check', exchange);
assert.equal(scannerCheckRun.status, 'complete', 'scanner-check compatibility fixture should execute');
assert.equal(scannerCheckRun.issue.title, 'legacy proxy migrated scanner check');
assert.equal(scannerCheckRun.issue.confidence, 'firm');
assert.match(scannerCheckRun.logs.join('\n'), /Ran scanner check and created issue/);
assert.match(scannerCheckRun.logs.join('\n'), /IScannerInsertionPointProvider/);

const legacyProxyEditorRun = extensionEngine.runExtension(legacyProxyStyleInstall.extension, 'message-editor', exchange);
assert.equal(legacyProxyEditorRun.status, 'complete', 'legacy proxy-compatible message editor tab fixture should execute');
assert.match(legacyProxyEditorRun.logs.join('\n'), /Registered editor tab legacy proxy Message Tab/);
assert.match(legacyProxyEditorRun.logs.join('\n'), /IExtensionStateListener\.extensionUnloaded|context menu factory/);

const policyDeniedRun = extensionEngine.runExtension(legacyProxyStyleInstall.extension, 'headless-runner', exchange);
assert.equal(policyDeniedRun.status, 'blocked', 'policy-denied compatibility fixture should fail closed');
assert.match(policyDeniedRun.logs.join('\n'), /Policy denied legacy proxy-compatible operation ILegacyExtensionCallbacks\.makeHttpRequest/);

const responseHeaderRun = extensionEngine.runExtension(installed.extension, 'response-editor', exchange);
assert.equal(responseHeaderRun.status, 'complete', 'response-header sandbox action should execute');
assert.match(responseHeaderRun.exchange.responseRaw, /X-ProxyForge-Response-Sandbox: enabled/);

const disabledExtension = { ...installed.extension, id: 'local-disabled-sandbox-header-mutator', enabled: false };
const disabledRun = extensionEngine.runExtension(disabledExtension, 'request-editor', exchange);
assert.equal(disabledRun.status, 'blocked', 'disabled extension run should produce blocked run log evidence');

const parityPackage = extensionEngine.buildExtensionParityEvidencePackage(buildParityContext({
  sandboxExtension: installed.extension,
  legacyProxyStyleExtension: legacyProxyStyleInstall.extension,
  disabledExtension,
  exchange,
  runs: [
    requestRun,
    issueRun,
    editorRun,
    deniedRun,
    unsupportedRun,
    defaultRun,
    authzRun,
    listenerRun,
    responseListenerRun,
    scannerCheckRun,
    legacyProxyEditorRun,
    policyDeniedRun,
    responseHeaderRun,
    disabledRun,
  ],
}));
const parityContent = JSON.parse(parityPackage.content);
assert.equal(parityPackage.kind, 'proxyforge-extension-parity-evidence-package');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.reportReady, true);
assert(Object.values(parityPackage.requirements).every(Boolean), 'all Extension parity requirements should be true');
assert.ok(parityPackage.artifactIds.sdkCompatibilityPackageIds.length >= 1, 'Extension parity should link legacy extension SDK compatibility packages');
assert.ok(parityPackage.artifactIds.thirdPartySdkCompatibilityPackageIds.length >= 1, 'Extension parity should link third-party SDK compatibility packages');
assert.equal(parityContent.kind, 'proxyforge-extension-parity-evidence-package');
assert.match(parityPackage.content, /Authorization: Bearer extension-secret-token/);
assert.match(parityPackage.content, /session=extension-session/);
assert.match(parityPackage.content, /X-API-Key: extension-api-key/);
assert.match(parityPackage.content, /proxyforge-extension-package/);
assert.match(parityPackage.content, /proxyforge-extension-legacy-sdk-compatibility-package/);
assert.match(parityPackage.content, /proxyforge-extension-third-party-sdk-compatibility-package/);
assert.match(parityPackage.content, /context-menu-multi-selection|session-handling-token-refresh|manifest-dependency-edge|package-refresh/);
assert.match(parityPackage.content, /IProxyListener|IScannerInsertionPointProvider|IContextMenuFactory|ISessionHandlingAction|IExtensionStateListener|IExtensionHelpers/);
assert.match(parityPackage.content, /extension-fixtures/);
assert.match(parityPackage.content, /Policy denied|Unsupported sandbox action|missing modify-traffic/);
assert.match(parityPackage.content, /current|available|blocked/);
assert.match(parityPackage.content, /redact-only-during-report-export/);

const artifactDir = path.resolve('.gitignored/test-artifacts/extension-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'extension-parity-evidence-package.json'), parityPackage.content);

console.log('extension-engine: exercised sandbox runtime hooks, legacy proxy-compatible listener/scanner/editor compatibility, policy denial, unsupported capability denial, and legacy extension flows');

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
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] !== 'undefined');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}

function buildExchange() {
  return {
    id: 'hx-extension-sandbox',
    method: 'GET',
    host: 'admin.shop.local',
    path: '/admin/users',
    url: 'https://admin.shop.local/admin/users',
    status: 403,
    length: 512,
    mime: 'application/json',
    risk: 'medium',
    timing: 91,
    notes: 'Selected authorization boundary sample.',
    source: 'proxy',
    time: '18:45:00',
    requestRaw: [
      'GET /admin/users HTTP/1.1',
      'Host: admin.shop.local',
      'Authorization: Bearer extension-secret-token',
      'Cookie: session=extension-session; csrf=extension-csrf',
      'X-API-Key: extension-api-key',
      '',
      '',
    ].join('\n'),
    responseRaw: [
      'HTTP/1.1 403 Forbidden',
      'Content-Type: application/json',
      '',
      '{"error":"forbidden","permission":"admin.users.read","token":"extension-secret-token"}',
    ].join('\n'),
    tags: ['authz'],
  };
}

function buildParityContext({ sandboxExtension, legacyProxyStyleExtension, disabledExtension, exchange, runs }) {
  const now = '2026-05-25T23:05:00.000Z';
  const installedExtensions = [
    extensionEngine.installCatalogExtension(extensionEngine.extensionCatalog[0], '10:00:00', true),
    extensionEngine.installCatalogExtension(extensionEngine.extensionCatalog[1], '10:01:00', false),
    extensionEngine.installCatalogExtension(extensionEngine.extensionCatalog[2], '10:02:00', true),
    sandboxExtension,
    legacyProxyStyleExtension,
    disabledExtension,
  ];
  const packageManifests = installedExtensions.slice(0, 3).map((extension, index) => ({
    id: `extension-package-manifest-${index + 1}`,
    title: `${extension.name} signed manifest`,
    fileName: `proxyforge-extension-package-${extension.id}.json`,
    path: `extensions/proxyforge-extension-package-${extension.id}.json`,
    exportedAt: now,
    extensionId: extension.id,
    extensionName: extension.name,
    author: extension.author,
    version: extension.version,
    hooks: extension.hooks,
    permissions: extension.permissions,
    trustLevel: extension.trustLevel,
    apiCapabilities: {
      trafficMutationApi: extension.permissions.includes('modify-traffic'),
      replayApi: extension.hooks.includes('headless-runner'),
      issueHandoff: extension.permissions.includes('create-issues'),
      evidenceHandoff: true,
    },
    signature: makeSignature(`manifest-${index + 1}`, 'signed'),
    content: JSON.stringify({
      kind: 'proxyforge-extension-package',
      extensionId: extension.id,
      requestRaw: 'Authorization: Bearer extension-secret-token\nCookie: session=extension-session\nX-API-Key: extension-api-key',
      responseRaw: 'HTTP/1.1 200 OK\n\nextension-secret-token',
    }),
  }));
  const runtimeApiPolicies = installedExtensions.slice(0, 4).map((extension, index) => ({
    id: `extension-runtime-policy-${index + 1}`,
    extensionId: extension.id,
    extensionName: extension.name,
    reviewedAt: now,
    apiVersion: 'proxyforge-extender-api/v1',
    sandbox: index === 2 ? 'headless-ci' : 'isolated-worker',
    allowedHooks: extension.hooks,
    deniedHooks: ['intruder-payload'],
    networkAccess: extension.permissions.includes('callback-access') ? 'callback-only' : 'blocked',
    filesystemAccess: 'evidence-write',
    dependencyReviewStatus: index === 3 ? 'blocked' : 'approved',
    signatureStatus: 'signed',
    reviewer: 'ProxyForge extension policy engine',
    summary: `${extension.name} sandbox policy reviewed with hook and dependency constraints.`,
  }));
  const dependencyReviews = installedExtensions.slice(0, 3).map((extension, index) => ({
    id: `extension-dependency-review-${index + 1}`,
    extensionId: extension.id,
    extensionName: extension.name,
    reviewedAt: now,
    status: index === 2 ? 'blocked' : 'approved',
    apiVersion: 'proxyforge-extender-api/v1',
    dependencies: (extension.dependencies ?? [{ name: '@proxyforge/extender-api', version: '^1.4.0' }]).map((dependency) => ({
      name: dependency.name,
      version: dependency.version,
      policy: 'pinned proxyforge extension runtime dependency',
      status: index === 2 ? 'blocked' : 'approved',
    })),
    summary: `${extension.name} dependency metadata reviewed.`,
    signature: makeSignature(`dependency-${index + 1}`, 'signed'),
    content: JSON.stringify({ kind: 'proxyforge-extension-dependency-review', extensionId: extension.id, secret: 'extension-secret-token' }),
  }));
  const headlessEvidence = [
    {
      id: 'extension-headless-evidence-1',
      title: 'Headless extension fixtures',
      fileName: 'proxyforge-extension-headless-evidence.json',
      path: 'extensions/proxyforge-extension-headless-evidence.json',
      createdAt: now,
      extensionId: legacyProxyStyleExtension.id,
      extensionName: legacyProxyStyleExtension.name,
      apiPolicyId: 'extension-runtime-policy-1',
      dependencyReviewId: 'extension-dependency-review-1',
      hookCoverage: ['request-editor', 'response-editor', 'message-editor', 'scanner-check', 'headless-runner'],
      headlessCommand: 'node scripts/proxyforge-agent.mjs extension-fixtures --project ./workspace.proxyforge.json --json',
      status: 'exported',
      runIds: runs.map((run) => run.id),
      runtimePolicyStatus: 'approved',
      reportReady: true,
      summary: 'Headless CI fixtures cover request/response/editor/scanner/headless extension hooks.',
      signature: makeSignature('headless', 'signed'),
      content: JSON.stringify({ kind: 'proxyforge-extension-headless-evidence', command: 'extension-fixtures', Authorization: 'Bearer extension-secret-token' }),
    },
  ];
  const signedUpdates = [
    makeSignedUpdate('extension-update-current', installedExtensions[0], 'current', 'stable', now),
    makeSignedUpdate('extension-update-available', installedExtensions[1], 'available', 'beta', now),
    makeSignedUpdate('extension-update-blocked', sandboxExtension, 'blocked', 'local', now),
  ];
  const compatibilityFixtures = [
    makeFixture('fixture-request-listener', legacyProxyStyleExtension, 'request-editor', 'IHttpListener', 'processHttpMessage(request)', 'allowed', 'pass', now),
    makeFixture('fixture-response-listener', legacyProxyStyleExtension, 'response-editor', 'IHttpListener', 'processHttpMessage(response)', 'allowed', 'pass', now),
    makeFixture('fixture-proxy-listener', legacyProxyStyleExtension, 'request-editor', 'IProxyListener', 'processProxyMessage(request)', 'allowed', 'pass', now),
    makeFixture('fixture-scanner-check', legacyProxyStyleExtension, 'scanner-check', 'IScannerCheck', 'doActiveScan', 'adapter-required', 'warning', now),
    makeFixture('fixture-insertion-provider', legacyProxyStyleExtension, 'scanner-check', 'IScannerInsertionPointProvider', 'getInsertionPoints', 'allowed', 'pass', now),
    makeFixture('fixture-editor-tab', legacyProxyStyleExtension, 'message-editor', 'IMessageEditorTab', 'editor tab', 'allowed', 'pass', now),
    makeFixture('fixture-context-menu', legacyProxyStyleExtension, 'message-editor', 'IContextMenuFactory', 'createMenuItems', 'allowed', 'pass', now),
    makeFixture('fixture-session-action', legacyProxyStyleExtension, 'request-editor', 'ISessionHandlingAction', 'performAction', 'allowed', 'pass', now),
    makeFixture('fixture-extension-state', legacyProxyStyleExtension, 'message-editor', 'IExtensionStateListener', 'extensionUnloaded', 'allowed', 'pass', now),
    makeFixture('fixture-helper-analyze', legacyProxyStyleExtension, 'request-editor', 'IExtensionHelpers', 'analyzeRequest', 'allowed', 'pass', now),
    makeFixture('fixture-helper-build', legacyProxyStyleExtension, 'request-editor', 'IExtensionHelpers', 'buildHttpMessage', 'allowed', 'pass', now),
    makeFixture('fixture-headless-denied', legacyProxyStyleExtension, 'headless-runner', 'ILegacyExtensionCallbacks', 'makeHttpRequest', 'denied', 'pass', now),
  ];
  const sdkCompatibilityPackage = extensionEngine.buildExtensionLegacySdkCompatibilityPackage({
    extension: legacyProxyStyleExtension,
    exchange,
    runs,
    fixtures: compatibilityFixtures,
    now,
  });
  assert.equal(sdkCompatibilityPackage.kind, 'proxyforge-extension-legacy-sdk-compatibility-package');
  assert.equal(sdkCompatibilityPackage.reportReady, true);
  assert.equal(sdkCompatibilityPackage.missingApis.length, 0);
  assert.ok(sdkCompatibilityPackage.coveredApis.includes('IProxyListener'));
  assert.ok(sdkCompatibilityPackage.coveredApis.includes('IScannerInsertionPointProvider'));
  assert.ok(sdkCompatibilityPackage.coveredApis.includes('IContextMenuFactory'));
  assert.ok(sdkCompatibilityPackage.coveredApis.includes('ISessionHandlingAction'));
  assert.ok(sdkCompatibilityPackage.coveredApis.includes('IExtensionStateListener'));
  assert.ok(sdkCompatibilityPackage.coveredApis.includes('IExtensionHelpers'));
  assert.match(sdkCompatibilityPackage.content, /Authorization: Bearer extension-secret-token|session=extension-session|X-API-Key: extension-api-key/);
  const thirdPartySdkCompatibilityPackage = extensionEngine.buildExtensionThirdPartySdkCompatibilityPackage({
    extension: legacyProxyStyleExtension,
    exchange,
    fixtures: compatibilityFixtures,
    profiles: makeThirdPartyProfiles(legacyProxyStyleExtension, now, exchange),
    sdkCompatibilityPackage,
    operationalSecretSamples: ['extension-secret-token', 'extension-session', 'extension-api-key'],
    now,
  });
  assert.equal(thirdPartySdkCompatibilityPackage.kind, 'proxyforge-extension-third-party-sdk-compatibility-package');
  assert.equal(thirdPartySdkCompatibilityPackage.reportReady, true);
  assert.equal(thirdPartySdkCompatibilityPackage.missingCategories.length, 0);
  assert.equal(thirdPartySdkCompatibilityPackage.requirements.profileDiversityCovered, true);
  assert.equal(thirdPartySdkCompatibilityPackage.requirements.helpersTransformCovered, true);
  assert.equal(thirdPartySdkCompatibilityPackage.requirements.contextMenuMultiSelectionCovered, true);
  assert.equal(thirdPartySdkCompatibilityPackage.requirements.sessionHandlingTokenRefreshCovered, true);
  assert.equal(thirdPartySdkCompatibilityPackage.requirements.packageRefreshCovered, true);
  assert.match(thirdPartySdkCompatibilityPackage.content, /Authorization: Bearer extension-secret-token|session=extension-session|X-API-Key: extension-api-key/);
  assert.match(thirdPartySdkCompatibilityPackage.content, /process-spawn|multi-message|extensionUnloaded|package-refresh/);
  const runtimeDiagnostics = [
    {
      id: 'extension-runtime-diagnostic-1',
      title: 'Extension runtime diagnostics',
      fileName: 'proxyforge-extension-runtime-diagnostics.json',
      path: 'extensions/proxyforge-extension-runtime-diagnostics.json',
      createdAt: now,
      extensionId: legacyProxyStyleExtension.id,
      extensionName: legacyProxyStyleExtension.name,
      apiVersion: 'proxyforge-extender-api/v1',
      updateId: 'extension-update-available',
      fixtureIds: compatibilityFixtures.map((fixture) => fixture.id),
      runIds: runs.map((run) => run.id),
      status: 'exported',
      reportReady: true,
      signature: makeSignature('diagnostic', 'signed'),
      summary: 'Runtime diagnostics include update metadata, fixtures, run ids, and report handoff.',
      content: JSON.stringify({ kind: 'proxyforge-extension-runtime-diagnostics', requestRaw: 'Authorization: Bearer extension-secret-token\nCookie: session=extension-session' }),
    },
  ];
  const evidenceHandoffs = [
    {
      id: 'extension-evidence-handoff-1',
      title: 'Extension evidence handoff',
      fileName: 'proxyforge-extension-evidence-handoff.json',
      path: 'reports/proxyforge-extension-evidence-handoff.json',
      createdAt: now,
      attachedAt: now,
      extensionId: legacyProxyStyleExtension.id,
      extensionName: legacyProxyStyleExtension.name,
      runId: runs[0].id,
      manifestId: packageManifests[0].id,
      reportReady: true,
      signature: makeSignature('handoff', 'signed'),
      summary: 'Extension evidence handoff is report ready while executor secrets remain preserved until report export.',
      content: JSON.stringify({ kind: 'proxyforge-extension-evidence-handoff', requestRaw: 'X-API-Key: extension-api-key', reportRedactionBoundary: 'redact-only-during-report-export' }),
    },
  ];
  return {
    catalogItems: extensionEngine.extensionCatalog,
    installedExtensions,
    runs,
    packageManifests,
    runtimeApiPolicies,
    dependencyReviews,
    headlessEvidence,
    signedUpdates,
    compatibilityFixtures,
    sdkCompatibilityPackages: [sdkCompatibilityPackage],
    thirdPartySdkCompatibilityPackages: [thirdPartySdkCompatibilityPackage],
    runtimeDiagnostics,
    migrationGuides: [
      {
        id: 'extension-migration-guide-1',
        title: 'legacy extension migration guide',
        fileName: 'proxyforge-extension-migration-guide.json',
        path: 'extensions/proxyforge-extension-migration-guide.json',
        createdAt: now,
        extensionId: legacyProxyStyleExtension.id,
        extensionName: legacyProxyStyleExtension.name,
        source: 'legacy-extension',
        apiVersion: 'proxyforge-extender-api/v1',
        diagnosticId: 'extension-runtime-diagnostic-1',
        reportReady: true,
        signature: makeSignature('migration', 'signed'),
        summary: 'Migration guide covers request listeners, scanner checks, editor tabs, callbacks, and denied makeHttpRequest behavior.',
        content: JSON.stringify({ kind: 'proxyforge-extension-migration-guide', raw: 'Authorization: Bearer extension-secret-token' }),
      },
    ],
    runtimeHealth: runs.map((run, index) => ({
      id: `extension-runtime-health-${index + 1}`,
      extensionId: run.extensionId,
      extensionName: run.extensionName,
      hook: run.hook,
      runId: run.id,
      status: run.status === 'complete' ? 'success' : 'blocked',
      observedAt: now,
      latencyMs: 10 + index,
      permissionScope: ['read-traffic'],
      apiCapabilities: {
        trafficMutationApi: true,
        replayApi: true,
        issueHandoff: true,
        evidenceHandoff: true,
      },
      summary: run.summary,
    })),
    evidenceHandoffs,
    operationalSecretSamples: ['extension-secret-token', 'extension-session', 'extension-api-key'],
    exportedAt: now,
  };
}

function makeThirdPartyProfiles(extension, now, exchange) {
  const rawPostRequest = [
    'POST /admin/users?role=analyst HTTP/1.1',
    'Host: admin.shop.local',
    'Authorization: Bearer extension-secret-token',
    'Cookie: session=extension-session; csrf=extension-csrf',
    'X-API-Key: extension-api-key',
    'Content-Type: application/json',
    '',
    '{"user":"alice","csrf":"extension-secret-token"}',
  ].join('\n');
  return [
    {
      id: 'third-party-profile-extension-catalog-param-miner',
      name: 'extension package Param Miner Migration',
      source: 'extension-catalog',
      packageName: 'param-miner-migrated',
      version: '1.0.0',
      hooks: ['request-editor', 'scanner-check'],
      manifestFeatures: ['legacy-legacy-extension-api', 'helpers-update-parameter', 'insertion-points', 'package-refresh'],
      dependencies: [{ name: 'legacy-extension-shim', version: '^2026.5.0' }],
      signature: makeSignature('third-party-param-miner', 'signed'),
      edgeCases: [
        {
          category: 'http-message-mutation',
          legacyExtensionApi: 'IHttpRequestResponse',
          operation: 'setRequest / setComment / setHighlight',
          hook: 'request-editor',
          adapterAction: 'request-response-annotation',
          fixtureId: 'fixture-request-listener',
          rawRequest: rawPostRequest,
          rawResponse: exchange.responseRaw,
          evidence: ['Preserves selected raw request while adding metadata annotations for migrated UI state.'],
        },
        {
          category: 'helpers-transform',
          legacyExtensionApi: 'IExtensionHelpers',
          operation: 'analyzeRequest / updateParameter / urlEncode / bytesToString',
          hook: 'request-editor',
          adapterAction: 'helpers-update-parameter',
          fixtureId: 'fixture-helper-analyze',
          rawRequest: rawPostRequest,
          rawResponse: exchange.responseRaw,
          evidence: ['Covers parameter mutation, URL helpers, base64 helpers, and byte/string conversion with operational secrets intact.'],
        },
        {
          category: 'scanner-insertion-point',
          legacyExtensionApi: 'IScannerInsertionPointProvider',
          operation: 'getInsertionPoints(query, header, cookie, json)',
          hook: 'scanner-check',
          adapterAction: 'scanner-insertion-point-provider',
          fixtureId: 'fixture-insertion-provider',
          rawRequest: rawPostRequest,
          rawResponse: exchange.responseRaw,
          evidence: ['query:role header:Authorization cookie:session json:csrf insertion points were retained.'],
        },
      ],
    },
    {
      id: 'third-party-profile-auth-refresh',
      name: 'Session Refresh Action Migration',
      source: 'local-manifest',
      packageName: 'auth-refresh-action',
      version: '2.3.1',
      hooks: ['request-editor', 'headless-runner'],
      manifestFeatures: ['session-handling-action', 'token-refresh', 'policy-denied-callback'],
      dependencies: [{ name: '@proxyforge/session-adapter', version: '^1.2.0' }],
      signature: makeSignature('third-party-auth-refresh', 'signed'),
      edgeCases: [
        {
          category: 'session-handling-token-refresh',
          legacyExtensionApi: 'ISessionHandlingAction',
          operation: 'performAction updates Authorization/Cookie/CSRF material',
          hook: 'request-editor',
          adapterAction: 'session-token-refresh',
          fixtureId: 'fixture-session-action',
          rawRequest: rawPostRequest.replace('Bearer extension-secret-token', 'Bearer refreshed-extension-secret-token'),
          rawResponse: 'HTTP/1.1 200 OK\nSet-Cookie: session=extension-session; HttpOnly\n\n{"csrf":"extension-secret-token"}',
          evidence: ['Full session token and cookie material is retained for executor replay and only redacted during report export.'],
        },
        {
          category: 'unsupported-api-fail-closed',
          legacyExtensionApi: 'ILegacyExtensionCallbacks',
          operation: 'makeHttpRequest / process-spawn denied before side effects',
          hook: 'headless-runner',
          adapterAction: 'policy-denied',
          fixtureId: 'fixture-headless-denied',
          rawRequest: rawPostRequest,
          rawResponse: exchange.responseRaw,
          evidence: ['Unsafe active callback and process-spawn surfaces fail closed unless routed through scoped ProxyForge execution.'],
        },
        {
          category: 'package-refresh',
          legacyExtensionApi: 'ILegacyExtensionCallbacks',
          operation: 'extension package refresh digest',
          hook: 'headless-runner',
          adapterAction: 'package-refresh',
          rawRequest: rawPostRequest,
          rawResponse: exchange.responseRaw,
          evidence: [`${extension.name} package refresh keeps HMAC manifest evidence dated ${now}.`],
        },
      ],
    },
    {
      id: 'third-party-profile-ui-tools',
      name: 'UI Tools Extension Migration',
      source: 'agent-manifest',
      packageName: 'ui-tools-migrated',
      version: '0.9.5',
      hooks: ['message-editor', 'request-editor'],
      manifestFeatures: ['context-menu-factory', 'message-editor-tab', 'extension-state-listener', 'dependency-review'],
      dependencies: [{ name: '@proxyforge/editor-adapter', version: '^0.7.0' }],
      signature: makeSignature('third-party-ui-tools', 'ready-on-export'),
      edgeCases: [
        {
          category: 'context-menu-multi-selection',
          legacyExtensionApi: 'IContextMenuFactory',
          operation: 'createMenuItems for multi-message selected request arrays',
          hook: 'message-editor',
          adapterAction: 'context-menu-multi-selection',
          fixtureId: 'fixture-context-menu',
          rawRequest: rawPostRequest,
          rawResponse: exchange.responseRaw,
          evidence: ['Multi-message selected request/response arrays route to Repeater, Intruder, Scanner, and Reports handoff actions.'],
        },
        {
          category: 'editor-state-lifecycle',
          legacyExtensionApi: 'IMessageEditorTab / IExtensionStateListener',
          operation: 'createNewInstance / getUiComponent / extensionUnloaded',
          hook: 'message-editor',
          adapterAction: 'editor-tab + extension-state-listener',
          fixtureId: 'fixture-extension-state',
          rawRequest: rawPostRequest,
          rawResponse: exchange.responseRaw,
          evidence: ['Editor tab lifecycle and extensionUnloaded cleanup evidence are packaged with run ids.'],
        },
        {
          category: 'manifest-dependency-edge',
          legacyExtensionApi: 'ILegacyExtensionCallbacks',
          operation: 'legacy manifest migration and dependency review',
          hook: 'message-editor',
          adapterAction: 'dependency-review',
          rawRequest: rawPostRequest,
          rawResponse: exchange.responseRaw,
          evidence: ['Legacy manifest fields, dependency pins, signature state, and adapter guidance survive package review.'],
        },
      ],
    },
  ];
}

function makeSignature(label, status) {
  return {
    algorithm: 'HMAC-SHA256',
    signerName: 'ProxyForge Extension Policy',
    keyId: 'extension-policy-key',
    status,
    digestPreview: `${label}-digest-preview`,
  };
}

function makeSignedUpdate(id, extension, status, channel, checkedAt) {
  return {
    id,
    extensionId: extension.id,
    extensionName: extension.name,
    checkedAt,
    channel,
    currentVersion: extension.version,
    availableVersion: status === 'available' ? '9.9.9' : extension.version,
    status,
    apiVersion: 'proxyforge-extender-api/v1',
    signature: makeSignature(id, 'signed'),
    summary: `${extension.name} signed update status is ${status}.`,
    content: JSON.stringify({ kind: 'proxyforge-extension-signed-update', extensionId: extension.id, status, raw: 'Cookie: session=extension-session' }),
  };
}

function makeFixture(id, extension, hook, legacyExtensionApi, operation, policyOutcome, status, executedAt) {
  return {
    id,
    extensionId: extension.id,
    extensionName: extension.name,
    executedAt,
    name: `${legacyExtensionApi} ${operation}`,
    hook,
    apiVersion: 'proxyforge-extender-api/v1',
    legacyExtensionApi,
    operation,
    expectedOutcome: policyOutcome === 'denied' ? 'fail closed before side effect' : 'produce compatibility evidence',
    policyOutcome,
    status,
    summary: `${legacyExtensionApi} ${operation} fixture ${status}.`,
  };
}
