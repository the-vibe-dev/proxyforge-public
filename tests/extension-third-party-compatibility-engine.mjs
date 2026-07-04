import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'installManifestExtension',
  'runExtension',
  'buildExtensionLegacySdkCompatibilityPackage',
  'buildExtensionThirdPartySdkCompatibilityPackage',
];

const enginePath = path.resolve('src/extensionEngine.ts');
const extensionEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof extensionEngine[name] === 'undefined');
assert.deepEqual(missingExports, [], `extension-third-party-compatibility-engine: missing export(s): ${missingExports.join(', ')}`);

const now = '2026-05-26T05:20:00.000Z';
const exchange = {
  id: 'hx-third-party-extender',
  method: 'POST',
  host: 'admin.shop.local',
  path: '/admin/users?role=analyst',
  url: 'https://admin.shop.local/admin/users?role=analyst',
  status: 403,
  length: 768,
  mime: 'application/json',
  risk: 'high',
  timing: 104,
  notes: 'Third-party extension compatibility source exchange.',
  source: 'proxy',
  time: '19:20:00',
  requestRaw: [
    'POST /admin/users?role=analyst HTTP/1.1',
    'Host: admin.shop.local',
    'Authorization: Bearer third-party-extension-token',
    'Cookie: session=third-party-extension-session; csrf=third-party-extension-csrf',
    'X-API-Key: third-party-extension-key',
    'Content-Type: application/json',
    '',
    '{"target":"alice","csrf":"third-party-extension-token"}',
  ].join('\n'),
  responseRaw: [
    'HTTP/1.1 403 Forbidden',
    'Content-Type: application/json',
    '',
    '{"error":"forbidden","token":"third-party-extension-token"}',
  ].join('\n'),
  tags: ['extension', 'third-party'],
};

const manifestInstall = extensionEngine.installManifestExtension(JSON.stringify({
  name: 'Third Party extension Edge Probe',
  version: '1.0.0',
  author: 'ProxyForge Compatibility',
  hooks: ['request-editor', 'response-editor', 'message-editor', 'scanner-check', 'headless-runner'],
  permissions: ['read-traffic', 'modify-traffic', 'create-issues', 'run-automations'],
  runtimeApi: {
    apiVersion: 'proxyforge-extender-api/v1',
    sandbox: 'isolated-worker',
    actions: [
      { hook: 'request-editor', kind: 'request-response-annotation', value: 'Annotated selected IHttpRequestResponse.' },
      { hook: 'request-editor', kind: 'helpers-analyze-request', name: 'IExtensionHelpers.analyzeRequest' },
      { hook: 'request-editor', kind: 'helpers-update-parameter', name: 'thirdPartyEdge', value: 'true' },
      { hook: 'request-editor', kind: 'helpers-url-encode', value: 'third-party-extension-token' },
      { hook: 'request-editor', kind: 'helpers-base64-encode', value: 'third-party-extension-token' },
      { hook: 'request-editor', kind: 'context-menu-multi-selection', title: 'Send selected requests to Intruder' },
      { hook: 'request-editor', kind: 'session-token-refresh', name: 'X-Session-Token', value: 'third-party-extension-token' },
      { hook: 'response-editor', kind: 'helpers-analyze-response', name: 'IExtensionHelpers.analyzeResponse' },
      { hook: 'scanner-check', kind: 'scanner-insertion-point-provider', name: 'IScannerInsertionPointProvider.getInsertionPoints' },
      { hook: 'message-editor', kind: 'editor-tab', title: 'Third Party Tab' },
      { hook: 'message-editor', kind: 'extension-state-listener', name: 'IExtensionStateListener.extensionUnloaded' },
      { hook: 'headless-runner', kind: 'policy-denied', name: 'ILegacyExtensionCallbacks.makeHttpRequest/process-spawn' },
    ],
  },
}), []);
assert.ok(manifestInstall.extension, manifestInstall.error ?? 'third-party manifest should install');

const requestRun = extensionEngine.runExtension(manifestInstall.extension, 'request-editor', exchange);
assert.equal(requestRun.status, 'complete');
assert.match(requestRun.logs.join('\n'), /Annotated IHttpRequestResponse|updated request parameter|urlEncode|base64Encode|multi-message|session token refresh/);
assert.match(requestRun.exchange.requestRaw, /thirdPartyEdge=true/);
assert.match(requestRun.exchange.requestRaw, /X-Session-Token: third-party-extension-token/);

const responseRun = extensionEngine.runExtension(manifestInstall.extension, 'response-editor', exchange);
assert.equal(responseRun.status, 'complete');
assert.match(responseRun.logs.join('\n'), /IExtensionHelpers analyzed response/);

const scannerRun = extensionEngine.runExtension(manifestInstall.extension, 'scanner-check', exchange);
assert.equal(scannerRun.status, 'complete');
assert.match(scannerRun.logs.join('\n'), /IScannerInsertionPointProvider/);

const editorRun = extensionEngine.runExtension(manifestInstall.extension, 'message-editor', exchange);
assert.equal(editorRun.status, 'complete');
assert.match(editorRun.logs.join('\n'), /Third Party Tab|IExtensionStateListener\.extensionUnloaded/);

const deniedRun = extensionEngine.runExtension(manifestInstall.extension, 'headless-runner', exchange);
assert.equal(deniedRun.status, 'blocked');
assert.match(deniedRun.logs.join('\n'), /Policy denied legacy proxy-compatible operation/);

const fixtures = [
  makeFixture('edge-fixture-http-message', manifestInstall.extension, 'request-editor', 'IHttpRequestResponse', 'setRequest/setComment/setHighlight', 'allowed', 'pass'),
  makeFixture('edge-fixture-helpers', manifestInstall.extension, 'request-editor', 'IExtensionHelpers', 'analyzeRequest/updateParameter/urlEncode/base64Encode/bytesToString', 'allowed', 'pass'),
  makeFixture('edge-fixture-menu', manifestInstall.extension, 'message-editor', 'IContextMenuFactory', 'createMenuItems multi-message selection', 'allowed', 'pass'),
  makeFixture('edge-fixture-session', manifestInstall.extension, 'request-editor', 'ISessionHandlingAction', 'performAction token refresh', 'allowed', 'pass'),
  makeFixture('edge-fixture-insertion', manifestInstall.extension, 'scanner-check', 'IScannerInsertionPointProvider', 'getInsertionPoints query/header/cookie/json', 'allowed', 'pass'),
  makeFixture('edge-fixture-editor-state', manifestInstall.extension, 'message-editor', 'IMessageEditorTab/IExtensionStateListener', 'extensionUnloaded cleanup', 'allowed', 'pass'),
  makeFixture('edge-fixture-denied', manifestInstall.extension, 'headless-runner', 'ILegacyExtensionCallbacks', 'makeHttpRequest/process-spawn', 'denied', 'pass'),
];
const sdkFixtures = [
  makeFixture('sdk-fixture-http-listener', manifestInstall.extension, 'request-editor', 'IHttpListener', 'processHttpMessage(request)', 'allowed', 'pass'),
  makeFixture('sdk-fixture-proxy-listener', manifestInstall.extension, 'request-editor', 'IProxyListener', 'processProxyMessage(request)', 'allowed', 'pass'),
  makeFixture('sdk-fixture-scanner-check', manifestInstall.extension, 'scanner-check', 'IScannerCheck', 'doActiveScan', 'adapter-required', 'warning'),
  makeFixture('sdk-fixture-insertion-provider', manifestInstall.extension, 'scanner-check', 'IScannerInsertionPointProvider', 'getInsertionPoints', 'allowed', 'pass'),
  makeFixture('sdk-fixture-editor-tab', manifestInstall.extension, 'message-editor', 'IMessageEditorTab', 'createNewInstance / getUiComponent', 'allowed', 'pass'),
  makeFixture('sdk-fixture-context-menu', manifestInstall.extension, 'message-editor', 'IContextMenuFactory', 'createMenuItems', 'allowed', 'pass'),
  makeFixture('sdk-fixture-session-action', manifestInstall.extension, 'request-editor', 'ISessionHandlingAction', 'performAction', 'allowed', 'pass'),
  makeFixture('sdk-fixture-state-listener', manifestInstall.extension, 'message-editor', 'IExtensionStateListener', 'extensionUnloaded', 'allowed', 'pass'),
  makeFixture('sdk-fixture-helpers', manifestInstall.extension, 'request-editor', 'IExtensionHelpers', 'analyzeRequest/buildHttpMessage/updateParameter', 'allowed', 'pass'),
  makeFixture('sdk-fixture-callback-denied', manifestInstall.extension, 'headless-runner', 'ILegacyExtensionCallbacks', 'makeHttpRequest/process-spawn', 'denied', 'pass'),
];

const sdkPackage = extensionEngine.buildExtensionLegacySdkCompatibilityPackage({
  extension: manifestInstall.extension,
  exchange,
  runs: [requestRun, responseRun, scannerRun, editorRun, deniedRun],
  fixtures: sdkFixtures,
  now,
});
assert.equal(sdkPackage.reportReady, true);

const thirdPartyPackage = extensionEngine.buildExtensionThirdPartySdkCompatibilityPackage({
  extension: manifestInstall.extension,
  exchange,
  fixtures,
  sdkCompatibilityPackage: sdkPackage,
  profiles: buildProfiles(),
  operationalSecretSamples: [
    'third-party-extension-token',
    'third-party-extension-session',
    'third-party-extension-key',
  ],
  now,
});

const content = JSON.parse(thirdPartyPackage.content);
assert.equal(thirdPartyPackage.kind, 'proxyforge-extension-third-party-sdk-compatibility-package');
assert.equal(thirdPartyPackage.reportReady, true);
assert.equal(thirdPartyPackage.missingCategories.length, 0);
assert(Object.values(thirdPartyPackage.requirements).every(Boolean), 'all third-party Extension SDK edge requirements should be true');
assert.equal(thirdPartyPackage.profileCount, 3);
assert.equal(thirdPartyPackage.failCount, 0);
assert.match(thirdPartyPackage.content, /third-party-extension-token/);
assert.match(thirdPartyPackage.content, /third-party-extension-session/);
assert.match(thirdPartyPackage.content, /third-party-extension-key/);
assert.match(thirdPartyPackage.content, /context-menu-multi-selection|session-handling-token-refresh|unsupported-api-fail-closed|manifest-dependency-edge|package-refresh/);
assert.equal(content.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(content.packageRefreshProof.staleProfileIds.length, 0);

const artifactDir = path.resolve('.gitignored/test-artifacts/extension-third-party-compatibility');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(path.join(artifactDir, 'extension-third-party-sdk-compatibility-package.json'), thirdPartyPackage.content);

console.log('extension-third-party-compatibility-engine: verified third-party extension SDK edge profiles, helper transforms, multi-select context menus, session refresh, insertion points, fail-closed denial, package refresh, and full-fidelity secrets');

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

function makeFixture(id, extension, hook, legacyExtensionApi, operation, policyOutcome, status) {
  return {
    id,
    extensionId: extension.id,
    extensionName: extension.name,
    executedAt: now,
    name: `${legacyExtensionApi} ${operation}`,
    hook,
    apiVersion: 'proxyforge-extender-api/v1',
    legacyExtensionApi,
    operation,
    expectedOutcome: policyOutcome === 'denied' ? 'fail closed before side effect' : 'produce third-party compatibility evidence',
    policyOutcome,
    status,
    summary: `${legacyExtensionApi} ${operation} third-party edge fixture ${status}.`,
  };
}

function signature(label, status = 'signed') {
  return {
    algorithm: 'HMAC-SHA256',
    signerName: 'ProxyForge Extension Policy',
    keyId: 'extension-policy-key',
    status,
    digestPreview: `${label}-digest-preview`,
  };
}

function buildProfiles() {
  const sharedRaw = exchange.requestRaw;
  return [
    {
      id: 'profile-extension-catalog-param-miner',
      name: 'extension package Param Miner Migration',
      source: 'extension-catalog',
      packageName: 'param-miner-migrated',
      version: '1.2.0',
      hooks: ['request-editor', 'scanner-check'],
      manifestFeatures: ['legacy-legacy-extension-api', 'helpers-transform', 'scanner-insertion-point', 'package-refresh'],
      dependencies: [{ name: 'legacy-extension-shim', version: '^2026.5.0' }],
      signature: signature('profile-param-miner'),
      edgeCases: [
        edge('http-message-mutation', 'IHttpRequestResponse', 'setRequest/setComment/setHighlight', 'request-editor', 'request-response-annotation', 'edge-fixture-http-message', sharedRaw, exchange.responseRaw),
        edge('helpers-transform', 'IExtensionHelpers', 'analyzeRequest/updateParameter/urlEncode/base64Encode/bytesToString', 'request-editor', 'helpers-update-parameter', 'edge-fixture-helpers', sharedRaw, exchange.responseRaw),
        edge('scanner-insertion-point', 'IScannerInsertionPointProvider', 'getInsertionPoints query/header/cookie/json', 'scanner-check', 'scanner-insertion-point-provider', 'edge-fixture-insertion', sharedRaw, exchange.responseRaw),
      ],
    },
    {
      id: 'profile-session-refresh',
      name: 'Session Refresh Action Migration',
      source: 'local-manifest',
      packageName: 'session-refresh-migrated',
      version: '3.0.0',
      hooks: ['request-editor', 'headless-runner'],
      manifestFeatures: ['session-handling-action', 'policy-denied-callback', 'manifest-dependency-edge'],
      dependencies: [{ name: '@proxyforge/session-adapter', version: '^1.2.0' }],
      signature: signature('profile-session-refresh'),
      edgeCases: [
        edge('session-handling-token-refresh', 'ISessionHandlingAction', 'performAction token refresh', 'request-editor', 'session-token-refresh', 'edge-fixture-session', sharedRaw, exchange.responseRaw),
        edge('unsupported-api-fail-closed', 'ILegacyExtensionCallbacks', 'makeHttpRequest/process-spawn denied before side effects', 'headless-runner', 'policy-denied', 'edge-fixture-denied', sharedRaw, exchange.responseRaw),
        edge('package-refresh', 'ILegacyExtensionCallbacks', 'package refresh digest', 'headless-runner', 'package-refresh', undefined, sharedRaw, exchange.responseRaw),
      ],
    },
    {
      id: 'profile-ui-tools',
      name: 'UI Tools Migration',
      source: 'agent-manifest',
      packageName: 'ui-tools-migrated',
      version: '0.8.4',
      hooks: ['message-editor', 'request-editor'],
      manifestFeatures: ['context-menu-factory', 'message-editor-tab', 'extension-state-listener', 'dependency-review'],
      dependencies: [{ name: '@proxyforge/editor-adapter', version: '^0.7.0' }],
      signature: signature('profile-ui-tools', 'ready-on-export'),
      edgeCases: [
        edge('context-menu-multi-selection', 'IContextMenuFactory', 'createMenuItems for multi-message selected request arrays', 'message-editor', 'context-menu-multi-selection', 'edge-fixture-menu', sharedRaw, exchange.responseRaw),
        edge('editor-state-lifecycle', 'IMessageEditorTab / IExtensionStateListener', 'createNewInstance / extensionUnloaded cleanup', 'message-editor', 'editor-tab + extension-state-listener', 'edge-fixture-editor-state', sharedRaw, exchange.responseRaw),
        edge('manifest-dependency-edge', 'ILegacyExtensionCallbacks', 'legacy manifest migration and dependency review', 'message-editor', 'dependency-review', undefined, sharedRaw, exchange.responseRaw),
      ],
    },
  ];
}

function edge(category, legacyExtensionApi, operation, hook, adapterAction, fixtureId, rawRequest, rawResponse) {
  return {
    category,
    legacyExtensionApi,
    operation,
    hook,
    adapterAction,
    fixtureId,
    status: 'pass',
    rawRequest,
    rawResponse,
    evidence: [`${category} preserves raw request/response with third-party-extension-token until report export.`],
  };
}
