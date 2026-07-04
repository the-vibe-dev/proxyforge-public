import { strict as assert } from 'node:assert';
import fs from 'node:fs/promises';
import path from 'node:path';
import { createRequire } from 'node:module';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

async function loadRepeaterEvidenceEngine() {
  const enginePath = path.resolve('src/repeaterEvidenceEngine.ts');
  const source = await fs.readFile(enginePath, 'utf8');
  const transpiled = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
      esModuleInterop: true,
    },
    fileName: enginePath,
  }).outputText;
  const module = { exports: {} };
  const sandbox = {
    module,
    exports: module.exports,
    Date,
    Math,
    JSON,
    RegExp,
    Set,
    Array,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: enginePath });
  return module.exports;
}

const repeaterEngine = await loadRepeaterEvidenceEngine();
assert.equal(typeof repeaterEngine.buildRepeaterParityEvidencePackage, 'function', 'Repeater parity package builder should be exported');

const rawRefundRequest = [
  'POST /api/refunds HTTP/1.1',
  'Host: app.shop.local',
  'Authorization: Bearer support-admin-preview',
  'X-ProxyForge-Role: support_admin',
  'Cookie: session=retail-support-preview; csrf=csrf-preview',
  'Content-Type: application/json',
  '',
  '{"orderId":"ord_100","amount":42}',
].join('\r\n');

const editedRefundRequest = rawRefundRequest.replace('"amount":42', '"amount":4200');
const createdAt = '2026-05-25T14:00:00.000Z';
const updatedAt = '2026-05-25T14:03:00.000Z';

const tabs = [
  {
    id: 'rt-refunds-support',
    name: 'POST /api/refunds support',
    group: 'Refund authorization',
    targetUrl: 'https://app.shop.local/api/refunds',
    rawRequest: editedRefundRequest,
    createdAt,
    updatedAt: '2026-05-25T14:03:00.000Z',
    dirty: true,
    lastStatus: 200,
    lastReplayId: 'replay-refunds-support',
    snapshots: [
      {
        id: 'snap-refunds-original',
        tabId: 'rt-refunds-support',
        label: 'Original customer deny',
        targetUrl: 'https://app.shop.local/api/refunds',
        rawRequest: rawRefundRequest,
        createdAt: '2026-05-25T14:01:00.000Z',
        changedLines: 0,
      },
    ],
    diffs: [
      {
        id: 'diff-refunds-amount',
        tabId: 'rt-refunds-support',
        label: 'Amount escalation edit',
        fromLabel: 'Original customer deny',
        toLabel: 'Support replay',
        targetUrl: 'https://app.shop.local/api/refunds',
        createdAt: '2026-05-25T14:02:00.000Z',
        changedLines: 1,
        addedLines: 1,
        removedLines: 1,
        preview: ['- {"orderId":"ord_100","amount":42}', '+ {"orderId":"ord_100","amount":4200}'],
      },
    ],
  },
  {
    id: 'rt-orders-customer',
    name: 'GET /admin/orders customer',
    group: 'Admin route review',
    targetUrl: 'https://app.shop.local/admin/orders?status=open',
    rawRequest: [
      'GET /admin/orders?status=open HTTP/1.1',
      'Host: app.shop.local',
      'Authorization: Bearer customer-preview',
      'Cookie: session=retail-customer-preview',
      '',
      '',
    ].join('\r\n'),
    createdAt,
    updatedAt: createdAt,
    dirty: false,
    snapshots: [],
    diffs: [],
  },
];

const savedRequests = [
  {
    id: 'saved-refunds-support',
    name: 'Support refund replay',
    folder: 'Authorization/Refunds',
    targetUrl: 'https://app.shop.local/api/refunds',
    rawRequest: editedRefundRequest,
    createdAt,
    updatedAt: createdAt,
    tags: ['authz', 'support_admin', 'refunds'],
  },
];

const sessionProfiles = [
  {
    id: 'session-support-admin',
    name: 'Support Admin Browser',
    role: 'support_admin',
    targetUrl: 'https://app.shop.local/dashboard',
    source: 'browser',
    status: 'ready',
    headerText: 'Authorization: Bearer support-admin-preview\nX-ProxyForge-Role: support_admin',
    cookieText: 'session=retail-support-preview; csrf=csrf-preview',
    createdAt,
    updatedAt,
    lastUsedAt: '2026-05-25T14:03:00.000Z',
    headerCount: 2,
    cookieCount: 2,
    notes: 'Captured from managed Chromium profile and preserved for executor replay.',
  },
];

const sessionProfileInjections = [
  {
    id: 'injection-support-admin',
    name: 'Support admin headers and cookies',
    sessionProfileId: 'session-support-admin',
    sessionProfileName: 'Support Admin Browser',
    target: 'headers-and-cookies',
    mode: 'merge',
    headerNames: ['authorization', 'x-proxyforge-role'],
    cookieNames: ['session', 'csrf'],
    createdAt,
    updatedAt,
    lastAppliedAt: '2026-05-25T14:03:00.000Z',
    notes: 'Merged full-fidelity support session into active Repeater tab.',
  },
];

const manualReplay = {
  id: 'replay-refunds-support',
  method: 'POST',
  host: 'app.shop.local',
  path: '/api/refunds',
  url: 'https://app.shop.local/api/refunds',
  status: 200,
  length: 96,
  mime: 'application/json',
  risk: 'medium',
  timing: 87,
  notes: 'Replayed from Repeater; redirects manual; connection keep-alive',
  source: 'repeater',
  time: '2026-05-25T14:03:10.000Z',
  requestRaw: editedRefundRequest,
  responseRaw: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{"approved":true,"role":"support_admin"}',
  tags: ['replayed', 'redirect:manual', 'connection:keep-alive', 'tab:rt-refunds-support'],
};

const bulkRun = {
  id: 'bulk-refunds-support',
  name: 'Refund support replay queue',
  startedAt: '2026-05-25T14:04:00.000Z',
  completedAt: '2026-05-25T14:04:01.000Z',
  status: 'completed',
  totalRequests: 2,
  completedRequests: 2,
  blockedRequests: 0,
  failedRequests: 0,
  message: 'Bulk replay complete: 2 completed, 0 blocked, 0 failed.',
  sessionProfileId: 'session-support-admin',
  sessionProfileInjectionId: 'injection-support-admin',
  authorizationMatrixId: 'matrix-refunds',
  throttleMs: 50,
  items: [
    {
      id: 'bulk-item-refunds',
      name: 'Support refund replay',
      targetUrl: 'https://app.shop.local/api/refunds',
      rawRequest: editedRefundRequest,
      status: 'completed',
      blocked: false,
      message: 'status 200',
      sessionProfileId: 'session-support-admin',
      sessionProfileInjectionId: 'injection-support-admin',
      sourceRepeaterTabId: 'rt-refunds-support',
      exchangeId: 'replay-refunds-support',
      statusCode: 200,
      length: 96,
      timing: 87,
      risk: 'medium',
    },
  ],
};

const authorizationMatrix = {
  id: 'matrix-refunds',
  name: 'proxyforge replay authorization matrix refunds',
  description: 'Customer baseline denied, support admin allowed.',
  createdAt,
  updatedAt: '2026-05-25T14:05:00.000Z',
  targetUrl: 'https://app.shop.local/api/refunds',
  identities: [
    {
      id: 'identity-customer',
      name: 'Customer Browser',
      role: 'customer',
      sessionProfileId: 'session-customer',
      notes: 'Baseline customer session',
    },
    {
      id: 'identity-support',
      name: 'Support Admin Browser',
      role: 'support_admin',
      sessionProfileId: 'session-support-admin',
      sessionProfileInjectionId: 'injection-support-admin',
      notes: 'Privileged support identity',
    },
  ],
  routes: [
    {
      id: 'route-refunds',
      name: 'POST /api/refunds',
      method: 'POST',
      targetUrl: 'https://app.shop.local/api/refunds',
      rawRequest: editedRefundRequest,
      baselineExchangeId: 'hx-customer-refunds',
      notes: 'Refund authorization route',
    },
  ],
  cells: [
    {
      id: 'cell-support-refunds',
      identityId: 'identity-support',
      routeId: 'route-refunds',
      expectation: 'allow',
      outcome: 'allowed',
      lastRunAt: '2026-05-25T14:05:00.000Z',
      bulkRunItemId: 'bulk-item-refunds',
      exchangeId: 'replay-refunds-support',
      statusCode: 200,
      length: 96,
      timing: 87,
      risk: 'medium',
      notes: 'status 403->200 for support_admin replay',
    },
  ],
  lastBulkRunId: 'bulk-refunds-support',
  notes: 'proxyforge authorization evidence with full-fidelity requests retained until report export',
};

const parityPackage = repeaterEngine.buildRepeaterParityEvidencePackage({
  tabs,
  savedRequests,
  sessionProfiles,
  sessionProfileInjections,
  manualReplay,
  bulkRun,
  authorizationMatrix,
  transportSettings: {
    redirectMode: 'manual',
    maxRedirects: 3,
    connectionMode: 'keep-alive',
    timeoutMs: 10000,
  },
  operationalSecretSamples: [
    'Authorization: Bearer support-admin-preview',
    'Cookie: session=retail-support-preview; csrf=csrf-preview',
    'X-ProxyForge-Role: support_admin',
  ],
  exportedAt: '2026-05-25T14:10:00.000Z',
});

assert.equal(parityPackage.kind, 'proxyforge-repeater-parity-evidence-package');
assert.equal(parityPackage.reportReady, true);
assert.equal(parityPackage.tabCount, 2);
assert.equal(parityPackage.savedRequestCount, 1);
assert.equal(parityPackage.sessionInjectionCount, 1);
for (const [name, covered] of Object.entries(parityPackage.requirements)) {
  assert.equal(covered, true, `Repeater parity requirement ${name} should be covered`);
}
assert.equal(parityPackage.requirements.packageRefreshCovered, true);
assert.equal(parityPackage.packageRefreshProof.stalePackageIds.length, 0);
assert.equal(parityPackage.packageRefreshProof.sourceTabCount, 2);
assert.equal(parityPackage.packageRefreshProof.sourceSavedRequestCount, 1);
assert.equal(parityPackage.packageRefreshProof.sourceSessionProfileCount, 1);
assert.equal(parityPackage.packageRefreshProof.sourceSessionInjectionCount, 1);
assert.equal(parityPackage.packageRefreshProof.sourceBulkItemCount, 1);
for (const kind of [
  'proxyforge-repeater-manual-request-editor',
  'proxyforge-repeater-manual-send-runtime',
  'proxyforge-repeater-workspace-tabs',
  'proxyforge-repeater-saved-request-library',
  'proxyforge-repeater-session-profile-injection',
  'proxyforge-repeater-authorization-matrix',
  'proxyforge-repeater-transport-controls',
  'proxyforge-repeater-bulk-replay-handoff',
]) {
  assert.ok(parityPackage.packageRefreshProof.linkedPackageKinds.includes(kind), `Repeater package refresh should include ${kind}`);
}
assert.match(parityPackage.content, /Bearer support-admin-preview|retail-support-preview|csrf-preview/);
assert.match(parityPackage.content, /redact-only-during-report-export/);
assert.match(parityPackage.content, /snapshots|diffs|savedRequests|authorizationMatrix|transportSettings/);
assert.match(parityPackage.content, /packageRefreshProof|proxyforge-repeater-session-profile-injection|proxyforge-repeater-bulk-replay-handoff/);

const artifactDir = path.resolve('.gitignored/test-artifacts/repeater-workspace-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(
  path.join(artifactDir, 'repeater-parity-evidence-package.json'),
  JSON.stringify(parityPackage, null, 2),
);
console.log('repeater-workspace-engine: parity evidence package covered and written');
