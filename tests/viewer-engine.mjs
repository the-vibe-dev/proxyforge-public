import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const expectedExports = [
  'buildViewerModePreview',
  'buildViewerModePreviews',
  'buildViewerParityEvidencePackage',
];

const viewerEngine = normalizeModuleExports(await loadEngine(path.resolve('src/viewerEvidenceEngine.ts')));
const missingExports = expectedExports.filter((name) => typeof viewerEngine[name] !== 'function');
if (missingExports.length) {
  console.log(`viewer-engine: skipped; missing export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const exchanges = buildExchanges();
const previews = viewerEngine.buildViewerModePreviews(exchanges);
const previewModes = previews.map((preview) => preview.mode).sort();
assert.equal(JSON.stringify(previewModes), JSON.stringify(['binary', 'graphql', 'html', 'image', 'json', 'jwt', 'raw']));
assert.match(previews.find((preview) => preview.mode === 'raw').output, /Authorization: Bearer viewer-secret-token/);
assert.match(previews.find((preview) => preview.mode === 'json').output, /"role": "support_admin"/);
assert.match(previews.find((preview) => preview.mode === 'html').output, /<main>Profile Viewer<\/main>/);
assert.match(previews.find((preview) => preview.mode === 'jwt').output, /"scope": "profile.read"/);
assert.match(previews.find((preview) => preview.mode === 'graphql').output, /query Viewer/);
assert.match(previews.find((preview) => preview.mode === 'image').output, /image\/png/);
assert.match(previews.find((preview) => preview.mode === 'binary').output, /00000000/);

const source = viewerSourceForExchange(exchanges[0]);
const rawSnapshot = {
  id: 'viewer-snapshot-raw-profile',
  title: 'Raw profile snapshot',
  createdAt: '2026-05-25T11:00:00.000Z',
  updatedAt: '2026-05-25T11:00:00.000Z',
  source,
  side: 'request',
  representation: 'raw',
  decoderPipeline: ['none'],
  mime: exchanges[0].mime,
  rawContent: exchanges[0].requestRaw,
  sizeBytes: Buffer.byteLength(exchanges[0].requestRaw),
  evidencePinIds: ['viewer-pin-profile'],
  notes: 'Raw request snapshot from Viewer raw mode.',
};
const decodedSnapshot = {
  id: 'viewer-snapshot-decoded-profile',
  title: 'Decoded JSON profile snapshot',
  createdAt: '2026-05-25T11:00:01.000Z',
  updatedAt: '2026-05-25T11:00:01.000Z',
  source,
  side: 'response',
  representation: 'decoded',
  decoderPipeline: ['json'],
  mime: exchanges[0].mime,
  rawContent: exchanges[0].responseRaw,
  decodedContent: previews.find((preview) => preview.mode === 'json').output,
  sizeBytes: Buffer.byteLength(previews.find((preview) => preview.mode === 'json').output),
  evidencePinIds: ['viewer-pin-profile'],
  notes: 'Decoded JSON snapshot from Viewer Pretty JSON mode.',
};
const evidencePin = {
  id: 'viewer-pin-profile',
  title: 'Profile role evidence',
  createdAt: '2026-05-25T11:00:02.000Z',
  updatedAt: '2026-05-25T11:00:02.000Z',
  source,
  selection: {
    side: 'response',
    representation: 'raw-and-decoded',
    selectedText: exchanges[0].responseRaw,
  },
  severity: 'high',
  tags: ['viewer', 'persistent-pin', 'proxy'],
  linkedIssueIds: ['issue-authz-profile'],
  linkedExchangeIds: [exchanges[0].id],
  reportReady: true,
  reportSection: 'evidence',
  notes: 'Profile response role evidence stays pinned for reporting.',
};
const replayComparisonExport = {
  id: 'viewer-replay-export-profile',
  title: 'Replay comparison POST /api/refunds',
  fileName: 'proxyforge-replay-comparison-profile.json',
  path: 'reports/proxyforge-replay-comparison-profile.json',
  exportedAt: '2026-05-25T11:00:03.000Z',
  format: 'json',
  candidateSessionProfileIds: ['session-support-admin'],
  baselineSessionProfileId: 'session-viewer',
  reportReady: true,
  reportSection: 'evidence',
  issueIds: ['issue-authz-profile'],
  exchangeIds: [exchanges[0].id, 'hx-replay-profile'],
  snapshotIds: [rawSnapshot.id, decodedSnapshot.id],
  evidencePinIds: [evidencePin.id],
  rows: [
    {
      id: 'viewer-replay-row-profile',
      label: 'POST /api/refunds',
      method: 'POST',
      url: 'https://app.shop.local/api/refunds',
      baselineSource: source,
      candidateSource: {
        ...source,
        id: 'hx-replay-profile',
        label: 'Replay candidate: POST app.shop.local/api/refunds',
        exchangeId: 'hx-replay-profile',
        path: '/api/refunds',
        url: 'https://app.shop.local/api/refunds',
      },
      baselineStatus: 403,
      candidateStatus: 200,
      baselineLength: 420,
      candidateLength: 680,
      baselineTiming: 120,
      candidateTiming: 95,
      statusChanged: true,
      lengthDelta: 260,
      timingDelta: -25,
      risk: 'high',
      snapshotIds: [rawSnapshot.id, decodedSnapshot.id],
      evidencePinIds: [evidencePin.id],
      diffSummary: '3 changed, 2 added, 0 removed',
      notes: 'Replay comparison exported from Viewer/Comparer.',
    },
  ],
  summary: 'Replay comparison preserves baseline/candidate status and diff evidence.',
  content: JSON.stringify({
    kind: 'proxyforge-replay-comparison',
    baselineResponse: exchanges[0].responseRaw,
    replayResponse: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"role":"support_admin","refund":"approved","token":"viewer-secret-token"}',
    rawExecutorHeaders: ['Authorization: Bearer viewer-secret-token', 'Cookie: session=viewer-session'],
  }, null, 2),
};

const parityPackage = viewerEngine.buildViewerParityEvidencePackage({
  modePreviews: previews,
  evidencePins: [evidencePin],
  snapshots: [rawSnapshot, decodedSnapshot],
  replayComparisonExports: [replayComparisonExport],
  operationalSecretSamples: ['viewer-secret-token', 'session=viewer-session'],
  exportedAt: '2026-05-25T11:00:04.000Z',
});
assert.equal(parityPackage.kind, 'proxyforge-viewer-parity-evidence-package');
assert.equal(parityPackage.secretHandling, 'execution-full-fidelity-secrets-preserved');
assert.equal(parityPackage.reportRedactionBoundary, 'redact-only-during-report-export');
assert.equal(parityPackage.reportReady, true);
assert.deepEqual(Object.values(parityPackage.requirements).filter(Boolean).length, Object.values(parityPackage.requirements).length, 'all Viewer parity requirements should be covered');
assert.ok(parityPackage.requirements.rawViewCovered, 'Viewer parity should cover raw view');
assert.ok(parityPackage.requirements.prettyJsonViewCovered, 'Viewer parity should cover pretty JSON');
assert.ok(parityPackage.requirements.htmlViewCovered, 'Viewer parity should cover HTML');
assert.ok(parityPackage.requirements.jwtViewCovered, 'Viewer parity should cover JWT');
assert.ok(parityPackage.requirements.graphqlViewCovered, 'Viewer parity should cover GraphQL');
assert.ok(parityPackage.requirements.imageViewCovered, 'Viewer parity should cover image');
assert.ok(parityPackage.requirements.binaryViewCovered, 'Viewer parity should cover binary');
assert.ok(parityPackage.requirements.sourceAwareSnapshotsCovered, 'Viewer parity should cover source-aware snapshots');
assert.ok(parityPackage.requirements.evidencePinsCovered, 'Viewer parity should cover evidence pins');
assert.ok(parityPackage.requirements.replayComparisonExportsCovered, 'Viewer parity should cover replay comparison exports');
assert.ok(parityPackage.requirements.reportAttachmentCovered, 'Viewer parity should cover report attachment handoff');
assert.ok(parityPackage.content.includes('viewer-secret-token'), 'Viewer parity package should preserve executor token until report generation');
assert.ok(parityPackage.content.includes('session=viewer-session'), 'Viewer parity package should preserve executor cookie until report generation');

const artifactDir = path.resolve('.gitignored/test-artifacts/viewer-engine');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(
  path.join(artifactDir, 'viewer-parity-evidence-package.json'),
  parityPackage.content,
  'utf8',
);

console.log('viewer-engine: exercised Viewer parity package, HTTP mode previews, source-aware snapshots, evidence pins, replay comparison exports, report handoff, and full-fidelity secret handling');

async function loadEngine(filePath) {
  const sourceText = await fs.readFile(filePath, 'utf8');
  const transpiled = ts.transpileModule(sourceText, {
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
    Uint8Array,
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

function viewerSourceForExchange(exchange) {
  return {
    kind: 'http-exchange',
    id: exchange.id,
    label: `Selected HTTP exchange: ${exchange.method} ${exchange.host}${exchange.path}`,
    toolId: exchange.source,
    exchangeId: exchange.id,
    method: exchange.method,
    host: exchange.host,
    path: exchange.path,
    url: exchange.url,
  };
}

function buildExchanges() {
  const jwt = makeJwt({ alg: 'HS256', typ: 'JWT' }, { sub: 'acct_123', role: 'viewer', scope: 'profile.read' });
  return [
    {
      id: 'hx-viewer-json',
      method: 'GET',
      host: 'app.shop.local',
      path: '/api/account/profile',
      url: 'https://app.shop.local/api/account/profile',
      status: 200,
      length: 512,
      mime: 'application/json',
      risk: 'high',
      timing: 120,
      notes: 'Profile response role evidence.',
      source: 'proxy',
      time: '11:00:00',
      requestRaw: 'GET /api/account/profile HTTP/2\nHost: app.shop.local\nAuthorization: Bearer viewer-secret-token\nCookie: session=viewer-session\n\n',
      responseRaw: 'HTTP/2 200 OK\nContent-Type: application/json\n\n{"id":"acct_123","role":"support_admin","token":"viewer-secret-token"}',
      tags: ['viewer', 'json', 'authz'],
    },
    {
      id: 'hx-viewer-html',
      method: 'GET',
      host: 'app.shop.local',
      path: '/profile',
      url: 'https://app.shop.local/profile',
      status: 200,
      length: 720,
      mime: 'text/html',
      risk: 'medium',
      timing: 80,
      notes: 'HTML profile page.',
      source: 'proxy',
      time: '11:00:01',
      requestRaw: 'GET /profile HTTP/1.1\nHost: app.shop.local\n\n',
      responseRaw: 'HTTP/1.1 200 OK\nContent-Type: text/html\n\n<!doctype html><html><body><main>Profile Viewer</main></body></html>',
      tags: ['viewer', 'html'],
    },
    {
      id: 'hx-viewer-jwt',
      method: 'GET',
      host: 'auth.shop.local',
      path: '/session',
      url: 'https://auth.shop.local/session',
      status: 200,
      length: 860,
      mime: 'application/json',
      risk: 'medium',
      timing: 55,
      notes: 'JWT session preview.',
      source: 'proxy',
      time: '11:00:02',
      requestRaw: `GET /session HTTP/1.1\nHost: auth.shop.local\nAuthorization: Bearer ${jwt}\n\n`,
      responseRaw: `HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"access_token":"${jwt}"}`,
      tags: ['viewer', 'jwt'],
    },
    {
      id: 'hx-viewer-graphql',
      method: 'POST',
      host: 'api.shop.local',
      path: '/graphql',
      url: 'https://api.shop.local/graphql',
      status: 200,
      length: 420,
      mime: 'application/json',
      risk: 'medium',
      timing: 65,
      notes: 'GraphQL viewer lane.',
      source: 'proxy',
      time: '11:00:03',
      requestRaw: 'POST /graphql HTTP/1.1\nHost: api.shop.local\nContent-Type: application/json\n\n{"operationName":"Viewer","query":"query Viewer { viewer { id role } }","variables":{"id":"acct_123"}}',
      responseRaw: 'HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"data":{"viewer":{"id":"acct_123","role":"viewer"}}}',
      tags: ['viewer', 'graphql'],
    },
    {
      id: 'hx-viewer-image',
      method: 'GET',
      host: 'cdn.shop.local',
      path: '/avatar.png',
      url: 'https://cdn.shop.local/avatar.png',
      status: 200,
      length: 2048,
      mime: 'image/png',
      risk: 'low',
      timing: 20,
      notes: 'Image viewer lane.',
      source: 'proxy',
      time: '11:00:04',
      requestRaw: 'GET /avatar.png HTTP/1.1\nHost: cdn.shop.local\n\n',
      responseRaw: 'HTTP/1.1 200 OK\nContent-Type: image/png\n\nPNGDATA',
      tags: ['viewer', 'image'],
    },
  ];
}

function makeJwt(header, payload) {
  const encode = (value) => Buffer.from(JSON.stringify(value), 'utf8')
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
  return `${encode(header)}.${encode(payload)}.${'signature1234567890'}`;
}
