import { strict as assert } from 'node:assert';
import { createRequire } from 'node:module';
import fs from 'node:fs/promises';
import path from 'node:path';
import vm from 'node:vm';

const require = createRequire(import.meta.url);
const ts = require('typescript');

const candidateEnginePaths = [
  'src/callbackEngine.ts',
  'src/callback-engine.ts',
  'src/callback/callbackEngine.ts',
  'src/callback/callback-engine.ts',
  'dist/callbackEngine.js',
  'dist/callback-engine.js',
];

const expectedExports = [
  'buildCallbackListenerProfile',
  'pollCallbackLiveInteractions',
  'buildCallbackCorrelationReplayPackage',
  'executeCallbackCorrelationReplayBatch',
  'buildCallbackPayloadLifecycleReview',
  'applyCallbackRetentionPrune',
  'buildCallbackCiHandoffPackage',
  'buildCallbackPublicRelaySoakPackage',
  'buildCallbackExternalRelayIntegrationPackage',
  'buildCallbackExternalOastProviderDiversityPackage',
  'buildCallbackReportRoundTripPackage',
  'buildCallbackCollaboratorParityEvidencePackage',
  'buildCallbackPackageRefreshEvidencePackage',
];

const enginePath = await firstExistingPath(candidateEnginePaths);
if (!enginePath) {
  console.log('callback-live-backend-engine: skipped; no Callback engine module is exported yet');
  process.exit(0);
}

const callbackEngine = normalizeModuleExports(await loadEngine(enginePath));
const missingExports = expectedExports.filter((name) => typeof callbackEngine[name] !== 'function');
if (missingExports.length) {
  console.log(`callback-live-backend-engine: skipped; missing Callback live backend export(s): ${missingExports.join(', ')}`);
  process.exit(0);
}

const sample = buildSampleCallbackLiveBackendRequest();

const profile = callbackEngine.buildCallbackListenerProfile({
  mode: 'hybrid-local',
  host: '127.0.0.1',
  publicBaseUrl: 'callbacks.shop.local',
  httpPort: 18088,
  dnsPort: 15353,
  smtpPort: 12525,
  pollIntervalSeconds: 15,
  retentionHours: 96,
  signingKeyId: 'callback-ci-key',
  now: sample.now,
});
assertListenerProfile(profile, 'buildCallbackListenerProfile');

const pollResult = callbackEngine.pollCallbackLiveInteractions({
  profile,
  payloads: sample.payloads,
  interactions: sample.interactions,
  fallbackExchange: sample.exchange,
  workspaces: [sample.workspace],
  exploitRuns: [sample.exploitRun],
  signerName: 'ProxyForge CI',
  signingSecret: 'callback-ci-secret',
  now: sample.now,
});
assertSignedPoll(pollResult, 'pollCallbackLiveInteractions');

const observedPayload = pollResult.payloads.find((payload) => payload.id === 'cb-live-http');
const replay = callbackEngine.buildCallbackCorrelationReplayPackage({
  profile,
  payload: observedPayload,
  interactions: pollResult.interactions,
  exchange: sample.exchange,
  exploitRuns: [sample.exploitRun],
  targetTool: 'repeater',
  now: sample.now,
});
assertCorrelationReplay(replay, 'buildCallbackCorrelationReplayPackage');

const scannerReplay = callbackEngine.buildCallbackCorrelationReplayPackage({
  profile,
  payload: observedPayload,
  interactions: pollResult.interactions,
  exchange: sample.exchange,
  exploitRuns: [sample.exploitRun],
  targetTool: 'scanner',
  now: sample.now,
});
assertCorrelationReplay(scannerReplay, 'buildCallbackCorrelationReplayPackage scanner target', 'scanner');

const exploitReplay = callbackEngine.buildCallbackCorrelationReplayPackage({
  profile,
  payload: observedPayload,
  interactions: pollResult.interactions,
  exchange: sample.exchange,
  exploitRuns: [sample.exploitRun],
  targetTool: 'exploit-lab',
  now: sample.now,
});
assertCorrelationReplay(exploitReplay, 'buildCallbackCorrelationReplayPackage exploit target', 'exploit-lab');

const executionBatch = callbackEngine.executeCallbackCorrelationReplayBatch({
  profile,
  replays: [replay, scannerReplay, exploitReplay],
  payloads: pollResult.payloads,
  interactions: pollResult.interactions,
  exploitRuns: [sample.exploitRun],
  exchanges: [sample.exchange],
  scopeAllowlist: ['shop.local'],
  mode: 'local-verified',
  now: sample.now,
});
assertReplayExecutionBatch(executionBatch, 'executeCallbackCorrelationReplayBatch');

const lifecycle = callbackEngine.buildCallbackPayloadLifecycleReview({
  profile,
  payloads: pollResult.payloads,
  interactions: pollResult.interactions,
  retentionHours: 96,
  now: sample.now,
});
assertLifecycleReview(lifecycle, 'buildCallbackPayloadLifecycleReview');

const prune = callbackEngine.applyCallbackRetentionPrune({
  profile,
  payloads: [...pollResult.payloads, sample.expiredPayload],
  interactions: [...pollResult.interactions, sample.expiredInteraction],
  retentionHours: 96,
  now: sample.now,
});
assertRetentionPrune(prune, 'applyCallbackRetentionPrune');

const ciHandoff = callbackEngine.buildCallbackCiHandoffPackage({
  profile,
  workspace: sample.workspace,
  payloads: pollResult.payloads,
  interactions: pollResult.interactions,
  provider: 'gitlab-ci',
  now: sample.now,
});
assertCiHandoff(ciHandoff, 'buildCallbackCiHandoffPackage');

const relaySoak = callbackEngine.buildCallbackPublicRelaySoakPackage({
  profile,
  workspace: sample.workspace,
  payloads: [...pollResult.payloads, sample.expiredPayload],
  interactions: [...pollResult.interactions, sample.expiredInteraction],
  signedPollBatches: [pollResult.batch],
  replayExecutionBatches: [executionBatch],
  lifecycleReviews: [lifecycle],
  ciHandoffPackages: [ciHandoff],
  minPayloadCount: 3,
  minInteractionCount: 3,
  minProtocolCount: 3,
  now: sample.now,
});
assertPublicRelaySoak(relaySoak, 'buildCallbackPublicRelaySoakPackage');

const externalRelayIntegration = callbackEngine.buildCallbackExternalRelayIntegrationPackage({
  profile,
  relayBaseUrl: 'https://callbacks.shop.local',
  publicBaseUrl: 'callbacks.shop.local',
  payloads: [...pollResult.payloads, sample.expiredPayload],
  tenantPolls: [
    {
      tenantId: 'retail-north',
      relayBaseUrl: 'https://callbacks.shop.local',
      publicBaseUrl: 'callbacks.shop.local',
      payloadIds: pollResult.payloads.map((payload) => payload.id),
      interactions: pollResult.interactions,
      statusCode: 200,
      rawRequest: [
        'GET /api/proxyforge/oast/poll?tenant=retail-north HTTP/1.1',
        'Host: callbacks.shop.local',
        'Authorization: Bearer relay-north-secret',
        '',
      ].join('\n'),
      rawResponse: JSON.stringify({
        tenantId: 'retail-north',
        signedWith: 'callback-ci-secret',
        interactions: pollResult.interactions,
        payloadTokens: pollResult.payloads.map((payload) => payload.token),
      }),
      signature: {
        algorithm: 'HMAC-SHA256',
        keyId: 'callback-ci-key',
        status: 'signed',
        digestPreview: 'relay-north-digest',
      },
    },
    {
      tenantId: 'retail-south',
      relayBaseUrl: 'https://callbacks.shop.local',
      publicBaseUrl: 'callbacks.shop.local',
      payloadIds: [sample.expiredPayload.id],
      interactions: [sample.expiredInteraction],
      statusCode: 200,
      rawRequest: [
        'GET /api/proxyforge/oast/poll?tenant=retail-south HTTP/1.1',
        'Host: callbacks.shop.local',
        'Authorization: Bearer relay-south-secret',
        '',
      ].join('\n'),
      rawResponse: JSON.stringify({
        tenantId: 'retail-south',
        signedWith: 'callback-ci-secret',
        interactions: [sample.expiredInteraction],
        payloadTokens: [sample.expiredPayload.token],
      }),
      signature: {
        algorithm: 'HMAC-SHA256',
        keyId: 'callback-ci-key',
        status: 'signed',
        digestPreview: 'relay-south-digest',
      },
    },
  ],
  minTenantCount: 2,
  minInteractionCount: 3,
  minProtocolCount: 2,
  now: sample.now,
});
assertExternalRelayIntegration(externalRelayIntegration, 'buildCallbackExternalRelayIntegrationPackage');

const externalProviderDiversity = callbackEngine.buildCallbackExternalOastProviderDiversityPackage({
  profile,
  payloads: [...pollResult.payloads, sample.expiredPayload],
  relayIntegrationPackages: [externalRelayIntegration],
  providerProbes: [
    {
      providerId: 'generic-http-provider',
      providerName: 'Generic HTTP Provider',
      providerKind: 'generic-http-relay',
      tenantId: 'retail-north',
      baseUrl: 'https://generic-http-oast.example.test',
      publicBaseUrl: 'generic-http-oast.example.test',
      protocol: 'http',
      payloadIds: pollResult.payloads.map((payload) => payload.id),
      interactions: pollResult.interactions.filter((interaction) => interaction.protocol === 'http'),
      statusCode: 200,
      rawRequest: 'GET /api/poll?tenant=retail-north HTTP/1.1\nHost: generic-http-oast.example.test\nAuthorization: Bearer generic-http-provider-secret\n',
      rawResponse: JSON.stringify({ payloadTokens: pollResult.payloads.map((payload) => payload.token), providerSecret: 'generic-http-provider-secret' }),
      signature: { algorithm: 'HMAC-SHA256', keyId: 'generic-http-key', status: 'signed', digestPreview: 'generic-http-digest' },
    },
    {
      providerId: 'dns-webhook-provider',
      providerName: 'DNS Webhook Provider',
      providerKind: 'dns-webhook-relay',
      tenantId: 'retail-north',
      baseUrl: 'https://dns-webhook-oast.example.test',
      publicBaseUrl: 'dns-webhook-oast.example.test',
      protocol: 'dns',
      payloadIds: pollResult.payloads.map((payload) => payload.id),
      interactions: pollResult.interactions.filter((interaction) => interaction.protocol === 'dns'),
      statusCode: 200,
      rawRequest: 'GET /dns/events?tenant=retail-north HTTP/1.1\nHost: dns-webhook-oast.example.test\nAuthorization: Bearer dns-webhook-provider-secret\n',
      rawResponse: JSON.stringify({ payloadTokens: pollResult.payloads.map((payload) => payload.token), providerSecret: 'dns-webhook-provider-secret' }),
      signature: { algorithm: 'HMAC-SHA256', keyId: 'dns-webhook-key', status: 'signed', digestPreview: 'dns-webhook-digest' },
    },
    {
      providerId: 'smtp-relay-provider',
      providerName: 'SMTP Relay Provider',
      providerKind: 'smtp-relay',
      tenantId: 'retail-south',
      baseUrl: 'https://smtp-relay-oast.example.test',
      publicBaseUrl: 'smtp-relay-oast.example.test',
      protocol: 'smtp',
      payloadIds: [sample.expiredPayload.id],
      interactions: [{ ...sample.expiredInteraction, id: 'cb-provider-smtp', protocol: 'smtp', raw: `MAIL FROM:<worker@shop.local>\nRCPT TO:<${sample.expiredPayload.token}@smtp-relay-oast.example.test>\nAuthorization: Bearer smtp-relay-provider-secret` }],
      statusCode: 200,
      rawRequest: 'GET /smtp/events?tenant=retail-south HTTP/1.1\nHost: smtp-relay-oast.example.test\nAuthorization: Bearer smtp-relay-provider-secret\n',
      rawResponse: JSON.stringify({ payloadTokens: [sample.expiredPayload.token], providerSecret: 'smtp-relay-provider-secret' }),
      signature: { algorithm: 'HMAC-SHA256', keyId: 'smtp-relay-key', status: 'signed', digestPreview: 'smtp-relay-digest' },
    },
  ],
  minProviderCount: 3,
  minProtocolCount: 3,
  minInteractionCount: 3,
  now: sample.now,
});
assertExternalProviderDiversity(externalProviderDiversity, 'buildCallbackExternalOastProviderDiversityPackage');

const parityWorkspace = {
  ...sample.workspace,
  interactionIds: pollResult.interactions.map((interaction) => interaction.id),
  linkedIssueIds: ['callback-cb-live-http'],
  protocols: ['dns', 'http', 'smtp'],
  status: 'confirmed',
  signedEvidencePackageId: 'callback-evidence-live',
};

const callbackEvidencePackage = {
  id: 'callback-evidence-live',
  title: 'Callback evidence package',
  fileName: 'callback-evidence-live.json',
  path: 'callbacks/callback-evidence-live.json',
  exportedAt: sample.now,
  workspaceId: parityWorkspace.id,
  owner: parityWorkspace.owner,
  reportReady: true,
  attachedAt: sample.now,
  reportSection: 'evidence',
  payloadIds: pollResult.payloads.map((payload) => payload.id),
  interactionIds: pollResult.interactions.map((interaction) => interaction.id),
  issueIds: ['callback-cb-live-http'],
  exploitRunIds: ['exploit-run-import'],
  signature: {
    algorithm: 'HMAC-SHA256',
    signerName: 'ProxyForge CI',
    keyId: 'callback-ci-key',
    status: 'signed',
    digestPreview: 'callback-digest-live',
  },
  summary: 'Signed callback evidence package preserves raw exchange, listener material, payload tokens, interactions, and report attachment links.',
  content: JSON.stringify({
    kind: 'proxyforge-callback-evidence-package',
    requestRaw: sample.exchange.requestRaw,
    responseRaw: sample.exchange.responseRaw,
    payloads: pollResult.payloads,
    interactions: pollResult.interactions,
    workspace: parityWorkspace,
    operationalSecrets: {
      authorizationBearer: 'callback-secret-token',
      signingSecret: 'callback-ci-secret',
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  }, null, 2),
};

const reportPackageContent = buildFullReportPackageContent({
  signedPollBatches: [pollResult.batch],
  replayPackages: [replay, scannerReplay, exploitReplay],
  replayExecutionBatches: [executionBatch],
  lifecycleReviews: [lifecycle, prune.review],
  ciHandoffPackages: [ciHandoff],
  relaySoakPackages: [relaySoak],
  externalRelayIntegrationPackages: [externalRelayIntegration],
  externalProviderDiversityPackages: [externalProviderDiversity],
  evidencePackages: [callbackEvidencePackage],
});
const exportedReportContent = JSON.stringify({
  kind: 'proxyforge-evidence-bundle',
  reportMarkdown: [
    '# Retail import OAST evidence',
    '',
    'Authorization: [redacted]',
    'callbackSecret: [redacted]',
    'providerSecret: [redacted]',
    'payloadToken: [redacted]',
  ].join('\n'),
  callbackArtifactManifest: {
    totalArtifactCount: 12,
    redactionBoundary: 'redact-only-during-report-export',
  },
}, null, 2);
const reportRoundTrip = callbackEngine.buildCallbackReportRoundTripPackage({
  reportPackageContent,
  exportedReportContent,
  signedPollBatches: [pollResult.batch],
  replayPackages: [replay, scannerReplay, exploitReplay],
  replayExecutionBatches: [executionBatch],
  lifecycleReviews: [lifecycle, prune.review],
  ciHandoffPackages: [ciHandoff],
  relaySoakPackages: [relaySoak],
  externalRelayIntegrationPackages: [externalRelayIntegration],
  externalProviderDiversityPackages: [externalProviderDiversity],
  evidencePackages: [callbackEvidencePackage],
  operationalSecretSamples: [
    'callback-secret-token',
    'callback-ci-secret',
    'relay-north-secret',
    'generic-http-provider-secret',
    'old-callback-secret',
    'pf-http-live',
  ],
  now: sample.now,
});
assertReportRoundTrip(reportRoundTrip, 'buildCallbackReportRoundTripPackage');

const collaboratorParityPackage = callbackEngine.buildCallbackCollaboratorParityEvidencePackage({
  payloads: [...pollResult.payloads, sample.expiredPayload],
  interactions: [...pollResult.interactions, sample.expiredInteraction],
  workspaces: [parityWorkspace],
  listenerProfiles: [profile],
  signedPollBatches: [pollResult.batch],
  evidencePackages: [callbackEvidencePackage],
  replayPackages: [replay, scannerReplay, exploitReplay],
  replayExecutionBatches: [executionBatch],
  lifecycleReviews: [lifecycle, prune.review],
  ciHandoffPackages: [ciHandoff],
  relaySoakPackages: [relaySoak],
  externalRelayIntegrationPackages: [externalRelayIntegration],
  externalProviderDiversityPackages: [externalProviderDiversity],
  reportRoundTripPackages: [reportRoundTrip],
  prunedInteractions: [sample.expiredInteraction],
  operationalSecretSamples: ['callback-secret-token', 'callback-ci-secret', 'old-callback-secret', 'pf-http-live'],
  exportedAt: sample.now,
});
assertCollaboratorParityEvidencePackage(collaboratorParityPackage, 'buildCallbackCollaboratorParityEvidencePackage');

const providerHostProofPackage = buildProviderHostProofPackage(sample, externalProviderDiversity);
const collaboratorRefreshPackage = callbackEngine.buildCallbackPackageRefreshEvidencePackage({
  collaboratorParityPackage,
  signedPollPackages: [pollResult.batch],
  replayPackages: [replay, scannerReplay, exploitReplay],
  replayExecutionPackages: [executionBatch],
  lifecyclePackages: [lifecycle, prune.review],
  ciHandoffPackages: [ciHandoff],
  relaySoakPackages: [relaySoak],
  externalRelayIntegrationPackages: [externalRelayIntegration],
  externalProviderDiversityPackages: [externalProviderDiversity],
  providerHostProofPackages: [providerHostProofPackage],
  reportRoundTripPackages: [reportRoundTrip],
  operationalSecretSamples: [
    'callback-secret-token',
    'callback-ci-secret',
    'relay-north-secret',
    'generic-http-provider-secret',
    'agent-provider-host-proof-token',
    'pf-http-live',
  ],
  generatedAt: sample.now,
});
assertCollaboratorPackageRefreshEvidencePackage(collaboratorRefreshPackage, 'buildCallbackPackageRefreshEvidencePackage');

const artifactDir = path.resolve('.gitignored/test-artifacts/callback-live-backend');
await fs.mkdir(artifactDir, { recursive: true });
await fs.writeFile(
  path.join(artifactDir, 'collaborator-parity-evidence-package.json'),
  `${collaboratorParityPackage.content}\n`,
);
await fs.writeFile(
  path.join(artifactDir, 'callback-report-roundtrip-package.json'),
  `${reportRoundTrip.content}\n`,
);
await fs.writeFile(
  path.join(artifactDir, 'collaborator-package-refresh-evidence-package.json'),
  `${collaboratorRefreshPackage.content}\n`,
);

console.log(`callback-live-backend-engine: exercised ${expectedExports.length} Callback live backend helper(s)`);

async function firstExistingPath(candidates) {
  for (const candidate of candidates) {
    const resolved = path.resolve(candidate);
    try {
      const stat = await fs.stat(resolved);
      if (stat.isFile()) return resolved;
    } catch {
      // Keep looking for an optional Callback engine export.
    }
  }
  return '';
}

async function loadEngine(enginePath) {
  if (enginePath.endsWith('.js') || enginePath.endsWith('.cjs')) {
    return require(enginePath);
  }

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
    TextDecoder,
    TextEncoder,
    URL,
    URLSearchParams,
    Buffer,
    console,
    crypto: globalThis.crypto,
    setTimeout,
    clearTimeout,
    require,
  };
  vm.runInNewContext(transpiled, sandbox, { filename: enginePath });
  return module.exports;
}

function normalizeModuleExports(moduleExports) {
  const hasNamedHelper = expectedExports.some((name) => typeof moduleExports[name] === 'function');
  if (hasNamedHelper) return moduleExports;
  if (moduleExports.default && typeof moduleExports.default === 'object') return moduleExports.default;
  return moduleExports;
}

function buildSampleCallbackLiveBackendRequest() {
  const now = '2026-05-24T17:30:00.000Z';
  const exchange = {
    id: 'hx-callback-import',
    method: 'POST',
    host: 'api.shop.local',
    path: '/v2/import',
    url: 'https://api.shop.local/v2/import',
    status: 202,
    length: 684,
    mime: 'application/json',
    risk: 'high',
    timing: 184,
    source: 'proxy',
    time: '17:28:42',
    requestRaw: [
      'POST /v2/import HTTP/2',
      'Host: api.shop.local',
      'Content-Type: application/json',
      'Authorization: Bearer callback-secret-token',
      '',
      '{"url":"CALLBACK_URL","mode":"server-side"}',
    ].join('\n'),
    responseRaw: [
      'HTTP/2 202 Accepted',
      'Content-Type: application/json',
      '',
      '{"job":"queued","worker":"import-worker"}',
    ].join('\n'),
    notes: 'Import endpoint accepts remote URLs and should preserve callback correlation.',
    tags: ['ssrf', 'oast', 'import'],
  };

  const payloads = [
    {
      id: 'cb-live-http',
      token: 'pf-http-live',
      label: 'Live HTTP import callback',
      protocol: 'http',
      endpoint: 'https://pf-http-live.callbacks.shop.local/probe',
      createdAt: '17:29:01',
      status: 'waiting',
      sourceExchangeId: exchange.id,
      sourceHost: exchange.host,
      sourcePath: exchange.path,
      notes: 'HTTP callback should produce DNS and HTTP interactions.',
    },
    {
      id: 'cb-live-dns-waiting',
      token: 'pf-dns-wait',
      label: 'Waiting DNS lifecycle canary',
      protocol: 'dns',
      endpoint: 'pf-dns-wait.callbacks.shop.local',
      createdAt: '17:29:08',
      status: 'waiting',
      sourceExchangeId: exchange.id,
      sourceHost: exchange.host,
      sourcePath: '/v2/status',
      notes: 'Waiting payload should stay visible in lifecycle review.',
    },
  ];

  const workspace = {
    id: 'callback-workspace-live',
    name: 'Retail import OAST workspace',
    createdAt: now,
    updatedAt: now,
    owner: 'ProxyForge CI',
    payloadIds: payloads.map((payload) => payload.id),
    interactionIds: [],
    sourceExchangeIds: [exchange.id],
    linkedIssueIds: [],
    linkedExploitRunIds: ['exploit-run-import'],
    protocols: ['dns', 'http'],
    severity: 'high',
    status: 'monitoring',
    notes: 'Live backend smoke workspace for callback CI handoff.',
  };

  const exploitRun = {
    id: 'exploit-run-import',
    title: 'Callback-assisted import validation',
    status: 'proof-ready',
    payloadPreview: 'https://pf-http-live.callbacks.shop.local/probe',
    logs: ['queued import with pf-http-live callback endpoint'],
    exchange,
  };

  const expiredPayload = {
    id: 'cb-expired',
    token: 'pf-expired',
    label: 'Expired OAST callback',
    protocol: 'http',
    endpoint: 'https://pf-expired.callbacks.shop.local/probe',
    createdAt: '2026-05-19T17:30:00.000Z',
    status: 'waiting',
    sourceExchangeId: exchange.id,
    sourceHost: exchange.host,
    sourcePath: '/v2/expired',
    notes: 'Expired callback should be archived by retention pruning.',
  };

  const expiredInteraction = {
    id: 'cb-int-expired-http',
    payloadId: expiredPayload.id,
    protocol: 'http',
    observedAt: '2026-05-19T18:30:00.000Z',
    sourceIp: '203.0.113.90',
    sourceHost: 'old-worker.shop.local',
    requestLine: 'GET /probe HTTP/1.1',
    userAgent: 'OldWorker/1.0',
    raw: 'GET /probe HTTP/1.1\nHost: pf-expired.callbacks.shop.local\nAuthorization: Bearer old-callback-secret',
    severity: 'high',
    tags: ['oast', 'http', 'expired'],
  };

  return {
    now,
    exchange,
    payloads,
    interactions: [],
    workspace,
    exploitRun,
    expiredPayload,
    expiredInteraction,
  };
}

function assertListenerProfile(profile, helperName) {
  const serialized = stringify(profile);
  assert.equal(profile.mode, 'hybrid-local', `${helperName} should preserve the requested listener mode`);
  assert.equal(profile.status, 'planned', `${helperName} should mark non-preview listener profiles as planned`);
  assert.equal(profile.protocols.join(','), 'dns,http,smtp', `${helperName} should enable DNS, HTTP, and SMTP for hybrid listeners`);
  assert.equal(profile.deploymentPlan.kind, 'proxyforge-callback-relay-deployment-plan', `${helperName} should include public relay deployment metadata`);
  assert.equal(profile.secretStorage.operationalSecretPolicy, 'full-fidelity-until-reporting', `${helperName} should keep executor secret policy explicit`);
  assert.ok(profile.deploymentPlan.dnsRecords.some((record) => record.includes('callbacks.shop.local')), `${helperName} should include relay DNS records`);
  assert.match(profile.ciCommand, /proxyforge oast poll.+--listener hybrid-local.+--report bundle/, `${helperName} should expose a CI poll command`);
  assert.match(serialized, /proxyforge-callback-live-listener-profile|signed polling|CI\/report handoff|proxyforge-callback-secret-storage-plan|proxyforge-callback-relay-deployment-plan/i, `${helperName} should expose live backend package content`);
}

function assertSignedPoll(result, helperName) {
  const serialized = stringify(result);
  assert.ok(result.newInteractions.length >= 2, `${helperName} should produce fresh DNS and protocol interactions for a waiting payload`);
  assert.equal(result.batch.status, 'observed', `${helperName} should mark observed poll batches`);
  assert.equal(result.batch.reportReady, true, `${helperName} should mark observed signed polls as report-ready`);
  assert.equal(result.batch.signature.status, 'signed', `${helperName} should sign when a signing secret is supplied`);
  assert.ok(result.batch.scannerIssueIds.includes('callback-cb-live-http'), `${helperName} should correlate callback scanner issue ids`);
  assert.ok(result.batch.exploitRunIds.includes('exploit-run-import'), `${helperName} should correlate exploit runs containing callback tokens`);
  assert.match(serialized, /proxyforge-callback-signed-poll-batch|HMAC-SHA256|workspaceIds|Retail import OAST/i, `${helperName} should keep signed poll package evidence`);
}

function assertCorrelationReplay(replay, helperName, targetTool = 'repeater') {
  const serialized = stringify(replay);
  assert.equal(replay.targetTool, targetTool, `${helperName} should keep the requested replay target`);
  assert.equal(replay.reportReady, true, `${helperName} should mark replay packages with interactions as report-ready`);
  assert.ok(replay.scannerIssueIds.includes('callback-cb-live-http'), `${helperName} should preserve scanner issue correlation links`);
  assert.ok(replay.exploitRunIds.includes('exploit-run-import'), `${helperName} should preserve exploit run correlation links`);
  assert.match(replay.replayRequestRaw, /https:\/\/pf-http-live\.callbacks\.shop\.local\/probe|X-ProxyForge-Callback/, `${helperName} should inject callback correlation into replay raw request`);
  assert.match(serialized, /proxyforge-callback-correlation-replay|callback-cb-live-http|exploit-run-import|scanner issue promotion|Reports evidence handoff/i, `${helperName} should preserve replay correlation context`);
}

function assertReplayExecutionBatch(batch, helperName) {
  const serialized = stringify(batch);
  assert.equal(batch.mode, 'local-verified', `${helperName} should preserve execution mode`);
  assert.equal(batch.status, 'completed', `${helperName} should complete verified target replays`);
  assert.equal(batch.completedCount, 3, `${helperName} should complete Repeater, Scanner, and Exploit Lab replay targets`);
  assert.equal(batch.verifiedCount, 3, `${helperName} should verify all targets against observed callback evidence`);
  assert.equal(batch.reportReady, true, `${helperName} should create report-ready execution evidence`);
  assert.ok(batch.targetResults.some((result) => result.targetTool === 'repeater' && result.command.includes('--target repeater')), `${helperName} should emit a Repeater command`);
  assert.ok(batch.targetResults.some((result) => result.targetTool === 'scanner' && result.verification.scannerIssueLinked), `${helperName} should verify Scanner issue links`);
  assert.ok(batch.targetResults.some((result) => result.targetTool === 'exploit-lab' && result.verification.exploitRunLinked), `${helperName} should verify Exploit Lab links`);
  assert.ok(batch.targetResults.every((result) => result.verification.scopeMatched), `${helperName} should pass scoped target hosts`);
  assert.match(serialized, /proxyforge-callback-replay-execution-batch|callback replay execution completed|--local-verify|observed callback interaction/i, `${helperName} should preserve execution evidence content`);
}

function assertLifecycleReview(review, helperName) {
  const serialized = stringify(review);
  assert.equal(review.retentionHours, 96, `${helperName} should preserve explicit retention`);
  assert.ok(review.observedPayloadIds.includes('cb-live-http'), `${helperName} should classify observed payloads`);
  assert.ok(review.waitingPayloadIds.includes('cb-live-dns-waiting'), `${helperName} should keep waiting payloads visible`);
  assert.ok(review.stalePayloadIds.includes('cb-live-dns-waiting'), `${helperName} should flag waiting payloads without interactions`);
  assert.ok(review.recommendedArchiveIds.includes('cb-live-http'), `${helperName} should recommend archiving observed exported payloads`);
  assert.equal(review.retentionActionCount, 0, `${helperName} should not prune fresh callback evidence`);
  assert.match(serialized, /proxyforge-callback-payload-lifecycle-review|archive observed payloads|signed poll batches|prune raw listener interactions/i, `${helperName} should expose lifecycle controls`);
}

function assertRetentionPrune(result, helperName) {
  const serialized = stringify(result);
  assert.ok(result.review.expiredPayloadIds.includes('cb-expired'), `${helperName} should identify expired payloads`);
  assert.ok(result.review.expiredInteractionIds.includes('cb-int-expired-http'), `${helperName} should identify expired raw interactions`);
  assert.equal(result.interactions.some((interaction) => interaction.id === 'cb-int-expired-http'), false, `${helperName} should prune expired raw interactions`);
  assert.equal(result.payloads.find((payload) => payload.id === 'cb-expired')?.status, 'archived', `${helperName} should archive expired payload provenance`);
  assert.match(serialized, /old-callback-secret/, `${helperName} should preserve operational raw secrets before report export`);
  assert.match(result.review.pruneSummary, /Prune 1 expired raw interaction/, `${helperName} should summarize retention pruning`);
}

function assertCiHandoff(handoff, helperName) {
  const serialized = stringify(handoff);
  assert.equal(handoff.provider, 'gitlab-ci', `${helperName} should preserve CI provider`);
  assert.equal(handoff.reportReady, true, `${helperName} should create report-ready handoffs`);
  assert.match(handoff.command, /proxyforge oast poll.+--report json --junit/, `${helperName} should use provider-specific CI flags`);
  assert.equal(handoff.env.PROXYFORGE_OAST_LISTENER, handoff.listenerProfileId, `${helperName} should bind the listener profile id into CI env`);
  assert.match(serialized, /proxyforge-callback-ci-handoff-package|GitLab CI|PROXYFORGE_OAST_PAYLOAD_IDS|Retail import OAST workspace/i, `${helperName} should preserve CI handoff evidence`);
}

function assertPublicRelaySoak(soak, helperName) {
  const serialized = stringify(soak);
  assert.equal(soak.status, 'pass', `${helperName} should pass when relay, poll, replay, lifecycle, and CI evidence meet budgets`);
  assert.equal(soak.reportReady, true, `${helperName} should mark passing relay soaks as report-ready`);
  assert.equal(soak.secretHandling, 'execution-full-fidelity-secrets-preserved', `${helperName} should preserve executor callback secrets`);
  assert.equal(soak.publicBaseUrl, 'callbacks.shop.local', `${helperName} should bind the public relay base`);
  assert.equal(soak.payloadCount, 3, `${helperName} should count full relay soak payloads`);
  assert.equal(soak.interactionCount, 3, `${helperName} should count raw relay soak interactions`);
  assert.equal(soak.observedProtocolCount, 3, `${helperName} should cover DNS, HTTP, and SMTP relay protocols from the listener profile`);
  assert.ok(soak.signedPollBatchIds.length >= 1, `${helperName} should link signed poll evidence`);
  assert.ok(soak.replayExecutionBatchIds.length >= 1, `${helperName} should link replay execution evidence`);
  assert.ok(soak.lifecycleReviewIds.length >= 1, `${helperName} should link lifecycle review evidence`);
  assert.ok(soak.ciHandoffPackageIds.length >= 1, `${helperName} should link CI handoff evidence`);
  assert.ok(soak.dnsRecords.some((record) => record.includes('callbacks.shop.local')), `${helperName} should include relay DNS records`);
  assert.match(serialized, /proxyforge-callback-public-relay-soak-package|proxyforge-callback-report-import-probe|proxyforge-callback-ci-handoff-package|proxyforge-callback-replay-execution-batch/i, `${helperName} should package relay soak and report import evidence`);
  assert.match(serialized, /old-callback-secret/, `${helperName} should keep raw callback secrets until report export`);
  assert.match(serialized, /proxyforge\/oast\/callback-ci-key|secretStorageRef|GET https:\/\/callbacks\.shop\.local\/healthz/i, `${helperName} should keep relay secret storage and health-check metadata`);
}

function assertExternalRelayIntegration(relay, helperName) {
  const serialized = stringify(relay);
  assert.equal(relay.kind, 'proxyforge-callback-external-relay-integration-package', `${helperName} should emit an external relay integration package`);
  assert.equal(relay.status, 'pass', `${helperName} should pass signed tenant-isolated relay polls`);
  assert.equal(relay.reportReady, true, `${helperName} should mark passing relay integration packages report-ready`);
  assert.equal(relay.secretHandling, 'execution-full-fidelity-secrets-preserved', `${helperName} should preserve executor callback secrets`);
  assert.equal(relay.reportRedactionBoundary, 'redact-only-during-report-export', `${helperName} should keep redaction at report export only`);
  assert.equal(relay.tenantCount, 2, `${helperName} should prove at least two tenants`);
  assert.equal(relay.leakedInteractionIds.length, 0, `${helperName} should not leak cross-tenant interactions`);
  assert.ok(relay.tenantPolls.every((poll) => poll.isolationStatus === 'isolated'), `${helperName} should isolate every tenant poll`);
  assert.ok(relay.tenantPolls.every((poll) => poll.signature.status === 'signed'), `${helperName} should preserve signed poll responses`);
  assert.match(serialized, /relay-north-secret|relay-south-secret|callback-ci-secret|old-callback-secret|pf-http-live/, `${helperName} should keep raw relay tokens and callback secrets before report export`);
  assert.match(serialized, /proxyforge-callback-external-relay-integration-package|retail-north|retail-south|redact-only-during-report-export/i, `${helperName} should package relay integration evidence`);
}

function assertExternalProviderDiversity(pkg, helperName) {
  const serialized = stringify(pkg);
  assert.equal(pkg.kind, 'proxyforge-callback-external-oast-provider-diversity-package', `${helperName} should emit an external provider diversity package`);
  assert.equal(pkg.status, 'pass', `${helperName} should pass signed isolated provider probes`);
  assert.equal(pkg.reportReady, true, `${helperName} should mark provider diversity packages report-ready`);
  assert.equal(pkg.providerCount, 3, `${helperName} should cover three providers`);
  assert.equal(pkg.protocolCount, 3, `${helperName} should cover DNS, HTTP, and SMTP provider shapes`);
  assert.equal(pkg.linkedRelayIntegrationPackageIds.length, 1, `${helperName} should link relay integration evidence`);
  assert.equal(pkg.leakedInteractionIds.length, 0, `${helperName} should not leak cross-provider interactions`);
  assert.ok(pkg.providerProbes.every((probe) => probe.isolationStatus === 'isolated' && probe.signature.status === 'signed'), `${helperName} should keep every provider probe signed and isolated`);
  assert.match(serialized, /generic-http-provider-secret|dns-webhook-provider-secret|smtp-relay-provider-secret|pf-http-live|old-callback-secret/, `${helperName} should preserve provider and callback secrets before report export`);
  assert.match(serialized, /generic-http-relay|dns-webhook-relay|smtp-relay|redact-only-during-report-export/i, `${helperName} should package provider diversity evidence`);
}

function assertReportRoundTrip(pkg, helperName) {
  const serialized = stringify(pkg);
  const failedRequirements = Object.entries(pkg.requirements).filter(([, value]) => !value).map(([name]) => name);
  assert.equal(pkg.kind, 'proxyforge-callback-report-roundtrip-package', `${helperName} should emit a callback report round-trip package`);
  assert.equal(pkg.status, 'pass', `${helperName} should pass when every callback artifact survives report import`);
  assert.equal(pkg.reportReady, true, `${helperName} should mark passing report round trips report-ready`);
  assert.deepEqual(failedRequirements, [], `${helperName} should satisfy every callback report round-trip requirement`);
  assert.equal(pkg.reportPackageKind, 'proxyforge-full-report-package', `${helperName} should bind to full report packages`);
  assert.equal(pkg.missingArtifactIds.length, 0, `${helperName} should not miss any callback artifact ids`);
  assert.ok(pkg.artifactManifest.signedPollBatchIds.length >= 1, `${helperName} should preserve signed poll batches`);
  assert.ok(pkg.artifactManifest.correlationReplayIds.length >= 3, `${helperName} should preserve Repeater, Scanner, and Exploit replay packages`);
  assert.ok(pkg.artifactManifest.externalRelayIntegrationPackageIds.length >= 1, `${helperName} should preserve external relay integration packages`);
  assert.ok(pkg.artifactManifest.externalProviderDiversityPackageIds.length >= 1, `${helperName} should preserve external provider diversity packages`);
  assert.equal(pkg.artifactManifest.importedArtifactCount, pkg.artifactManifest.totalArtifactCount, `${helperName} should import every tracked callback artifact`);
  assert.equal(pkg.secretHandling, 'execution-full-fidelity-secrets-preserved', `${helperName} should preserve executor callback secrets before reporting`);
  assert.equal(pkg.reportRedactionBoundary, 'redact-only-during-report-export', `${helperName} should only redact at report export`);
  assert.match(serialized, /callback-secret-token|callback-ci-secret|relay-north-secret|generic-http-provider-secret|pf-http-live/, `${helperName} should record pre-export operational secret samples`);
  assert.doesNotMatch(pkg.content, /"reportExportRedacted": false|missingArtifactIds": \[\s*"/, `${helperName} should not record redaction or import gaps`);
}

function assertCollaboratorParityEvidencePackage(pkg, helperName) {
  const serialized = stringify(pkg);
  const failedRequirements = Object.entries(pkg.requirements).filter(([, value]) => !value).map(([name]) => name);
  assert.equal(pkg.kind, 'proxyforge-collaborator-parity-evidence-package', `${helperName} should emit a Collaborator parity evidence package`);
  assert.deepEqual(failedRequirements, [], `${helperName} should satisfy every Collaborator/OAST parity requirement`);
  assert.equal(pkg.reportReady, true, `${helperName} should mark parity packages report-ready when all requirements pass`);
  assert.equal(pkg.secretHandling, 'execution-full-fidelity-secrets-preserved', `${helperName} should keep executor callback secrets intact`);
  assert.equal(pkg.reportRedactionBoundary, 'redact-only-during-report-export', `${helperName} should keep redaction at report export only`);
  assert.ok(pkg.artifactIds.listenerProfileIds.some((id) => id.startsWith('callback-listener-')), `${helperName} should link listener profile evidence`);
  assert.ok(pkg.artifactIds.evidencePackageIds.includes('callback-evidence-live'), `${helperName} should link signed report evidence packages`);
  assert.ok(pkg.artifactIds.externalRelayIntegrationPackageIds.length >= 1, `${helperName} should link external relay integration packages`);
  assert.ok(pkg.artifactIds.externalProviderDiversityPackageIds.length >= 1, `${helperName} should link external provider diversity packages`);
  assert.ok(pkg.artifactIds.reportRoundTripPackageIds.length >= 1, `${helperName} should link report round-trip packages`);
  assert.ok(pkg.artifactIds.replayPackageIds.length >= 3, `${helperName} should link Repeater, Scanner, and Exploit replay packages`);
  assert.match(serialized, /callback-secret-token|callback-ci-secret|old-callback-secret|pf-http-live/, `${helperName} should preserve operational callback tokens and keys`);
  assert.match(serialized, /payloadGenerationCovered|dnsHttpSmtpProtocolsCovered|externalRelayTenantIsolationCovered|externalProviderDiversityCovered|reportPackageRoundTripCovered|scannerExploitRepeaterStagingCovered|reportPackagePersistenceCovered|callbackSecretsPreserved/i, `${helperName} should expose parity requirement coverage`);
  assert.match(pkg.content, /proxyforge-callback-report-import-probe|proxyforge-callback-public-relay-soak-package|proxyforge-callback-external-relay-integration-package|proxyforge-callback-external-oast-provider-diversity-package|proxyforge-callback-report-roundtrip-package|proxyforge-callback-evidence-package/i, `${helperName} should keep report/import persistence evidence`);
}

function buildProviderHostProofPackage(sample, externalProviderDiversity) {
  const content = JSON.stringify({
    kind: 'proxyforge-agent-callback-provider-host-proof-package',
    providerCount: 2,
    protocolCount: 2,
    interactionCount: 2,
    linkedExternalProviderDiversityPackageId: externalProviderDiversity.id,
    rawProviderRequests: [
      'GET /provider/generic-http/poll HTTP/1.1\nHost: generic-http-oast.example.test\nAuthorization: Bearer agent-provider-host-proof-token\n',
      'GET /provider/dns-webhook/poll HTTP/1.1\nHost: dns-webhook-oast.example.test\nAuthorization: Bearer generic-http-provider-secret\n',
    ],
    rawProviderResponses: [
      'HTTP/1.1 200 OK\nX-ProxyForge-Signature: provider-host-proof\n\n{"payloadToken":"pf-http-live","callbackSecret":"callback-secret-token"}',
      'HTTP/1.1 200 OK\nX-ProxyForge-Signature: provider-host-proof-dns\n\n{"payloadToken":"pf-dns-wait","signingSecret":"callback-ci-secret"}',
    ],
    interactions: sample.interactions,
    requirements: {
      providerHostScopeCovered: true,
      externalHostRequestsCovered: true,
      signedPollsCovered: true,
      tenantIsolationCovered: true,
      rawExecutorMaterialPreserved: true,
      operationalSecretsPreserved: true,
      reportPhaseOnlyRedaction: true,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  }, null, 2);
  return {
    id: 'callback-provider-host-proof-live',
    kind: 'proxyforge-agent-callback-provider-host-proof-package',
    reportReady: true,
    content,
  };
}

function assertCollaboratorPackageRefreshEvidencePackage(pkg, helperName) {
  const serialized = stringify(pkg);
  const failedRequirements = Object.entries(pkg.requirements).filter(([, value]) => !value).map(([name]) => name);
  assert.equal(pkg.kind, 'proxyforge-collaborator-package-refresh-evidence-package', `${helperName} should emit a Collaborator/OAST package-refresh package`);
  assert.deepEqual(failedRequirements, [], `${helperName} should satisfy every Collaborator/OAST package-refresh requirement`);
  assert.equal(pkg.reportReady, true, `${helperName} should mark package-refresh evidence report-ready when every source package is fresh`);
  assert.equal(pkg.secretHandling, 'execution-full-fidelity-secrets-preserved', `${helperName} should keep callback secrets full-fidelity`);
  assert.equal(pkg.reportRedactionBoundary, 'redact-only-during-report-export', `${helperName} should keep redaction at report export only`);
  assert.equal(pkg.packageRefreshProof.stalePackageIds.length, 0, `${helperName} should not link stale callback packages`);
  assert.ok(pkg.packageRefreshProof.linkedPackageDigests.length >= 11, `${helperName} should link the callback parity, replay, relay, provider, and report packages`);
  for (const kind of [
    'proxyforge-collaborator-parity-evidence-package',
    'proxyforge-callback-signed-poll-batch',
    'proxyforge-callback-correlation-replay',
    'proxyforge-callback-replay-execution-batch',
    'proxyforge-callback-payload-lifecycle-review',
    'proxyforge-callback-ci-handoff-package',
    'proxyforge-callback-public-relay-soak-package',
    'proxyforge-callback-external-relay-integration-package',
    'proxyforge-callback-external-oast-provider-diversity-package',
    'proxyforge-agent-callback-provider-host-proof-package',
    'proxyforge-callback-report-roundtrip-package',
  ]) {
    assert.ok(pkg.linkedPackageKinds.includes(kind), `${helperName} should link ${kind}`);
  }
  assert.match(serialized, /callback-secret-token|callback-ci-secret|relay-north-secret|generic-http-provider-secret|agent-provider-host-proof-token|pf-http-live/, `${helperName} should preserve raw callback and provider secrets before report export`);
  assert.match(pkg.content, /packageRefreshProof|stalePackageIds|providerHostProofRefreshCovered|externalProviderDiversityRefreshCovered|reportRoundTripRefreshCovered|redact-only-during-report-export/i, `${helperName} should expose refresh proof, stale checks, provider coverage, report round-trip coverage, and redaction boundary`);
}

function buildFullReportPackageContent(options) {
  const callbackArtifactManifest = {
    signedPollBatchIds: options.signedPollBatches.map((item) => item.id),
    correlationReplayIds: options.replayPackages.map((item) => item.id),
    replayExecutionBatchIds: options.replayExecutionBatches.map((item) => item.id),
    lifecycleReviewIds: options.lifecycleReviews.map((item) => item.id),
    ciHandoffPackageIds: options.ciHandoffPackages.map((item) => item.id),
    publicRelaySoakPackageIds: options.relaySoakPackages.map((item) => item.id),
    externalRelayIntegrationPackageIds: options.externalRelayIntegrationPackages.map((item) => item.id),
    externalProviderDiversityPackageIds: options.externalProviderDiversityPackages.map((item) => item.id),
    evidencePackageIds: options.evidencePackages.map((item) => item.id),
  };
  return JSON.stringify({
    kind: 'proxyforge-full-report-package',
    projectName: 'Retail import OAST workspace',
    callbackArtifactManifest: {
      ...callbackArtifactManifest,
      totalArtifactCount: Object.values(callbackArtifactManifest).flat().length,
      summary: 'Imported report package preserves callback signed polls, replays, relay soaks, external relay/provider diversity, and evidence packages before report export redaction.',
    },
    callbackSignedPollBatches: options.signedPollBatches,
    callbackCorrelationReplays: options.replayPackages,
    callbackReplayExecutionBatches: options.replayExecutionBatches,
    callbackLifecycleReviews: options.lifecycleReviews,
    callbackCiHandoffPackages: options.ciHandoffPackages,
    callbackPublicRelaySoakPackages: options.relaySoakPackages,
    callbackExternalRelayIntegrationPackages: options.externalRelayIntegrationPackages,
    callbackExternalProviderDiversityPackages: options.externalProviderDiversityPackages,
    callbackEvidencePackages: options.evidencePackages,
    signature: {
      algorithm: 'HMAC-SHA256',
      signerName: 'ProxyForge CI',
      keyId: 'callback-ci-key',
      status: 'signed',
      digestPreview: 'callback-report-roundtrip-digest',
    },
  }, null, 2);
}

function stringify(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}
