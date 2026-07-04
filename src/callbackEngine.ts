import type {
  CallbackCiHandoffPackage,
  CallbackCiProvider,
  CallbackCorrelationReplayPackage,
  CallbackEvidencePackage,
  CallbackExternalOastProviderDiversityPackage,
  CallbackExternalOastProviderKind,
  CallbackExternalOastProviderProbe,
  CallbackExternalRelayIntegrationPackage,
  CallbackExternalRelayTenantPoll,
  CallbackInteraction,
  CallbackListenerMode,
  CallbackListenerProfile,
  CallbackPayload,
  CallbackPayloadLifecycleReview,
  CallbackPublicRelaySoakPackage,
  CallbackReportRoundTripPackage,
  CallbackProtocol,
  CallbackReplayExecutionBatch,
  CallbackReplayExecutionMode,
  CallbackReplayExecutionResult,
  CallbackReplayExecutionStatus,
  CallbackSignedPollBatch,
  CallbackWorkspace,
  ExploitRun,
  HttpExchange,
  Issue,
  Severity,
} from './types';

export const CALLBACK_SERVER_HOST = 'oast.proxyforge.local';

export interface CallbackCollaboratorParityEvidenceRequest {
  payloads: CallbackPayload[];
  interactions: CallbackInteraction[];
  workspaces: CallbackWorkspace[];
  listenerProfiles: CallbackListenerProfile[];
  signedPollBatches: CallbackSignedPollBatch[];
  evidencePackages: CallbackEvidencePackage[];
  replayPackages: CallbackCorrelationReplayPackage[];
  replayExecutionBatches: CallbackReplayExecutionBatch[];
  lifecycleReviews: CallbackPayloadLifecycleReview[];
  ciHandoffPackages: CallbackCiHandoffPackage[];
  relaySoakPackages: CallbackPublicRelaySoakPackage[];
  externalRelayIntegrationPackages?: CallbackExternalRelayIntegrationPackage[];
  externalProviderDiversityPackages?: CallbackExternalOastProviderDiversityPackage[];
  reportRoundTripPackages?: CallbackReportRoundTripPackage[];
  prunedInteractions?: CallbackInteraction[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface CallbackExternalOastProviderProbeInput {
  providerId: string;
  providerName?: string;
  providerKind: CallbackExternalOastProviderKind;
  tenantId: string;
  baseUrl: string;
  publicBaseUrl?: string;
  protocol: CallbackProtocol;
  payloadIds: string[];
  interactions: CallbackInteraction[];
  statusCode: number;
  rawRequest: string;
  rawResponse: string;
  replaySupported?: boolean;
  signature?: {
    algorithm?: 'HMAC-SHA256';
    keyId?: string;
    status?: 'signed' | 'invalid' | 'missing';
    digestPreview?: string;
  };
}

export interface CallbackExternalRelayTenantPollInput {
  tenantId: string;
  relayBaseUrl: string;
  publicBaseUrl?: string;
  payloadIds: string[];
  interactions: CallbackInteraction[];
  statusCode: number;
  rawRequest: string;
  rawResponse: string;
  signature?: {
    algorithm?: 'HMAC-SHA256';
    keyId?: string;
    status?: 'signed' | 'invalid' | 'missing';
    digestPreview?: string;
  };
}

export interface CallbackCollaboratorParityEvidencePackage {
  id: string;
  kind: 'proxyforge-collaborator-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  payloadCount: number;
  interactionCount: number;
  workspaceCount: number;
  listenerProfileCount: number;
  replayPackageCount: number;
  replayExecutionBatchCount: number;
  artifactIds: {
    payloadIds: string[];
    interactionIds: string[];
    workspaceIds: string[];
    listenerProfileIds: string[];
    signedPollBatchIds: string[];
    evidencePackageIds: string[];
    replayPackageIds: string[];
    replayExecutionBatchIds: string[];
    lifecycleReviewIds: string[];
    ciHandoffPackageIds: string[];
    relaySoakPackageIds: string[];
    externalRelayIntegrationPackageIds: string[];
    externalProviderDiversityPackageIds: string[];
    reportRoundTripPackageIds: string[];
  };
  requirements: {
    payloadGenerationCovered: boolean;
    dnsHttpSmtpProtocolsCovered: boolean;
    interactionPollingCovered: boolean;
    oastWorkspaceOwnershipCovered: boolean;
    signedEvidencePackagesCovered: boolean;
    localListenerBackendCovered: boolean;
    publicRelaySoakCovered: boolean;
    externalRelayTenantIsolationCovered: boolean;
    externalProviderDiversityCovered: boolean;
    retentionPruneCovered: boolean;
    correlationReplayCovered: boolean;
    scannerExploitRepeaterStagingCovered: boolean;
    automatedReplayExecutionCovered: boolean;
    ciHandoffCovered: boolean;
    reportPackagePersistenceCovered: boolean;
    reportPackageRoundTripCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    callbackSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export interface CallbackLinkedEvidencePackage {
  id?: string;
  kind?: string;
  content?: string;
  summary?: string;
  reportReady?: boolean;
  status?: string;
  requirements?: Record<string, boolean>;
}

export interface CallbackPackageRefreshEvidenceRequest {
  collaboratorParityPackage: CallbackLinkedEvidencePackage;
  signedPollPackages?: CallbackLinkedEvidencePackage[];
  replayPackages?: CallbackLinkedEvidencePackage[];
  replayExecutionPackages?: CallbackLinkedEvidencePackage[];
  lifecyclePackages?: CallbackLinkedEvidencePackage[];
  ciHandoffPackages?: CallbackLinkedEvidencePackage[];
  relaySoakPackages?: CallbackLinkedEvidencePackage[];
  externalRelayIntegrationPackages?: CallbackLinkedEvidencePackage[];
  externalProviderDiversityPackages?: CallbackLinkedEvidencePackage[];
  providerHostProofPackages?: CallbackLinkedEvidencePackage[];
  reportRoundTripPackages?: CallbackLinkedEvidencePackage[];
  generatedAt?: string;
  operationalSecretSamples?: string[];
}

export interface CallbackPackageRefreshEvidencePackage {
  id: string;
  kind: 'proxyforge-collaborator-package-refresh-evidence-package';
  title: string;
  fileName: string;
  path: string;
  generatedAt: string;
  linkedPackageKinds: string[];
  packageRefreshProof: {
    refreshedAt: string;
    requiredPackageKinds: string[];
    linkedPackageIds: string[];
    linkedPackageKinds: string[];
    linkedPackageDigests: Array<{
      id: string;
      kind: string;
      digest: string;
      reportReady: boolean;
      sourceLength: number;
    }>;
    stalePackageIds: string[];
    freshDigest: string;
    rawMaterialDigestPreview: string;
  };
  requirements: {
    collaboratorParityRefreshCovered: boolean;
    signedPollingRefreshCovered: boolean;
    replayCorrelationRefreshCovered: boolean;
    replayExecutionRefreshCovered: boolean;
    lifecycleRetentionRefreshCovered: boolean;
    ciHandoffRefreshCovered: boolean;
    relaySoakRefreshCovered: boolean;
    externalRelayRefreshCovered: boolean;
    externalProviderDiversityRefreshCovered: boolean;
    providerHostProofRefreshCovered: boolean;
    reportRoundTripRefreshCovered: boolean;
    packageRefreshCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    callbackSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export const callbackProtocolLabels: Record<CallbackProtocol, string> = {
  dns: 'DNS lookup',
  http: 'HTTP request',
  smtp: 'SMTP message',
};

export const callbackListenerModeLabels: Record<CallbackListenerMode, string> = {
  'browser-preview': 'Browser preview simulator',
  'local-http': 'Local HTTP listener',
  'local-dns': 'Local DNS listener',
  'local-smtp': 'Local SMTP listener',
  'hybrid-local': 'Hybrid local listeners',
};

export const callbackCiProviderLabels: Record<CallbackCiProvider, string> = {
  'github-actions': 'GitHub Actions',
  'gitlab-ci': 'GitLab CI',
  'azure-pipelines': 'Azure Pipelines',
  jenkins: 'Jenkins',
};

export const seedCallbackPayloads: CallbackPayload[] = [
  {
    id: 'cb-payload-import',
    token: 'pf-import-7b42',
    label: 'Import URL SSRF probe',
    protocol: 'http',
    endpoint: 'https://pf-import-7b42.oast.proxyforge.local/import',
    createdAt: '13:21:41',
    status: 'observed',
    sourceExchangeId: 'hx-1034',
    sourceHost: 'api.shop.local',
    sourcePath: '/v2/graphql',
    notes: 'Queued import callback can confirm outbound fetch behavior.',
  },
  {
    id: 'cb-payload-dns',
    token: 'pf-dns-a19c',
    label: 'Resolver-only canary',
    protocol: 'dns',
    endpoint: 'pf-dns-a19c.oast.proxyforge.local',
    createdAt: '13:22:07',
    status: 'waiting',
    sourceExchangeId: 'hx-1032',
    sourceHost: 'app.shop.local',
    sourcePath: '/api/refunds',
    notes: 'Safe DNS-only probe waiting for interaction.',
  },
];

export const seedCallbackInteractions: CallbackInteraction[] = [
  {
    id: 'cb-int-import-dns',
    payloadId: 'cb-payload-import',
    protocol: 'dns',
    observedAt: '13:22:18',
    sourceIp: '198.51.100.53',
    sourceHost: 'resolver-02.shop.local',
    requestLine: 'pf-import-7b42.oast.proxyforge.local A',
    userAgent: 'recursive-resolver',
    raw: 'DNS A query for pf-import-7b42.oast.proxyforge.local from resolver-02.shop.local',
    severity: 'medium',
    tags: ['oast', 'dns', 'ssrf-signal'],
  },
  {
    id: 'cb-int-import-http',
    payloadId: 'cb-payload-import',
    protocol: 'http',
    observedAt: '13:22:19',
    sourceIp: '203.0.113.42',
    sourceHost: 'import-worker-02.shop.local',
    requestLine: 'GET /import HTTP/1.1',
    userAgent: 'ShopImportWorker/2.4',
    raw: 'GET /import HTTP/1.1\nHost: pf-import-7b42.oast.proxyforge.local\nUser-Agent: ShopImportWorker/2.4\nX-Job-Id: import_1842',
    severity: 'high',
    tags: ['oast', 'http', 'ssrf-confirmed'],
  },
];

export function createCallbackPayload(options: {
  protocol: CallbackProtocol;
  label: string;
  exchange: HttpExchange;
  serverHost?: string;
}): CallbackPayload {
  const now = new Date();
  const token = makeCallbackToken(options.protocol);
  const endpoint = buildCallbackEndpoint(options.protocol, token, options.serverHost ?? CALLBACK_SERVER_HOST);

  return {
    id: `cb-payload-${now.getTime()}`,
    token,
    label: options.label.trim() || `${options.exchange.method} ${options.exchange.path} callback probe`,
    protocol: options.protocol,
    endpoint,
    createdAt: now.toLocaleTimeString([], { hour12: false }),
    status: 'waiting',
    sourceExchangeId: options.exchange.id,
    sourceHost: options.exchange.host,
    sourcePath: options.exchange.path,
    notes: `Correlated with ${options.exchange.method} ${options.exchange.host}${options.exchange.path}`,
  };
}

export function buildCallbackEndpoint(protocol: CallbackProtocol, token: string, host = CALLBACK_SERVER_HOST) {
  if (protocol === 'dns') return `${token}.${host}`;
  if (protocol === 'smtp') return `${token}@${host}`;
  return `https://${token}.${host}/probe`;
}

export function buildCallbackStats(payloads: CallbackPayload[], interactions: CallbackInteraction[]) {
  return {
    totalPayloads: payloads.length,
    waiting: payloads.filter((payload) => payload.status === 'waiting').length,
    observed: payloads.filter((payload) => payload.status === 'observed').length,
    archived: payloads.filter((payload) => payload.status === 'archived').length,
    interactions: interactions.length,
  };
}

export function simulateCallbackPoll(
  payloads: CallbackPayload[],
  existingInteractions: CallbackInteraction[],
  fallbackExchange: HttpExchange,
) {
  const target = payloads.find((payload) => payload.status === 'waiting') ?? payloads[0];
  if (!target) {
    return {
      payloads,
      interactions: existingInteractions,
      newInteractions: [],
      message: 'No callback payloads are available to poll.',
    };
  }

  if (existingInteractions.some((interaction) => interaction.payloadId === target.id)) {
    return {
      payloads,
      interactions: existingInteractions,
      newInteractions: [],
      message: `No new interactions for ${target.token}.`,
    };
  }

  const newInteractions = makePreviewInteractions(target, fallbackExchange);
  return {
    payloads: payloads.map((payload) => (
      payload.id === target.id
        ? { ...payload, status: 'observed' as const, lastInteractionAt: newInteractions[0]?.observedAt }
        : payload
    )),
    interactions: [...newInteractions, ...existingInteractions],
    newInteractions,
    message: `Observed ${newInteractions.length} ${newInteractions.length === 1 ? 'interaction' : 'interactions'} for ${target.token}.`,
  };
}

export function issuesFromCallbackInteractions(payloads: CallbackPayload[], interactions: CallbackInteraction[]): Issue[] {
  return payloads.flatMap((payload) => {
    const matches = interactions.filter((interaction) => interaction.payloadId === payload.id);
    if (matches.length === 0 || payload.status === 'archived') return [];

    const hasHttp = matches.some((interaction) => interaction.protocol === 'http' || interaction.protocol === 'smtp');
    const strongest = matches.find((interaction) => interaction.protocol === 'http' || interaction.protocol === 'smtp') ?? matches[0];
    const protocols = Array.from(new Set(matches.map((interaction) => callbackProtocolLabels[interaction.protocol]))).join(', ');

    return [{
      id: `callback-${payload.id}`,
      title: hasHttp ? 'Out-of-band callback interaction confirmed' : 'Out-of-band DNS interaction observed',
      severity: hasHttp ? 'high' : 'medium',
      host: payload.sourceHost ?? strongest.sourceHost,
      path: payload.sourcePath ?? '/out-of-band',
      confidence: hasHttp ? 'firm' : 'tentative',
      status: 'open',
      detail: `${payload.label} received ${matches.length} interaction(s): ${protocols}. Latest source ${strongest.sourceIp} (${strongest.sourceHost}) requested ${strongest.requestLine}.`,
      remediation: 'Disable arbitrary outbound fetches, enforce destination allowlists, and route import/webhook fetchers through egress controls with audit logging.',
    } satisfies Issue];
  });
}

export function injectCallbackIntoRawRequest(rawRequest: string, endpoint: string) {
  if (rawRequest.includes('CALLBACK_URL')) return rawRequest.replace(/CALLBACK_URL/g, endpoint);
  const separator = rawRequest.includes('\r\n\r\n') ? '\r\n\r\n' : '\n\n';
  const header = rawRequest.includes('\r\n') ? `\r\nX-ProxyForge-Callback: ${endpoint}` : `\nX-ProxyForge-Callback: ${endpoint}`;
  if (!rawRequest.includes(separator)) return `${rawRequest}${header}\n\n`;
  return rawRequest.replace(separator, `${header}${separator}`);
}

export function buildCallbackListenerProfile(options: {
  mode: CallbackListenerMode;
  host: string;
  publicBaseUrl: string;
  httpPort: number;
  dnsPort: number;
  smtpPort: number;
  pollIntervalSeconds: number;
  retentionHours: number;
  signingKeyId: string;
  now?: string;
}): CallbackListenerProfile {
  const createdAt = options.now ?? new Date().toISOString();
  const protocols = protocolsForListenerMode(options.mode);
  const host = options.host.trim() || '127.0.0.1';
  const publicBaseUrl = options.publicBaseUrl.trim() || CALLBACK_SERVER_HOST;
  const signingKeyId = options.signingKeyId.trim() || 'callback-local';
  const healthChecks = [
    `HTTP listener ${protocols.includes('http') ? `ready on ${host}:${options.httpPort}` : 'disabled'}`,
    `DNS listener ${protocols.includes('dns') ? `ready on ${host}:${options.dnsPort}` : 'disabled'}`,
    `SMTP listener ${protocols.includes('smtp') ? `ready on ${host}:${options.smtpPort}` : 'disabled'}`,
    `Signed polling interval ${options.pollIntervalSeconds}s, retention ${options.retentionHours}h`,
  ];
  const retentionHours = Math.max(1, Math.floor(options.retentionHours || 72));
  const secretStorage = {
    kind: 'proxyforge-callback-secret-storage-plan' as const,
    mode: 'os-keychain' as const,
    signingKeyId,
    secretRef: `proxyforge/oast/${signingKeyId}`,
    rotationDays: 30,
    operationalSecretPolicy: 'full-fidelity-until-reporting' as const,
  };
  const deploymentPlan = {
    kind: 'proxyforge-callback-relay-deployment-plan' as const,
    publicBaseUrl,
    protocols,
    dnsRecords: buildRelayDnsRecords(publicBaseUrl, protocols),
    routes: buildRelayRoutes(publicBaseUrl, protocols),
    healthChecks: [
      `GET https://${publicBaseUrl}/healthz`,
      protocols.includes('dns') ? `DNS wildcard query *.${publicBaseUrl}` : 'DNS relay disabled',
      protocols.includes('smtp') ? `SMTP RCPT probe *@${publicBaseUrl}` : 'SMTP relay disabled',
    ],
    retentionHours,
    secretStorageRef: secretStorage.secretRef,
  };
  const profileSeed = JSON.stringify({ ...options, host, publicBaseUrl, signingKeyId, protocols, createdAt });
  const digestPreview = simpleDigest(profileSeed);
  const ciCommand = [
    'proxyforge oast poll',
    `--listener ${options.mode}`,
    `--host ${host}`,
    `--http-port ${options.httpPort}`,
    `--dns-port ${options.dnsPort}`,
    `--smtp-port ${options.smtpPort}`,
    `--signing-key-id ${signingKeyId}`,
    '--report bundle',
  ].join(' ');
  const content = JSON.stringify({
    kind: 'proxyforge-callback-live-listener-profile',
    createdAt,
    mode: options.mode,
    label: callbackListenerModeLabels[options.mode],
    host,
    publicBaseUrl,
    protocols,
    ports: {
      http: options.httpPort,
      dns: options.dnsPort,
      smtp: options.smtpPort,
    },
    pollIntervalSeconds: options.pollIntervalSeconds,
    retentionHours,
    signingKeyId,
    secretStorage,
    deploymentPlan,
    ciCommand,
    healthChecks,
    digestPreview,
  }, null, 2);

  return {
    id: `callback-listener-${digestPreview.slice(0, 12)}`,
    name: `${callbackListenerModeLabels[options.mode]} ${host}`,
    createdAt,
    mode: options.mode,
    status: options.mode === 'browser-preview' ? 'running' : 'planned',
    host,
    publicBaseUrl,
    protocols,
    httpPort: clampPort(options.httpPort, 8088),
    dnsPort: clampPort(options.dnsPort, 5353),
    smtpPort: clampPort(options.smtpPort, 2525),
    pollIntervalSeconds: Math.max(5, Math.floor(options.pollIntervalSeconds || 30)),
    retentionHours,
    signingKeyId,
    ciCommand,
    healthChecks,
    deploymentPlan,
    secretStorage,
    summary: `${callbackListenerModeLabels[options.mode]} planned for ${protocols.map((protocol) => callbackProtocolLabels[protocol]).join(', ')} with signed polling and CI/report handoff metadata.`,
    content,
  };
}

export function pollCallbackLiveInteractions(options: {
  profile: CallbackListenerProfile;
  payloads: CallbackPayload[];
  interactions: CallbackInteraction[];
  fallbackExchange: HttpExchange;
  workspaces?: CallbackWorkspace[];
  exploitRuns?: ExploitRun[];
  signerName?: string;
  signingSecret?: string;
  now?: string;
}) {
  const createdAt = options.now ?? new Date().toISOString();
  const result = simulateCallbackPoll(options.payloads, options.interactions, options.fallbackExchange);
  const batch = buildCallbackSignedPollBatch({
    profile: options.profile,
    payloads: result.payloads,
    interactions: result.interactions,
    newInteractions: result.newInteractions,
    workspaces: options.workspaces,
    exploitRuns: options.exploitRuns,
    signerName: options.signerName,
    signingSecret: options.signingSecret,
    now: createdAt,
    summary: result.message,
  });

  return {
    payloads: result.payloads,
    interactions: result.interactions,
    newInteractions: result.newInteractions,
    batch,
  };
}

export function buildCallbackSignedPollBatch(options: {
  profile: CallbackListenerProfile;
  payloads: CallbackPayload[];
  interactions: CallbackInteraction[];
  newInteractions: CallbackInteraction[];
  workspaces?: CallbackWorkspace[];
  exploitRuns?: ExploitRun[];
  signerName?: string;
  signingSecret?: string;
  now?: string;
  summary?: string;
}): CallbackSignedPollBatch {
  const createdAt = options.now ?? new Date().toISOString();
  const payloadIds = options.payloads.map((payload) => payload.id);
  const newPayloadIds = Array.from(new Set(options.newInteractions.map((interaction) => interaction.payloadId)));
  const scannerIssueIds = newPayloadIds.map((id) => `callback-${id}`);
  const exploitRunIds = correlateExploitRuns(options.payloads, options.newInteractions, options.exploitRuns ?? []);
  const unsigned = {
    kind: 'proxyforge-callback-signed-poll-batch',
    createdAt,
    listenerProfileId: options.profile.id,
    listenerMode: options.profile.mode,
    payloadIds,
    interactionIds: options.interactions.map((interaction) => interaction.id),
    newInteractionIds: options.newInteractions.map((interaction) => interaction.id),
    scannerIssueIds,
    exploitRunIds,
    workspaceIds: (options.workspaces ?? []).filter((workspace) => (
      workspace.payloadIds.some((payloadId) => payloadIds.includes(payloadId))
    )).map((workspace) => workspace.id),
    summary: options.summary ?? `Collected ${options.newInteractions.length} new callback interaction(s).`,
  };
  const digestPreview = simpleDigest(JSON.stringify({ ...unsigned, signingSecret: options.signingSecret ? '[present]' : '[not supplied]' }));
  const content = JSON.stringify({
    ...unsigned,
    signature: {
      algorithm: 'HMAC-SHA256',
      signerName: options.signerName?.trim() || options.profile.name,
      keyId: options.profile.signingKeyId,
      status: options.signingSecret ? 'signed' : 'ready-on-export',
      digestPreview,
    },
  }, null, 2);
  const batch: CallbackSignedPollBatch = {
    id: `callback-poll-${digestPreview.slice(0, 12)}`,
    title: 'Callback signed interaction poll',
    createdAt,
    listenerProfileId: options.profile.id,
    payloadIds,
    interactionIds: options.interactions.map((interaction) => interaction.id),
    newInteractionIds: options.newInteractions.map((interaction) => interaction.id),
    scannerIssueIds,
    exploitRunIds,
    status: options.newInteractions.length ? 'observed' : 'no-new-interactions',
    reportReady: options.newInteractions.length > 0,
    signature: {
      algorithm: 'HMAC-SHA256',
      signerName: options.signerName?.trim() || options.profile.name,
      keyId: options.profile.signingKeyId,
      status: options.signingSecret ? 'signed' : 'ready-on-export',
      digestPreview,
    },
    summary: `${unsigned.summary} Signed listener ${options.profile.name} correlated ${scannerIssueIds.length} scanner issue(s) and ${exploitRunIds.length} exploit run(s).`,
    content,
  };
  return batch;
}

export function buildCallbackCorrelationReplayPackage(options: {
  profile?: CallbackListenerProfile;
  payload?: CallbackPayload;
  interactions: CallbackInteraction[];
  exchange: HttpExchange;
  exploitRuns?: ExploitRun[];
  targetTool?: CallbackCorrelationReplayPackage['targetTool'];
  now?: string;
}): CallbackCorrelationReplayPackage {
  const createdAt = options.now ?? new Date().toISOString();
  const payload = options.payload;
  const correlatedInteractions = options.interactions.filter((interaction) => !payload || interaction.payloadId === payload.id);
  const interactionIds = correlatedInteractions.map((interaction) => interaction.id);
  const scannerIssueIds = Array.from(new Set(correlatedInteractions.map((interaction) => `callback-${interaction.payloadId}`)));
  const exploitRunIds = correlateExploitRuns(payload ? [payload] : [], correlatedInteractions, options.exploitRuns ?? []);
  const endpoint = payload?.endpoint ?? buildCallbackEndpoint('http', `pf-http-${getRandomHex(3)}`, options.profile?.publicBaseUrl ?? CALLBACK_SERVER_HOST);
  const replayRequestRaw = injectCallbackIntoRawRequest(options.exchange.requestRaw, endpoint);
  const severity = highestInteractionSeverity(options.interactions, payload?.status === 'observed' ? 'medium' : 'info');
  const digestPreview = simpleDigest(`${options.profile?.id ?? 'no-profile'}|${payload?.id ?? 'manual'}|${interactionIds.join(',')}|${scannerIssueIds.join(',')}|${exploitRunIds.join(',')}|${options.exchange.id}`);
  const content = JSON.stringify({
    kind: 'proxyforge-callback-correlation-replay',
    createdAt,
    listenerProfile: options.profile ? {
      id: options.profile.id,
      mode: options.profile.mode,
      protocols: options.profile.protocols,
      publicBaseUrl: options.profile.publicBaseUrl,
    } : undefined,
    payload,
    interactionIds,
    scannerIssueIds,
    exploitRunIds,
    sourceExchangeId: options.exchange.id,
    targetTool: options.targetTool ?? 'repeater',
    replayRequestRaw,
    correlation: [
      'scanner issue promotion',
      'exploit validation replay',
      'Repeater staging',
      'Reports evidence handoff',
    ],
    digestPreview,
  }, null, 2);

  return {
    id: `callback-correlation-replay-${digestPreview.slice(0, 12)}`,
    title: 'Callback correlation replay',
    createdAt,
    payloadId: payload?.id,
    listenerProfileId: options.profile?.id,
    interactionIds,
    scannerIssueIds,
    exploitRunIds,
    sourceExchangeId: options.exchange.id,
    targetTool: options.targetTool ?? 'repeater',
    replayRequestRaw,
    severity,
    reportReady: interactionIds.length > 0,
    summary: `Callback correlation replay stages ${payload?.token ?? 'manual callback'} for ${options.targetTool ?? 'repeater'} with ${interactionIds.length} observed interaction(s), ${scannerIssueIds.length} scanner issue link(s), and ${exploitRunIds.length} exploit run link(s).`,
    content,
  };
}

export function executeCallbackCorrelationReplayBatch(options: {
  profile?: CallbackListenerProfile;
  replays: CallbackCorrelationReplayPackage[];
  interactions: CallbackInteraction[];
  payloads?: CallbackPayload[];
  exploitRuns?: ExploitRun[];
  exchanges?: HttpExchange[];
  scopeAllowlist?: string[];
  mode?: CallbackReplayExecutionMode;
  now?: string;
}): CallbackReplayExecutionBatch {
  const createdAt = options.now ?? new Date().toISOString();
  const mode = options.mode ?? 'local-verified';
  const scopeAllowlist = (options.scopeAllowlist ?? []).map((item) => item.trim().toLowerCase()).filter(Boolean);
  const targetResults = options.replays.map((replay, index) => buildReplayExecutionResult({
    replay,
    index,
    interactions: options.interactions,
    payloads: options.payloads ?? [],
    exploitRuns: options.exploitRuns ?? [],
    exchanges: options.exchanges ?? [],
    scopeAllowlist,
    mode,
  }));
  const completedCount = targetResults.filter((result) => result.status === 'completed').length;
  const blockedCount = targetResults.filter((result) => result.status === 'blocked').length;
  const failedCount = targetResults.filter((result) => result.status === 'failed').length;
  const verifiedCount = targetResults.filter((result) => (
    result.verification.callbackInjected
    && result.verification.observedInteractionsMatched
    && result.verification.scopeMatched
  )).length;
  const status: CallbackReplayExecutionStatus = targetResults.length === 0 || blockedCount === targetResults.length
    ? 'blocked'
    : completedCount === targetResults.length
      ? 'completed'
      : completedCount > 0 || targetResults.some((result) => result.status === 'partial')
        ? 'partial'
        : 'failed';
  const digestPreview = simpleDigest(`${createdAt}|${mode}|${targetResults.map((result) => `${result.replayPackageId}:${result.status}`).join('|')}`);
  const content = JSON.stringify({
    kind: 'proxyforge-callback-replay-execution-batch',
    createdAt,
    mode,
    listenerProfileId: options.profile?.id,
    replayPackageIds: options.replays.map((replay) => replay.id),
    status,
    counts: {
      completed: completedCount,
      blocked: blockedCount,
      failed: failedCount,
      verified: verifiedCount,
    },
    scopeAllowlist,
    targetResults,
    digestPreview,
  }, null, 2);

  return {
    id: `callback-replay-execution-${digestPreview.slice(0, 12)}`,
    title: 'Callback replay execution batch',
    createdAt,
    mode,
    listenerProfileId: options.profile?.id,
    replayPackageIds: options.replays.map((replay) => replay.id),
    status,
    completedCount,
    blockedCount,
    failedCount,
    verifiedCount,
    reportReady: completedCount > 0 && verifiedCount > 0,
    targetResults,
    summary: `Callback replay execution ${status}: ${completedCount}/${targetResults.length} target replay(s) completed, ${verifiedCount} verified with observed callback evidence, ${blockedCount} blocked, ${failedCount} failed.`,
    content,
  };
}

export function buildCallbackPayloadLifecycleReview(options: {
  profile?: CallbackListenerProfile;
  payloads: CallbackPayload[];
  interactions: CallbackInteraction[];
  retentionHours?: number;
  now?: string;
}): CallbackPayloadLifecycleReview {
  const createdAt = options.now ?? new Date().toISOString();
  const retentionHours = Math.max(1, Math.floor(options.retentionHours ?? options.profile?.retentionHours ?? 72));
  const nowDate = parseCallbackDate(createdAt) ?? new Date();
  const observedPayloadIds = options.payloads.filter((payload) => payload.status === 'observed').map((payload) => payload.id);
  const waitingPayloadIds = options.payloads.filter((payload) => payload.status === 'waiting').map((payload) => payload.id);
  const archivedPayloadIds = options.payloads.filter((payload) => payload.status === 'archived').map((payload) => payload.id);
  const stalePayloadIds = waitingPayloadIds.filter((payloadId) => !options.interactions.some((interaction) => interaction.payloadId === payloadId));
  const expiredInteractionIds = options.interactions
    .filter((interaction) => isOlderThanRetention(interaction.observedAt, createdAt, retentionHours, nowDate))
    .map((interaction) => interaction.id);
  const retainedInteractionIds = options.interactions
    .filter((interaction) => !expiredInteractionIds.includes(interaction.id))
    .map((interaction) => interaction.id);
  const payloadIdsWithRetainedInteractions = new Set(options.interactions
    .filter((interaction) => retainedInteractionIds.includes(interaction.id))
    .map((interaction) => interaction.payloadId));
  const expiredPayloadIds = options.payloads
    .filter((payload) => (
      payload.status === 'archived'
      || (
        isOlderThanRetention(payload.lastInteractionAt ?? payload.createdAt, createdAt, retentionHours, nowDate)
        && !payloadIdsWithRetainedInteractions.has(payload.id)
      )
    ))
    .map((payload) => payload.id);
  const retainedPayloadIds = options.payloads
    .filter((payload) => !expiredPayloadIds.includes(payload.id))
    .map((payload) => payload.id);
  const recommendedArchiveIds = Array.from(new Set([
    ...archivedPayloadIds,
    ...observedPayloadIds.filter((payloadId) => options.interactions.some((interaction) => interaction.payloadId === payloadId)),
    ...expiredPayloadIds,
  ]));
  const digestPreview = simpleDigest(`${createdAt}|${retentionHours}|${options.payloads.length}|${options.interactions.length}`);
  const retentionActionCount = expiredPayloadIds.length + expiredInteractionIds.length;
  const pruneSummary = retentionActionCount
    ? `Prune ${expiredInteractionIds.length} expired raw interaction(s) and archive ${expiredPayloadIds.length} payload(s) after preserving signed poll/report packages.`
    : 'No callback payload or raw interaction exceeds the retention window.';
  const content = JSON.stringify({
    kind: 'proxyforge-callback-payload-lifecycle-review',
    createdAt,
    listenerProfileId: options.profile?.id,
    retentionHours,
    observedPayloadIds,
    waitingPayloadIds,
    archivedPayloadIds,
    stalePayloadIds,
    expiredPayloadIds,
    expiredInteractionIds,
    retainedPayloadIds,
    retainedInteractionIds,
    recommendedArchiveIds,
    retentionActionCount,
    pruneSummary,
    controls: [
      'archive observed payloads after report package export',
      'keep waiting payloads until listener retention expires',
      'preserve signed poll batches and interaction raw evidence',
      'prune raw listener interactions only after retention and report evidence checks',
    ],
    digestPreview,
  }, null, 2);

  return {
    id: `callback-lifecycle-${digestPreview.slice(0, 12)}`,
    title: 'Callback payload lifecycle review',
    createdAt,
    listenerProfileId: options.profile?.id,
    retentionHours,
    observedPayloadIds,
    waitingPayloadIds,
    archivedPayloadIds,
    stalePayloadIds,
    expiredPayloadIds,
    expiredInteractionIds,
    retainedPayloadIds,
    retainedInteractionIds,
    recommendedArchiveIds,
    retentionActionCount,
    pruneSummary,
    reportReady: true,
    summary: `Lifecycle review covers ${options.payloads.length} payload(s): ${observedPayloadIds.length} observed, ${waitingPayloadIds.length} waiting, ${recommendedArchiveIds.length} archive candidate(s), ${expiredInteractionIds.length} expired raw interaction(s), retention ${retentionHours}h.`,
    content,
  };
}

export function applyCallbackRetentionPrune(options: {
  profile?: CallbackListenerProfile;
  payloads: CallbackPayload[];
  interactions: CallbackInteraction[];
  retentionHours?: number;
  now?: string;
}) {
  const review = buildCallbackPayloadLifecycleReview(options);
  const expiredPayloadIds = new Set(review.expiredPayloadIds ?? []);
  const expiredInteractionIds = new Set(review.expiredInteractionIds ?? []);
  const prunedInteractions = options.interactions.filter((interaction) => expiredInteractionIds.has(interaction.id));
  return {
    review,
    payloads: options.payloads.map((payload) => (
      expiredPayloadIds.has(payload.id)
        ? { ...payload, status: 'archived' as const, notes: `${payload.notes} Retention archived by ${review.id}.` }
        : payload
    )),
    interactions: options.interactions.filter((interaction) => !expiredInteractionIds.has(interaction.id)),
    prunedInteractions,
  };
}

export function buildCallbackCiHandoffPackage(options: {
  profile?: CallbackListenerProfile;
  workspace?: CallbackWorkspace;
  payloads: CallbackPayload[];
  interactions: CallbackInteraction[];
  provider: CallbackCiProvider;
  now?: string;
}): CallbackCiHandoffPackage {
  const createdAt = options.now ?? new Date().toISOString();
  const stamp = createdAt.replace(/[:.]/g, '-');
  const payloadIds = options.workspace?.payloadIds ?? options.payloads.map((payload) => payload.id).slice(0, 12);
  const interactionIds = options.interactions.filter((interaction) => payloadIds.includes(interaction.payloadId)).map((interaction) => interaction.id);
  const command = ciCommandForProvider(options.provider, options.profile, payloadIds);
  const env = {
    PROXYFORGE_OAST_LISTENER: options.profile?.id ?? 'browser-preview',
    PROXYFORGE_OAST_PUBLIC_BASE: options.profile?.publicBaseUrl ?? CALLBACK_SERVER_HOST,
    PROXYFORGE_OAST_SIGNING_KEY_ID: options.profile?.signingKeyId ?? 'callback-local',
    PROXYFORGE_OAST_PAYLOAD_IDS: payloadIds.join(','),
  };
  const digestPreview = simpleDigest(`${options.provider}|${payloadIds.join(',')}|${interactionIds.join(',')}|${command}`);
  const content = JSON.stringify({
    kind: 'proxyforge-callback-ci-handoff-package',
    createdAt,
    provider: options.provider,
    providerLabel: callbackCiProviderLabels[options.provider],
    listenerProfile: options.profile,
    workspace: options.workspace,
    command,
    env,
    payloadIds,
    interactionIds,
    reportReady: true,
    digestPreview,
  }, null, 2);

  return {
    id: `callback-ci-handoff-${digestPreview.slice(0, 12)}`,
    title: 'Callback CI/report handoff',
    fileName: `proxyforge-callback-ci-handoff-${stamp}.json`,
    path: `callbacks/proxyforge-callback-ci-handoff-${stamp}.json`,
    createdAt,
    listenerProfileId: options.profile?.id,
    workspaceId: options.workspace?.id,
    provider: options.provider,
    command,
    env,
    payloadIds,
    interactionIds,
    reportReady: true,
    summary: `${callbackCiProviderLabels[options.provider]} handoff polls ${payloadIds.length} payload(s), signs interactions with ${options.profile?.signingKeyId ?? 'callback-local'}, and exports report-ready OAST evidence.`,
    content,
  };
}

export function buildCallbackPublicRelaySoakPackage(options: {
  profile: CallbackListenerProfile;
  workspace?: CallbackWorkspace;
  payloads: CallbackPayload[];
  interactions: CallbackInteraction[];
  signedPollBatches?: CallbackSignedPollBatch[];
  replayExecutionBatches?: CallbackReplayExecutionBatch[];
  lifecycleReviews?: CallbackPayloadLifecycleReview[];
  ciHandoffPackages?: CallbackCiHandoffPackage[];
  minPayloadCount?: number;
  minInteractionCount?: number;
  minProtocolCount?: number;
  now?: string;
}): CallbackPublicRelaySoakPackage {
  const createdAt = options.now ?? new Date().toISOString();
  const stamp = createdAt.replace(/[:.]/g, '-');
  const payloadIds = options.payloads.map((payload) => payload.id);
  const interactionIds = options.interactions.map((interaction) => interaction.id);
  const observedProtocols = Array.from(new Set([
    ...options.profile.protocols,
    ...options.payloads.map((payload) => payload.protocol),
    ...options.interactions.map((interaction) => interaction.protocol),
  ])).filter((protocol): protocol is CallbackProtocol => ['dns', 'http', 'smtp'].includes(protocol));
  const signedPollBatchIds = (options.signedPollBatches ?? []).filter((item) => item.reportReady).map((item) => item.id);
  const replayExecutionBatchIds = (options.replayExecutionBatches ?? []).filter((item) => item.reportReady).map((item) => item.id);
  const lifecycleReviewIds = (options.lifecycleReviews ?? []).filter((item) => item.reportReady).map((item) => item.id);
  const ciHandoffPackageIds = (options.ciHandoffPackages ?? []).filter((item) => item.reportReady).map((item) => item.id);
  const minPayloadCount = Math.max(1, Math.floor(options.minPayloadCount ?? 1));
  const minInteractionCount = Math.max(1, Math.floor(options.minInteractionCount ?? 1));
  const minProtocolCount = Math.max(1, Math.floor(options.minProtocolCount ?? Math.min(3, Math.max(2, options.profile.protocols.length))));
  const relayHealthChecks = options.profile.deploymentPlan?.healthChecks ?? options.profile.healthChecks;
  const dnsRecords = options.profile.deploymentPlan?.dnsRecords ?? buildRelayDnsRecords(options.profile.publicBaseUrl, options.profile.protocols);
  const routes = options.profile.deploymentPlan?.routes ?? buildRelayRoutes(options.profile.publicBaseUrl, options.profile.protocols);
  const rawInteractionBytes = options.interactions.reduce((total, interaction) => total + interaction.raw.length, 0);
  const warnings = [
    options.profile.deploymentPlan ? '' : 'missing public relay deployment plan',
    options.profile.secretStorage ? '' : 'missing listener secret-storage reference',
    options.payloads.length >= minPayloadCount ? '' : `payload count ${options.payloads.length} below soak minimum ${minPayloadCount}`,
    options.interactions.length >= minInteractionCount ? '' : `interaction count ${options.interactions.length} below soak minimum ${minInteractionCount}`,
    observedProtocols.length >= minProtocolCount ? '' : `observed protocol count ${observedProtocols.length} below soak minimum ${minProtocolCount}`,
    signedPollBatchIds.length ? '' : 'missing report-ready signed poll batch',
    replayExecutionBatchIds.length ? '' : 'missing report-ready replay execution batch',
    lifecycleReviewIds.length ? '' : 'missing report-ready lifecycle review',
    ciHandoffPackageIds.length ? '' : 'missing report-ready CI handoff package',
  ].filter(Boolean);
  const status: CallbackPublicRelaySoakPackage['status'] = options.interactions.length === 0 || options.payloads.length === 0
    ? 'fail'
    : warnings.length
      ? 'warning'
      : 'pass';
  const reportImportProbe = {
    kind: 'proxyforge-callback-report-import-probe',
    signedPollBatchIds,
    replayExecutionBatchIds,
    lifecycleReviewIds,
    ciHandoffPackageIds,
    expectedManifestArtifactCount: signedPollBatchIds.length + replayExecutionBatchIds.length + lifecycleReviewIds.length + ciHandoffPackageIds.length,
    importExpectation: 'report package import can restore signed polls, replay execution batches, lifecycle reviews, CI handoffs, and public relay soak evidence without redacting executor callback secrets',
  };
  const digestPreview = simpleDigest(JSON.stringify({
    createdAt,
    profileId: options.profile.id,
    payloadIds,
    interactionIds,
    signedPollBatchIds,
    replayExecutionBatchIds,
    lifecycleReviewIds,
    ciHandoffPackageIds,
    rawInteractionBytes,
    status,
  }));
  const content = JSON.stringify({
    kind: 'proxyforge-callback-public-relay-soak-package',
    createdAt,
    listenerProfile: options.profile,
    workspace: options.workspace,
    payloads: options.payloads,
    interactions: options.interactions,
    signedPollBatches: options.signedPollBatches ?? [],
    replayExecutionBatches: options.replayExecutionBatches ?? [],
    lifecycleReviews: options.lifecycleReviews ?? [],
    ciHandoffPackages: options.ciHandoffPackages ?? [],
    relay: {
      publicBaseUrl: options.profile.publicBaseUrl,
      protocols: observedProtocols,
      dnsRecords,
      routes,
      healthChecks: relayHealthChecks,
      retentionHours: options.profile.retentionHours,
      secretStorageRef: options.profile.secretStorage?.secretRef ?? options.profile.deploymentPlan?.secretStorageRef,
    },
    budgets: {
      minPayloadCount,
      minInteractionCount,
      minProtocolCount,
      payloadCount: options.payloads.length,
      interactionCount: options.interactions.length,
      observedProtocolCount: observedProtocols.length,
      rawInteractionBytes,
    },
    reportImportProbe,
    status,
    warnings,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    digestPreview,
  }, null, 2);

  return {
    id: `callback-public-relay-soak-${digestPreview.slice(0, 12)}`,
    title: 'Callback public relay soak package',
    fileName: `proxyforge-callback-public-relay-soak-${stamp}.json`,
    path: `callbacks/proxyforge-callback-public-relay-soak-${stamp}.json`,
    createdAt,
    listenerProfileId: options.profile.id,
    workspaceId: options.workspace?.id,
    publicBaseUrl: options.profile.publicBaseUrl,
    protocols: observedProtocols,
    payloadIds,
    interactionIds,
    signedPollBatchIds,
    replayExecutionBatchIds,
    lifecycleReviewIds,
    ciHandoffPackageIds,
    payloadCount: options.payloads.length,
    interactionCount: options.interactions.length,
    observedProtocolCount: observedProtocols.length,
    rawInteractionBytes,
    retentionHours: options.profile.retentionHours,
    relayHealthChecks,
    dnsRecords,
    routes,
    secretStorageRef: options.profile.secretStorage?.secretRef ?? options.profile.deploymentPlan?.secretStorageRef,
    status,
    warnings,
    reportReady: status === 'pass',
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    summary: `Public relay soak ${status}: ${options.payloads.length} payload(s), ${options.interactions.length} raw interaction(s), ${observedProtocols.length} protocol(s), ${rawInteractionBytes} raw byte(s), ${signedPollBatchIds.length + replayExecutionBatchIds.length + lifecycleReviewIds.length + ciHandoffPackageIds.length} report/import artifact link(s).`,
    content,
  };
}

export function buildCallbackExternalRelayIntegrationPackage(options: {
  profile?: CallbackListenerProfile;
  relayBaseUrl: string;
  publicBaseUrl?: string;
  payloads: CallbackPayload[];
  tenantPolls: CallbackExternalRelayTenantPollInput[];
  minTenantCount?: number;
  minInteractionCount?: number;
  minProtocolCount?: number;
  now?: string;
}): CallbackExternalRelayIntegrationPackage {
  const createdAt = options.now ?? new Date().toISOString();
  const stamp = createdAt.replace(/[:.]/g, '-');
  const relayBaseUrl = options.relayBaseUrl.replace(/\/+$/, '');
  const publicBaseUrl = options.publicBaseUrl ?? options.profile?.publicBaseUrl ?? relayBaseUrl.replace(/^https?:\/\//i, '');
  const payloadIds = options.payloads.map((payload) => payload.id);
  const tenantIds = Array.from(new Set(options.tenantPolls.map((poll) => poll.tenantId)));
  const minTenantCount = Math.max(1, Math.floor(options.minTenantCount ?? 2));
  const minInteractionCount = Math.max(1, Math.floor(options.minInteractionCount ?? 1));
  const minProtocolCount = Math.max(1, Math.floor(options.minProtocolCount ?? 2));
  const allPayloadTokens = options.payloads.map((payload) => payload.token).filter(Boolean);
  const tenantPolls: CallbackExternalRelayTenantPoll[] = options.tenantPolls.map((poll) => {
    const tenantPayloadIds = new Set(poll.payloadIds);
    const foreignPayloads = options.payloads.filter((payload) => !tenantPayloadIds.has(payload.id));
    const leakedInteractionIds = poll.interactions
      .filter((interaction) => !tenantPayloadIds.has(interaction.payloadId))
      .map((interaction) => interaction.id);
    const leakedPayloadIds = foreignPayloads
      .filter((payload) => payload.token && poll.rawResponse.includes(payload.token))
      .map((payload) => payload.id);
    const hasOwnPayloadEvidence = options.payloads
      .filter((payload) => tenantPayloadIds.has(payload.id))
      .some((payload) => poll.rawResponse.includes(payload.token) || poll.interactions.some((interaction) => interaction.payloadId === payload.id));
    const statusOk = poll.statusCode >= 200 && poll.statusCode < 300;
    const signature: CallbackExternalRelayTenantPoll['signature'] = {
      algorithm: poll.signature?.algorithm ?? 'HMAC-SHA256',
      keyId: poll.signature?.keyId ?? options.profile?.signingKeyId ?? 'callback-external-relay',
      status: poll.signature?.status ?? (poll.signature?.digestPreview ? 'signed' : 'missing'),
      digestPreview: poll.signature?.digestPreview ?? '',
    };
    const signatureOk = signature.status === 'signed' && signature.digestPreview.length > 0;
    const warnings = [
      statusOk ? '' : `relay poll returned HTTP ${poll.statusCode}`,
      signatureOk ? '' : 'relay poll response is missing a signed HMAC digest',
      hasOwnPayloadEvidence ? '' : 'relay poll response did not contain tenant-owned payload evidence',
      leakedInteractionIds.length ? `tenant poll leaked interaction id(s): ${leakedInteractionIds.join(', ')}` : '',
      leakedPayloadIds.length ? `tenant poll leaked payload token(s): ${leakedPayloadIds.join(', ')}` : '',
      allPayloadTokens.some((token) => poll.rawRequest.includes(token)) ? 'relay poll request contains callback payload token material' : '',
    ].filter(Boolean);
    const isolationStatus: CallbackExternalRelayTenantPoll['isolationStatus'] = leakedInteractionIds.length || leakedPayloadIds.length
      ? 'leaked'
      : statusOk && signatureOk
        ? 'isolated'
        : 'blocked';

    return {
      tenantId: poll.tenantId,
      relayBaseUrl,
      publicBaseUrl: poll.publicBaseUrl ?? publicBaseUrl,
      payloadIds: poll.payloadIds,
      interactionIds: poll.interactions.map((interaction) => interaction.id),
      statusCode: poll.statusCode,
      rawRequest: poll.rawRequest,
      rawResponse: poll.rawResponse,
      interactions: poll.interactions,
      signature,
      isolationStatus,
      warnings,
    };
  });
  const interactions = tenantPolls.flatMap((poll) => poll.interactions);
  const interactionIds = Array.from(new Set(interactions.map((interaction) => interaction.id)));
  const observedProtocols = Array.from(new Set([
    ...options.payloads.map((payload) => payload.protocol),
    ...interactions.map((interaction) => interaction.protocol),
  ])).filter((protocol): protocol is CallbackProtocol => ['dns', 'http', 'smtp'].includes(protocol));
  const leakedInteractionIds = Array.from(new Set(tenantPolls
    .flatMap((poll) => poll.interactions
      .filter((interaction) => !new Set(poll.payloadIds).has(interaction.payloadId))
      .map((interaction) => interaction.id))));
  const budgetWarnings = [
    tenantIds.length >= minTenantCount ? '' : `tenant count ${tenantIds.length} below relay integration minimum ${minTenantCount}`,
    interactionIds.length >= minInteractionCount ? '' : `interaction count ${interactionIds.length} below relay integration minimum ${minInteractionCount}`,
    observedProtocols.length >= minProtocolCount ? '' : `observed protocol count ${observedProtocols.length} below relay integration minimum ${minProtocolCount}`,
  ].filter(Boolean);
  const pollWarnings = tenantPolls.flatMap((poll) => poll.warnings.map((warning) => `${poll.tenantId}: ${warning}`));
  const hasBlockedOrLeakedPoll = tenantPolls.some((poll) => poll.isolationStatus !== 'isolated');
  const status: CallbackExternalRelayIntegrationPackage['status'] = tenantPolls.length === 0 || options.payloads.length === 0 || hasBlockedOrLeakedPoll
    ? 'fail'
    : budgetWarnings.length
      ? 'warning'
      : 'pass';
  const digestPreview = simpleDigest(JSON.stringify({
    createdAt,
    relayBaseUrl,
    publicBaseUrl,
    tenantIds,
    payloadIds,
    interactionIds,
    status,
  }));
  const content = JSON.stringify({
    kind: 'proxyforge-callback-external-relay-integration-package',
    createdAt,
    listenerProfile: options.profile,
    relayBaseUrl,
    publicBaseUrl,
    payloads: options.payloads,
    tenantPolls,
    budgets: {
      minTenantCount,
      minInteractionCount,
      minProtocolCount,
      tenantCount: tenantIds.length,
      payloadCount: options.payloads.length,
      interactionCount: interactionIds.length,
      observedProtocolCount: observedProtocols.length,
    },
    status,
    warnings: [...pollWarnings, ...budgetWarnings],
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    digestPreview,
  }, null, 2);

  return {
    id: `callback-external-relay-integration-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-callback-external-relay-integration-package',
    title: 'Callback external relay integration package',
    fileName: `proxyforge-callback-external-relay-integration-${stamp}.json`,
    path: `callbacks/proxyforge-callback-external-relay-integration-${stamp}.json`,
    createdAt,
    listenerProfileId: options.profile?.id,
    publicBaseUrl,
    relayBaseUrl,
    tenantCount: tenantIds.length,
    payloadCount: options.payloads.length,
    interactionCount: interactionIds.length,
    observedProtocolCount: observedProtocols.length,
    tenantPolls,
    leakedInteractionIds,
    status,
    reportReady: status === 'pass',
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `External relay integration ${status}: ${tenantIds.length} tenant(s), ${interactionIds.length} signed poll interaction(s), ${observedProtocols.length} protocol(s), ${leakedInteractionIds.length} leaked interaction id(s).`,
    content,
  };
}

export function buildCallbackExternalOastProviderDiversityPackage(options: {
  profile?: CallbackListenerProfile;
  payloads: CallbackPayload[];
  providerProbes: CallbackExternalOastProviderProbeInput[];
  relayIntegrationPackages?: CallbackExternalRelayIntegrationPackage[];
  minProviderCount?: number;
  minProtocolCount?: number;
  minInteractionCount?: number;
  now?: string;
}): CallbackExternalOastProviderDiversityPackage {
  const createdAt = options.now ?? new Date().toISOString();
  const stamp = createdAt.replace(/[:.]/g, '-');
  const minProviderCount = Math.max(1, Math.floor(options.minProviderCount ?? 3));
  const minProtocolCount = Math.max(1, Math.floor(options.minProtocolCount ?? 3));
  const minInteractionCount = Math.max(1, Math.floor(options.minInteractionCount ?? 3));
  const providerProbes: CallbackExternalOastProviderProbe[] = options.providerProbes.map((probe, index) => {
    const allowedPayloadIds = new Set(probe.payloadIds);
    const foreignPayloads = options.payloads.filter((payload) => !allowedPayloadIds.has(payload.id));
    const leakedInteractionIds = probe.interactions
      .filter((interaction) => !allowedPayloadIds.has(interaction.payloadId))
      .map((interaction) => interaction.id);
    const leakedPayloadIds = foreignPayloads
      .filter((payload) => payload.token && probe.rawResponse.includes(payload.token))
      .map((payload) => payload.id);
    const ownPayloadEvidence = options.payloads
      .filter((payload) => allowedPayloadIds.has(payload.id))
      .some((payload) => probe.rawResponse.includes(payload.token)
        || probe.rawRequest.includes(payload.token)
        || probe.interactions.some((interaction) => interaction.payloadId === payload.id));
    const statusOk = probe.statusCode >= 200 && probe.statusCode < 300;
    const signature: CallbackExternalOastProviderProbe['signature'] = {
      algorithm: probe.signature?.algorithm ?? 'HMAC-SHA256',
      keyId: probe.signature?.keyId ?? options.profile?.signingKeyId ?? `${probe.providerId}-callback-signing-key`,
      status: probe.signature?.status ?? (probe.signature?.digestPreview ? 'signed' : 'missing'),
      digestPreview: probe.signature?.digestPreview ?? '',
    };
    const signatureOk = signature.status === 'signed' && signature.digestPreview.length > 0;
    const warnings = [
      statusOk ? '' : `${probe.providerId} returned HTTP ${probe.statusCode}`,
      signatureOk ? '' : `${probe.providerId} poll response is not signed`,
      ownPayloadEvidence ? '' : `${probe.providerId} did not return tenant-owned payload evidence`,
      probe.rawRequest.length && probe.rawResponse.length ? '' : `${probe.providerId} is missing raw request/response evidence`,
      leakedInteractionIds.length ? `${probe.providerId} leaked interaction id(s): ${leakedInteractionIds.join(', ')}` : '',
      leakedPayloadIds.length ? `${probe.providerId} leaked foreign payload token(s): ${leakedPayloadIds.join(', ')}` : '',
      probe.replaySupported === false ? `${probe.providerId} does not expose replay-friendly poll metadata` : '',
    ].filter(Boolean);
    const isolationStatus: CallbackExternalOastProviderProbe['isolationStatus'] = leakedInteractionIds.length || leakedPayloadIds.length
      ? 'leaked'
      : statusOk && signatureOk
        ? 'isolated'
        : 'blocked';

    return {
      id: `external-oast-provider-probe-${index + 1}-${slugify(`${probe.providerId}-${probe.protocol}`)}`,
      providerId: probe.providerId,
      providerName: probe.providerName ?? probe.providerId,
      providerKind: probe.providerKind,
      tenantId: probe.tenantId,
      baseUrl: probe.baseUrl.replace(/\/+$/, ''),
      publicBaseUrl: probe.publicBaseUrl ?? probe.baseUrl.replace(/^https?:\/\//i, '').replace(/\/+$/, ''),
      protocol: probe.protocol,
      payloadIds: probe.payloadIds,
      interactionIds: probe.interactions.map((interaction) => interaction.id),
      statusCode: probe.statusCode,
      rawRequest: probe.rawRequest,
      rawResponse: probe.rawResponse,
      interactions: probe.interactions,
      signature,
      isolationStatus,
      replaySupported: probe.replaySupported ?? true,
      warnings,
    };
  });
  const providerIds = Array.from(new Set(providerProbes.map((probe) => probe.providerId)));
  const providerKinds = Array.from(new Set(providerProbes.map((probe) => probe.providerKind)));
  const protocols = Array.from(new Set(providerProbes.map((probe) => probe.protocol)));
  const interactionIds = Array.from(new Set(providerProbes.flatMap((probe) => probe.interactionIds)));
  const leakedInteractionIds = Array.from(new Set(providerProbes
    .flatMap((probe) => probe.interactions
      .filter((interaction) => !new Set(probe.payloadIds).has(interaction.payloadId))
      .map((interaction) => interaction.id))));
  const linkedRelayIntegrationPackageIds = (options.relayIntegrationPackages ?? [])
    .filter((item) => item.reportReady)
    .map((item) => item.id);
  const budgetWarnings = [
    providerIds.length >= minProviderCount ? '' : `provider count ${providerIds.length} below diversity minimum ${minProviderCount}`,
    protocols.length >= minProtocolCount ? '' : `protocol count ${protocols.length} below diversity minimum ${minProtocolCount}`,
    interactionIds.length >= minInteractionCount ? '' : `interaction count ${interactionIds.length} below diversity minimum ${minInteractionCount}`,
    linkedRelayIntegrationPackageIds.length ? '' : 'missing linked signed tenant-isolated relay integration package',
  ].filter(Boolean);
  const hasBlockedOrLeakedProbe = providerProbes.some((probe) => probe.isolationStatus !== 'isolated');
  const status: CallbackExternalOastProviderDiversityPackage['status'] = providerProbes.length === 0 || hasBlockedOrLeakedProbe
    ? 'fail'
    : budgetWarnings.length
      ? 'warning'
      : 'pass';
  const digestPreview = simpleDigest(JSON.stringify({
    createdAt,
    providerIds,
    providerKinds,
    protocols,
    interactionIds,
    linkedRelayIntegrationPackageIds,
    status,
  }));
  const content = JSON.stringify({
    kind: 'proxyforge-callback-external-oast-provider-diversity-package',
    createdAt,
    listenerProfile: options.profile,
    providerProbes,
    relayIntegrationPackages: options.relayIntegrationPackages ?? [],
    budgets: {
      minProviderCount,
      minProtocolCount,
      minInteractionCount,
      providerCount: providerIds.length,
      protocolCount: protocols.length,
      interactionCount: interactionIds.length,
    },
    warnings: [
      ...providerProbes.flatMap((probe) => probe.warnings),
      ...budgetWarnings,
    ],
    status,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    digestPreview,
  }, null, 2);

  return {
    id: `external-oast-provider-diversity-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-callback-external-oast-provider-diversity-package',
    title: 'External OAST provider diversity package',
    fileName: `proxyforge-callback-external-oast-provider-diversity-${stamp}.json`,
    path: `callbacks/proxyforge-callback-external-oast-provider-diversity-${stamp}.json`,
    createdAt,
    listenerProfileId: options.profile?.id,
    providerCount: providerIds.length,
    providerKinds,
    protocolCount: protocols.length,
    payloadCount: options.payloads.length,
    interactionCount: interactionIds.length,
    providerProbes,
    leakedInteractionIds,
    linkedRelayIntegrationPackageIds,
    status,
    reportReady: status === 'pass',
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `External OAST provider diversity ${status}: ${providerIds.length} provider(s), ${providerKinds.length} provider kind(s), ${protocols.length} protocol(s), ${interactionIds.length} interaction(s), ${leakedInteractionIds.length} leaked interaction id(s).`,
    content,
  };
}

export function buildCallbackReportRoundTripPackage(options: {
  reportPackageContent: string;
  exportedReportContent: string;
  signedPollBatches?: CallbackSignedPollBatch[];
  replayPackages?: CallbackCorrelationReplayPackage[];
  replayExecutionBatches?: CallbackReplayExecutionBatch[];
  lifecycleReviews?: CallbackPayloadLifecycleReview[];
  ciHandoffPackages?: CallbackCiHandoffPackage[];
  relaySoakPackages?: CallbackPublicRelaySoakPackage[];
  externalRelayIntegrationPackages?: CallbackExternalRelayIntegrationPackage[];
  externalProviderDiversityPackages?: CallbackExternalOastProviderDiversityPackage[];
  evidencePackages?: CallbackEvidencePackage[];
  operationalSecretSamples?: string[];
  now?: string;
}): CallbackReportRoundTripPackage {
  const createdAt = options.now ?? new Date().toISOString();
  const stamp = createdAt.replace(/[:.]/g, '-');
  const readySignedPollBatches = (options.signedPollBatches ?? []).filter((item) => item.reportReady);
  const readyReplayPackages = (options.replayPackages ?? []).filter((item) => item.reportReady);
  const readyReplayExecutionBatches = (options.replayExecutionBatches ?? []).filter((item) => item.reportReady);
  const readyLifecycleReviews = (options.lifecycleReviews ?? []).filter((item) => item.reportReady);
  const readyCiHandoffPackages = (options.ciHandoffPackages ?? []).filter((item) => item.reportReady);
  const readyRelaySoakPackages = (options.relaySoakPackages ?? []).filter((item) => item.reportReady);
  const readyExternalRelayIntegrationPackages = (options.externalRelayIntegrationPackages ?? []).filter((item) => item.reportReady && item.status === 'pass');
  const readyExternalProviderDiversityPackages = (options.externalProviderDiversityPackages ?? []).filter((item) => item.reportReady && item.status === 'pass');
  const readyEvidencePackages = (options.evidencePackages ?? []).filter((item) => item.reportReady);
  const artifactGroups = [
    readySignedPollBatches.map((item) => item.id),
    readyReplayPackages.map((item) => item.id),
    readyReplayExecutionBatches.map((item) => item.id),
    readyLifecycleReviews.map((item) => item.id),
    readyCiHandoffPackages.map((item) => item.id),
    readyRelaySoakPackages.map((item) => item.id),
    readyExternalRelayIntegrationPackages.map((item) => item.id),
    readyExternalProviderDiversityPackages.map((item) => item.id),
    readyEvidencePackages.map((item) => item.id),
  ];
  const allArtifactIds = Array.from(new Set(artifactGroups.flat()));
  const rawArtifactText = [
    ...readySignedPollBatches.map((item) => item.content),
    ...readyReplayPackages.map((item) => item.content),
    ...readyReplayExecutionBatches.map((item) => item.content),
    ...readyLifecycleReviews.map((item) => item.content),
    ...readyCiHandoffPackages.map((item) => item.content),
    ...readyRelaySoakPackages.map((item) => item.content),
    ...readyExternalRelayIntegrationPackages.map((item) => item.content),
    ...readyExternalProviderDiversityPackages.map((item) => item.content),
    ...readyEvidencePackages.map((item) => item.content),
  ].join('\n');
  const parsedReportPackage = parseJsonRecord(options.reportPackageContent);
  const reportPackageKind = readStringField(parsedReportPackage, 'kind', 'unknown');
  const signature = readRecordField(parsedReportPackage, 'signature');
  const reportPackageSignatureStatus = readStringField(signature, 'status', 'missing');
  const importedArtifactIds = allArtifactIds.filter((id) => options.reportPackageContent.includes(id));
  const missingArtifactIds = allArtifactIds.filter((id) => !importedArtifactIds.includes(id));
  const operationalSecretSamples = (options.operationalSecretSamples ?? [])
    .map((sample) => sample.trim())
    .filter(Boolean);
  const rawTextWithReportPackage = `${rawArtifactText}\n${options.reportPackageContent}`;
  const requirements = {
    signedPollsPreserved: readySignedPollBatches.length > 0 && readySignedPollBatches.every((item) => importedArtifactIds.includes(item.id)),
    correlationReplaysPreserved: readyReplayPackages.length > 0 && readyReplayPackages.every((item) => importedArtifactIds.includes(item.id)),
    replayExecutionsPreserved: readyReplayExecutionBatches.length > 0 && readyReplayExecutionBatches.every((item) => importedArtifactIds.includes(item.id)),
    lifecycleReviewsPreserved: readyLifecycleReviews.length > 0 && readyLifecycleReviews.every((item) => importedArtifactIds.includes(item.id)),
    ciHandoffsPreserved: readyCiHandoffPackages.length > 0 && readyCiHandoffPackages.every((item) => importedArtifactIds.includes(item.id)),
    publicRelaySoaksPreserved: readyRelaySoakPackages.length > 0 && readyRelaySoakPackages.every((item) => importedArtifactIds.includes(item.id)),
    externalRelayIntegrationsPreserved: readyExternalRelayIntegrationPackages.length > 0 && readyExternalRelayIntegrationPackages.every((item) => importedArtifactIds.includes(item.id)),
    externalProviderDiversityPreserved: readyExternalProviderDiversityPackages.length > 0 && readyExternalProviderDiversityPackages.every((item) => importedArtifactIds.includes(item.id)),
    reportPackageImportCovered: reportPackageKind === 'proxyforge-full-report-package'
      && options.reportPackageContent.includes('callbackArtifactManifest')
      && importedArtifactIds.length === allArtifactIds.length
      && allArtifactIds.length > 0,
    operationalSecretsPreservedBeforeExport: operationalSecretSamples.length > 0
      && operationalSecretSamples.every((sample) => rawTextWithReportPackage.includes(sample)),
    reportExportRedacted: operationalSecretSamples.length > 0
      && operationalSecretSamples.every((sample) => !options.exportedReportContent.includes(sample))
      && /\[redacted\]|redact/i.test(options.exportedReportContent),
    reportPhaseOnlyRedaction: true,
  };
  const status: CallbackReportRoundTripPackage['status'] = Object.values(requirements).every(Boolean)
    ? 'pass'
    : importedArtifactIds.length && requirements.reportExportRedacted
      ? 'warning'
      : 'fail';
  const artifactManifest = {
    signedPollBatchIds: readySignedPollBatches.map((item) => item.id),
    correlationReplayIds: readyReplayPackages.map((item) => item.id),
    replayExecutionBatchIds: readyReplayExecutionBatches.map((item) => item.id),
    lifecycleReviewIds: readyLifecycleReviews.map((item) => item.id),
    ciHandoffPackageIds: readyCiHandoffPackages.map((item) => item.id),
    publicRelaySoakPackageIds: readyRelaySoakPackages.map((item) => item.id),
    externalRelayIntegrationPackageIds: readyExternalRelayIntegrationPackages.map((item) => item.id),
    externalProviderDiversityPackageIds: readyExternalProviderDiversityPackages.map((item) => item.id),
    evidencePackageIds: readyEvidencePackages.map((item) => item.id),
    totalArtifactCount: allArtifactIds.length,
    importedArtifactCount: importedArtifactIds.length,
    rawArtifactBytes: rawArtifactText.length,
    reportPackageBytes: options.reportPackageContent.length,
    exportedReportBytes: options.exportedReportContent.length,
  };
  const digestPreview = simpleDigest(JSON.stringify({
    createdAt,
    reportPackageKind,
    reportPackageSignatureStatus,
    artifactManifest,
    importedArtifactIds,
    missingArtifactIds,
    status,
  }));
  const content = JSON.stringify({
    kind: 'proxyforge-callback-report-roundtrip-package',
    createdAt,
    reportPackageKind,
    reportPackageSignatureStatus,
    artifactManifest,
    importedArtifactIds,
    missingArtifactIds,
    operationalSecretSamples,
    requirements,
    status,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    digestPreview,
  }, null, 2);

  return {
    id: `callback-report-roundtrip-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-callback-report-roundtrip-package',
    title: 'Callback report package round-trip',
    fileName: `proxyforge-callback-report-roundtrip-${stamp}.json`,
    path: `callbacks/proxyforge-callback-report-roundtrip-${stamp}.json`,
    createdAt,
    reportPackageKind,
    reportPackageSignatureStatus,
    artifactManifest,
    importedArtifactIds,
    missingArtifactIds,
    operationalSecretSamples,
    requirements,
    status,
    reportReady: status === 'pass',
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `Callback report round-trip ${status}: imported ${importedArtifactIds.length}/${allArtifactIds.length} callback artifact(s), external relay packages ${artifactManifest.externalRelayIntegrationPackageIds.length}, external provider packages ${artifactManifest.externalProviderDiversityPackageIds.length}, report export redacted=${requirements.reportExportRedacted}.`,
    content,
  };
}

export function buildCallbackCollaboratorParityEvidencePackage(
  request: CallbackCollaboratorParityEvidenceRequest,
): CallbackCollaboratorParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const externalRelayIntegrationPackages = request.externalRelayIntegrationPackages ?? [];
  const externalProviderDiversityPackages = request.externalProviderDiversityPackages ?? [];
  const reportRoundTripPackages = request.reportRoundTripPackages ?? [];
  const protocols = new Set<CallbackProtocol>([
    ...request.payloads.map((payload) => payload.protocol),
    ...request.interactions.map((interaction) => interaction.protocol),
    ...request.listenerProfiles.flatMap((profile) => profile.protocols),
  ]);
  const targetTools = new Set(request.replayPackages.map((replay) => replay.targetTool));
  const artifactOperationalText = [
    JSON.stringify(request.payloads),
    JSON.stringify(request.interactions),
    JSON.stringify(request.workspaces),
    JSON.stringify(request.listenerProfiles),
    JSON.stringify(request.signedPollBatches),
    JSON.stringify(request.evidencePackages),
    JSON.stringify(request.replayPackages),
    JSON.stringify(request.replayExecutionBatches),
    JSON.stringify(request.lifecycleReviews),
    JSON.stringify(request.ciHandoffPackages),
    JSON.stringify(request.relaySoakPackages),
    JSON.stringify(externalRelayIntegrationPackages),
    JSON.stringify(externalProviderDiversityPackages),
    JSON.stringify(reportRoundTripPackages),
    JSON.stringify(request.prunedInteractions ?? []),
    ...request.signedPollBatches.map((item) => item.content),
    ...request.evidencePackages.map((item) => item.content),
    ...request.replayPackages.map((item) => item.content),
    ...request.replayExecutionBatches.map((item) => item.content),
    ...request.lifecycleReviews.map((item) => item.content),
    ...request.ciHandoffPackages.map((item) => item.content),
    ...request.relaySoakPackages.map((item) => item.content),
    ...externalRelayIntegrationPackages.map((item) => item.content),
    ...externalProviderDiversityPackages.map((item) => item.content),
    ...reportRoundTripPackages.map((item) => item.content),
  ].join('\n');
  const combinedOperationalText = [
    artifactOperationalText,
    JSON.stringify({ operationalSecretSamples: request.operationalSecretSamples ?? [] }),
  ].join('\n');
  const requirements = {
    payloadGenerationCovered: request.payloads.length >= 3
      && request.payloads.every((payload) => payload.token && payload.endpoint && payload.sourceExchangeId),
    dnsHttpSmtpProtocolsCovered: ['dns', 'http', 'smtp'].every((protocol) => protocols.has(protocol as CallbackProtocol)),
    interactionPollingCovered: request.signedPollBatches.some((batch) => batch.status === 'observed' && batch.newInteractionIds.length > 0 && batch.reportReady),
    oastWorkspaceOwnershipCovered: request.workspaces.some((workspace) => workspace.owner && workspace.payloadIds.length > 0 && workspace.interactionIds.length > 0),
    signedEvidencePackagesCovered: request.evidencePackages.some((item) => item.reportReady && item.signature.status === 'signed' && item.payloadIds.length > 0),
    localListenerBackendCovered: request.listenerProfiles.some((profile) => profile.mode === 'hybrid-local'
      && profile.protocols.includes('dns')
      && profile.protocols.includes('http')
      && profile.protocols.includes('smtp')
      && Boolean(profile.secretStorage?.secretRef)),
    publicRelaySoakCovered: request.relaySoakPackages.some((soak) => soak.status === 'pass' && soak.reportReady && soak.secretHandling === 'execution-full-fidelity-secrets-preserved'),
    externalRelayTenantIsolationCovered: externalRelayIntegrationPackages.some((relay) => relay.status === 'pass'
      && relay.reportReady
      && relay.secretHandling === 'execution-full-fidelity-secrets-preserved'
      && relay.reportRedactionBoundary === 'redact-only-during-report-export'
      && relay.tenantCount >= 2
      && relay.tenantPolls.every((poll) => poll.isolationStatus === 'isolated'
        && poll.signature.status === 'signed'
        && poll.rawRequest.length > 0
        && poll.rawResponse.length > 0)),
    externalProviderDiversityCovered: externalProviderDiversityPackages.some((item) => item.status === 'pass'
      && item.reportReady
      && item.providerCount >= 3
      && item.protocolCount >= 3
      && item.linkedRelayIntegrationPackageIds.length > 0
      && item.providerProbes.every((probe) => probe.isolationStatus === 'isolated'
        && probe.signature.status === 'signed'
        && probe.rawRequest.length > 0
        && probe.rawResponse.length > 0)),
    retentionPruneCovered: request.lifecycleReviews.some((review) => review.reportReady && (review.retentionActionCount ?? 0) > 0)
      && (request.prunedInteractions?.length ?? 0) > 0,
    correlationReplayCovered: request.replayPackages.some((replay) => replay.reportReady
      && (/proxyforge-callback-correlation-replay|X-ProxyForge-Callback/i.test(replay.content)
        || /X-ProxyForge-Callback/i.test(replay.replayRequestRaw))),
    scannerExploitRepeaterStagingCovered: ['scanner', 'exploit-lab', 'repeater'].every((tool) => targetTools.has(tool as CallbackCorrelationReplayPackage['targetTool'])),
    automatedReplayExecutionCovered: request.replayExecutionBatches.some((batch) => batch.reportReady && batch.completedCount > 0 && batch.verifiedCount > 0),
    ciHandoffCovered: request.ciHandoffPackages.some((handoff) => handoff.reportReady && handoff.command.includes('proxyforge oast poll')),
    reportPackagePersistenceCovered: request.evidencePackages.some((item) => item.reportReady && item.reportSection === 'evidence')
      && request.relaySoakPackages.some((soak) => soak.content.includes('proxyforge-callback-report-import-probe')),
    reportPackageRoundTripCovered: reportRoundTripPackages.some((item) => item.status === 'pass'
      && item.reportReady
      && item.reportPackageKind === 'proxyforge-full-report-package'
      && item.requirements.externalRelayIntegrationsPreserved
      && item.requirements.externalProviderDiversityPreserved
      && item.requirements.operationalSecretsPreservedBeforeExport
      && item.requirements.reportExportRedacted
      && item.reportRedactionBoundary === 'redact-only-during-report-export'),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|raw|replayRequestRaw|interactions/i.test(combinedOperationalText),
    callbackSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => artifactOperationalText.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-collaborator-parity-evidence-package',
    exportedAt,
    payloads: request.payloads,
    interactions: request.interactions,
    workspaces: request.workspaces,
    listenerProfiles: request.listenerProfiles,
    signedPollBatches: request.signedPollBatches,
    evidencePackages: request.evidencePackages,
    replayPackages: request.replayPackages,
    replayExecutionBatches: request.replayExecutionBatches,
    lifecycleReviews: request.lifecycleReviews,
    ciHandoffPackages: request.ciHandoffPackages,
    relaySoakPackages: request.relaySoakPackages,
    externalRelayIntegrationPackages,
    externalProviderDiversityPackages,
    reportRoundTripPackages,
    prunedInteractions: request.prunedInteractions ?? [],
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `collaborator-parity-${Date.parse(exportedAt) || Date.now()}`,
    kind: 'proxyforge-collaborator-parity-evidence-package',
    title: 'Collaborator/OAST parity evidence package',
    fileName: `proxyforge-collaborator-parity-${stamp}.json`,
    path: `collaborator/proxyforge-collaborator-parity-${stamp}.json`,
    exportedAt,
    payloadCount: request.payloads.length,
    interactionCount: request.interactions.length,
    workspaceCount: request.workspaces.length,
    listenerProfileCount: request.listenerProfiles.length,
    replayPackageCount: request.replayPackages.length,
    replayExecutionBatchCount: request.replayExecutionBatches.length,
    artifactIds: {
      payloadIds: request.payloads.map((payload) => payload.id),
      interactionIds: request.interactions.map((interaction) => interaction.id),
      workspaceIds: request.workspaces.map((workspace) => workspace.id),
      listenerProfileIds: request.listenerProfiles.map((profile) => profile.id),
      signedPollBatchIds: request.signedPollBatches.map((batch) => batch.id),
      evidencePackageIds: request.evidencePackages.map((item) => item.id),
      replayPackageIds: request.replayPackages.map((replay) => replay.id),
      replayExecutionBatchIds: request.replayExecutionBatches.map((batch) => batch.id),
      lifecycleReviewIds: request.lifecycleReviews.map((review) => review.id),
      ciHandoffPackageIds: request.ciHandoffPackages.map((handoff) => handoff.id),
      relaySoakPackageIds: request.relaySoakPackages.map((soak) => soak.id),
      externalRelayIntegrationPackageIds: externalRelayIntegrationPackages.map((relay) => relay.id),
      externalProviderDiversityPackageIds: externalProviderDiversityPackages.map((item) => item.id),
      reportRoundTripPackageIds: reportRoundTripPackages.map((item) => item.id),
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Collaborator/OAST parity evidence covers DNS/HTTP/SMTP payloads, polling, workspaces, signed packages, local listener planning, relay soak, signed tenant-isolated external relay polling, external OAST provider diversity, retention pruning, replay correlation, CI handoff, report/import persistence, and callback report package round trips.',
    content,
  };
}

const callbackRefreshRequiredKinds = [
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
];

export function buildCallbackPackageRefreshEvidencePackage(
  request: CallbackPackageRefreshEvidenceRequest,
): CallbackPackageRefreshEvidencePackage {
  const generatedAt = request.generatedAt ?? new Date().toISOString();
  const stamp = generatedAt.replace(/[:.]/g, '-');
  const groups = [
    {
      label: 'collaboratorParity',
      packages: [request.collaboratorParityPackage],
      fallbackKind: 'proxyforge-collaborator-parity-evidence-package',
      marker: /payloadGenerationCovered|externalProviderDiversityCovered|reportPackageRoundTripCovered|proxyforge-collaborator-parity/i,
    },
    {
      label: 'signedPolling',
      packages: request.signedPollPackages ?? [],
      fallbackKind: 'proxyforge-callback-signed-poll-batch',
      marker: /proxyforge-callback-signed-poll-batch|signed polling|newInteractionIds|HMAC-SHA256/i,
    },
    {
      label: 'replayCorrelation',
      packages: request.replayPackages ?? [],
      fallbackKind: 'proxyforge-callback-correlation-replay',
      marker: /proxyforge-callback-correlation-replay|X-ProxyForge-Callback|scanner issue promotion|Reports evidence handoff/i,
    },
    {
      label: 'replayExecution',
      packages: request.replayExecutionPackages ?? [],
      fallbackKind: 'proxyforge-callback-replay-execution-batch',
      marker: /proxyforge-callback-replay-execution-batch|callback replay execution|observed callback interaction|local-verify/i,
    },
    {
      label: 'lifecycleRetention',
      packages: request.lifecyclePackages ?? [],
      fallbackKind: 'proxyforge-callback-payload-lifecycle-review',
      marker: /proxyforge-callback-payload-lifecycle-review|retention|prune raw listener interactions|archive observed payloads/i,
    },
    {
      label: 'ciHandoff',
      packages: request.ciHandoffPackages ?? [],
      fallbackKind: 'proxyforge-callback-ci-handoff-package',
      marker: /proxyforge-callback-ci-handoff-package|PROXYFORGE_OAST_PAYLOAD_IDS|oast poll|CI/i,
    },
    {
      label: 'relaySoak',
      packages: request.relaySoakPackages ?? [],
      fallbackKind: 'proxyforge-callback-public-relay-soak-package',
      marker: /proxyforge-callback-public-relay-soak-package|proxyforge-callback-report-import-probe|relay soak|publicBaseUrl/i,
    },
    {
      label: 'externalRelay',
      packages: request.externalRelayIntegrationPackages ?? [],
      fallbackKind: 'proxyforge-callback-external-relay-integration-package',
      marker: /proxyforge-callback-external-relay-integration-package|tenantPolls|isolationStatus|rawRequest|rawResponse/i,
    },
    {
      label: 'externalProviderDiversity',
      packages: request.externalProviderDiversityPackages ?? [],
      fallbackKind: 'proxyforge-callback-external-oast-provider-diversity-package',
      marker: /proxyforge-callback-external-oast-provider-diversity-package|providerProbes|providerKinds|replaySupported/i,
    },
    {
      label: 'providerHostProof',
      packages: request.providerHostProofPackages ?? [],
      fallbackKind: 'proxyforge-agent-callback-provider-host-proof-package',
      marker: /proxyforge-agent-callback-provider-host-proof-package|providerHostScopeCovered|externalHostRequestsCovered|signedPollsCovered/i,
    },
    {
      label: 'reportRoundTrip',
      packages: request.reportRoundTripPackages ?? [],
      fallbackKind: 'proxyforge-callback-report-roundtrip-package',
      marker: /proxyforge-callback-report-roundtrip-package|externalRelayIntegrationsPreserved|externalProviderDiversityPreserved|reportExportRedacted/i,
    },
  ];
  const linkedPackages = groups.flatMap((group) => group.packages.map((item, index) => ({
    item,
    fallbackKind: group.fallbackKind,
    idPrefix: `${group.label}-${index + 1}`,
  })));
  const linkedPackageDigests = linkedPackages.map(({ item, fallbackKind, idPrefix }, index) => {
    const text = callbackLinkedPackageText(item);
    return {
      id: callbackLinkedPackageId(item, idPrefix, index),
      kind: callbackLinkedPackageKind(item, fallbackKind),
      digest: simpleDigest(text),
      reportReady: callbackLinkedPackageReady(item),
      sourceLength: text.length,
    };
  });
  const linkedPackageKinds = uniqueStrings(linkedPackageDigests.map((item) => item.kind));
  const stalePackageIds = linkedPackageDigests.filter((item) => !item.reportReady).map((item) => item.id);
  const rawMaterial = linkedPackages.map(({ item }) => callbackLinkedPackageText(item)).join('\n');
  const packageRefreshProof = {
    refreshedAt: generatedAt,
    requiredPackageKinds: callbackRefreshRequiredKinds,
    linkedPackageIds: linkedPackageDigests.map((item) => item.id),
    linkedPackageKinds,
    linkedPackageDigests,
    stalePackageIds,
    freshDigest: simpleDigest(linkedPackageDigests.map((item) => `${item.id}:${item.kind}:${item.digest}:${item.reportReady}:${item.sourceLength}`).join('|')),
    rawMaterialDigestPreview: simpleDigest(rawMaterial),
  };
  const groupCovered = (label: string) => {
    const group = groups.find((item) => item.label === label);
    if (!group) return false;
    return group.packages.some((item) => callbackLinkedPackageKind(item, group.fallbackKind) === group.fallbackKind
      && callbackLinkedPackageReady(item)
      && group.marker.test(callbackLinkedPackageText(item)));
  };
  const operationalSecretSamples = (request.operationalSecretSamples ?? []).map((sample) => sample.trim()).filter(Boolean);
  const requirements = {
    collaboratorParityRefreshCovered: groupCovered('collaboratorParity'),
    signedPollingRefreshCovered: groupCovered('signedPolling'),
    replayCorrelationRefreshCovered: groupCovered('replayCorrelation'),
    replayExecutionRefreshCovered: groupCovered('replayExecution'),
    lifecycleRetentionRefreshCovered: groupCovered('lifecycleRetention'),
    ciHandoffRefreshCovered: groupCovered('ciHandoff'),
    relaySoakRefreshCovered: groupCovered('relaySoak'),
    externalRelayRefreshCovered: groupCovered('externalRelay'),
    externalProviderDiversityRefreshCovered: groupCovered('externalProviderDiversity'),
    providerHostProofRefreshCovered: groupCovered('providerHostProof'),
    reportRoundTripRefreshCovered: groupCovered('reportRoundTrip'),
    packageRefreshCovered: callbackRefreshRequiredKinds.every((kind) => linkedPackageKinds.includes(kind))
      && stalePackageIds.length === 0
      && linkedPackageDigests.length >= callbackRefreshRequiredKinds.length,
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Bearer|callback|token|secret|rawRequest|rawResponse|interactions/i.test(rawMaterial),
    callbackSecretsPreserved: operationalSecretSamples.length > 0
      && operationalSecretSamples.every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: /redact-only-during-report-export|report-export-only|reportPhaseOnlyRedaction/i.test(rawMaterial),
  };
  const digestPreview = simpleDigest(JSON.stringify({ generatedAt, packageRefreshProof, requirements }));
  const content = JSON.stringify({
    kind: 'proxyforge-collaborator-package-refresh-evidence-package',
    generatedAt,
    linkedPackages: linkedPackages.map(({ item, fallbackKind, idPrefix }, index) => ({
      id: callbackLinkedPackageId(item, idPrefix, index),
      kind: callbackLinkedPackageKind(item, fallbackKind),
      reportReady: callbackLinkedPackageReady(item),
      content: callbackLinkedPackageText(item),
    })),
    packageRefreshProof,
    requirements,
    operationalSecretSamples,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    digestPreview,
  }, null, 2);

  return {
    id: `collaborator-package-refresh-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-collaborator-package-refresh-evidence-package',
    title: 'Collaborator/OAST package-refresh evidence',
    fileName: `proxyforge-collaborator-package-refresh-${stamp}.json`,
    path: `collaborator/proxyforge-collaborator-package-refresh-${stamp}.json`,
    generatedAt,
    linkedPackageKinds,
    packageRefreshProof,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: `Collaborator/OAST package refresh links ${linkedPackageDigests.length} package digest(s) across polling, replay, relay, provider, retention, report round-trip, and parity evidence with ${stalePackageIds.length} stale package(s).`,
    content,
  };
}

function parseJsonRecord(value: string): Record<string, unknown> | undefined {
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function readRecordField(source: Record<string, unknown> | undefined, key: string): Record<string, unknown> | undefined {
  const value = source?.[key];
  return value && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function readStringField(source: Record<string, unknown> | undefined, key: string, fallback: string) {
  const value = source?.[key];
  return typeof value === 'string' && value.trim() ? value : fallback;
}

function callbackLinkedPackageText(item: CallbackLinkedEvidencePackage) {
  if (item.content) return item.content;
  if (item.summary) return item.summary;
  return JSON.stringify(item);
}

function callbackLinkedPackageKind(item: CallbackLinkedEvidencePackage, fallbackKind: string) {
  if (item.kind) return item.kind;
  const parsed = item.content ? parseJsonRecord(item.content) : undefined;
  const kind = parsed?.kind;
  return typeof kind === 'string' && kind ? kind : fallbackKind;
}

function callbackLinkedPackageId(item: CallbackLinkedEvidencePackage, fallbackPrefix: string, index: number) {
  if (item.id) return item.id;
  const parsed = item.content ? parseJsonRecord(item.content) : undefined;
  const id = parsed?.id;
  if (typeof id === 'string' && id) return id;
  return `${fallbackPrefix}-${index + 1}-${simpleDigest(callbackLinkedPackageText(item)).slice(0, 8)}`;
}

function callbackLinkedPackageReady(item: CallbackLinkedEvidencePackage) {
  if (item.reportReady === false) return false;
  if (/failed|blocked|stale/i.test(item.status ?? '')) return false;
  const parsed = item.content ? parseJsonRecord(item.content) : undefined;
  const requirements = item.requirements ?? readRecordField(parsed, 'requirements');
  return requirements ? Object.values(requirements).every((value) => value !== false) : true;
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values.filter(Boolean))).sort((left, right) => left.localeCompare(right));
}

function makePreviewInteractions(payload: CallbackPayload, exchange: HttpExchange): CallbackInteraction[] {
  const now = new Date();
  const host = payload.sourceHost ?? exchange.host;
  const baseId = `${now.getTime()}-${Math.random().toString(16).slice(2)}`;
  const observedAt = now.toLocaleTimeString([], { hour12: false });
  const dnsInteraction: CallbackInteraction = {
    id: `cb-int-${baseId}-dns`,
    payloadId: payload.id,
    protocol: 'dns',
    observedAt,
    sourceIp: '198.51.100.53',
    sourceHost: `resolver.${host}`,
    requestLine: `${payload.token}.${CALLBACK_SERVER_HOST} A`,
    userAgent: 'recursive-resolver',
    raw: `DNS A query for ${payload.token}.${CALLBACK_SERVER_HOST} from resolver.${host}`,
    severity: 'medium',
    tags: ['oast', 'dns', 'browser-preview'],
  };

  if (payload.protocol === 'dns') return [dnsInteraction];

  if (payload.protocol === 'smtp') {
    return [
      dnsInteraction,
      {
        id: `cb-int-${baseId}-smtp`,
        payloadId: payload.id,
        protocol: 'smtp',
        observedAt: new Date(now.getTime() + 700).toLocaleTimeString([], { hour12: false }),
        sourceIp: '203.0.113.25',
        sourceHost: `mail.${host}`,
        requestLine: `RCPT TO:<${payload.endpoint}>`,
        userAgent: 'smtp-client',
        raw: `MAIL FROM:<worker@${host}>\nRCPT TO:<${payload.endpoint}>\nSubject: callback validation`,
        severity: 'high',
        tags: ['oast', 'smtp', 'browser-preview'],
      },
    ];
  }

  return [
    dnsInteraction,
    {
      id: `cb-int-${baseId}-http`,
      payloadId: payload.id,
      protocol: 'http',
      observedAt: new Date(now.getTime() + 700).toLocaleTimeString([], { hour12: false }),
      sourceIp: '203.0.113.42',
      sourceHost: `worker.${host}`,
      requestLine: 'GET /probe HTTP/1.1',
      userAgent: 'ProxyForgePreviewWorker/1.0',
      raw: `GET /probe HTTP/1.1\nHost: ${payload.token}.${CALLBACK_SERVER_HOST}\nUser-Agent: ProxyForgePreviewWorker/1.0\nX-Source-Path: ${payload.sourcePath ?? exchange.path}`,
      severity: 'high',
      tags: ['oast', 'http', 'browser-preview'],
    },
  ];
}

function protocolsForListenerMode(mode: CallbackListenerMode): CallbackProtocol[] {
  if (mode === 'local-http') return ['http'];
  if (mode === 'local-dns') return ['dns'];
  if (mode === 'local-smtp') return ['smtp'];
  if (mode === 'hybrid-local') return ['dns', 'http', 'smtp'];
  return ['dns', 'http'];
}

function clampPort(port: number, fallback: number) {
  return Number.isFinite(port) ? Math.max(1, Math.min(65535, Math.floor(port))) : fallback;
}

function buildRelayDnsRecords(publicBaseUrl: string, protocols: CallbackProtocol[]) {
  const records = [`*.${publicBaseUrl} 300 IN CNAME relay.proxyforge.local.`];
  if (protocols.includes('smtp')) records.push(`${publicBaseUrl} 300 IN MX 10 mail.${publicBaseUrl}.`);
  if (protocols.includes('dns')) records.push(`${publicBaseUrl} 300 IN NS ns1.proxyforge.local.`);
  return records;
}

function buildRelayRoutes(publicBaseUrl: string, protocols: CallbackProtocol[]) {
  return [
    protocols.includes('http') ? `https://*.${publicBaseUrl}/probe/:token` : 'HTTP callback relay disabled',
    protocols.includes('dns') ? `dns://*.${publicBaseUrl}/A,AAAA,CNAME,TXT` : 'DNS callback relay disabled',
    protocols.includes('smtp') ? `smtp://*@${publicBaseUrl}` : 'SMTP callback relay disabled',
    `https://${publicBaseUrl}/api/proxyforge/oast/poll`,
  ];
}

function isOlderThanRetention(value: string | undefined, reference: string, retentionHours: number, referenceDate = new Date()) {
  const date = parseCallbackDate(value, reference) ?? referenceDate;
  return referenceDate.getTime() - date.getTime() > retentionHours * 60 * 60 * 1000;
}

function parseCallbackDate(value: string | undefined, reference?: string): Date | null {
  if (!value) return null;
  const parsed = new Date(value);
  if (!Number.isNaN(parsed.getTime())) return parsed;
  const timeMatch = value.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  if (timeMatch) {
    const referenceDate: Date = reference ? parseCallbackDate(reference) ?? new Date() : new Date();
    const next: Date = new Date(referenceDate);
    next.setHours(Number(timeMatch[1]), Number(timeMatch[2]), Number(timeMatch[3] ?? 0), 0);
    return next;
  }
  return null;
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}

function slugify(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'callback';
}

function highestInteractionSeverity(interactions: CallbackInteraction[], fallback: Severity): Severity {
  const rank: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return interactions.reduce<Severity>((highest, interaction) => (
    rank[interaction.severity] > rank[highest] ? interaction.severity : highest
  ), fallback);
}

function correlateExploitRuns(payloads: CallbackPayload[], interactions: CallbackInteraction[], exploitRuns: ExploitRun[]) {
  const tokens = new Set(payloads
    .filter((payload) => interactions.some((interaction) => interaction.payloadId === payload.id))
    .flatMap((payload) => [payload.id, payload.token, payload.endpoint]));
  return exploitRuns.filter((run) => {
    const haystack = `${run.payloadPreview}\n${run.logs.join('\n')}\n${run.exchange?.requestRaw ?? ''}\n${run.exchange?.responseRaw ?? ''}`;
    return Array.from(tokens).some((token) => haystack.includes(token));
  }).map((run) => run.id);
}

function buildReplayExecutionResult(options: {
  replay: CallbackCorrelationReplayPackage;
  index: number;
  interactions: CallbackInteraction[];
  payloads: CallbackPayload[];
  exploitRuns: ExploitRun[];
  exchanges: HttpExchange[];
  scopeAllowlist: string[];
  mode: CallbackReplayExecutionMode;
}): CallbackReplayExecutionResult {
  const replay = options.replay;
  const sourceExchange = options.exchanges.find((exchange) => exchange.id === replay.sourceExchangeId);
  const sourceHost = sourceExchange?.host ?? findHostInRawRequest(replay.replayRequestRaw);
  const requestDigestPreview = simpleDigest(replay.replayRequestRaw);
  const linkedInteractions = options.interactions.filter((interaction) => replay.interactionIds.includes(interaction.id));
  const linkedPayloads = options.payloads.filter((payload) => (
    payload.id === replay.payloadId
    || linkedInteractions.some((interaction) => interaction.payloadId === payload.id)
  ));
  const callbackInjected = hasCallbackInjection(replay.replayRequestRaw, linkedPayloads);
  const replayRequestReady = replay.replayRequestRaw.trim().length > 0;
  const scopeMatched = isHostInScope(sourceHost, options.scopeAllowlist);
  const observedInteractionsMatched = linkedInteractions.length > 0;
  const scannerIssueLinked = replay.scannerIssueIds.length > 0;
  const exploitRunLinked = replay.exploitRunIds.length > 0 && (
    options.exploitRuns.length === 0
    || replay.exploitRunIds.some((id) => options.exploitRuns.some((run) => run.id === id))
  );
  const targetVerified = replay.targetTool === 'scanner'
    ? scannerIssueLinked && observedInteractionsMatched
    : replay.targetTool === 'exploit-lab'
      ? exploitRunLinked && observedInteractionsMatched
      : replay.targetTool === 'reports'
        ? replay.reportReady
        : callbackInjected && replayRequestReady;
  const status: CallbackReplayExecutionStatus = !scopeMatched || !replayRequestReady
    ? 'blocked'
    : targetVerified && callbackInjected
      ? 'completed'
      : observedInteractionsMatched || callbackInjected
        ? 'partial'
        : 'failed';
  const command = callbackReplayCommand(replay, options.mode);
  const evidence = [
    scopeMatched ? `scope matched ${sourceHost || 'unknown host'}` : `scope blocked ${sourceHost || 'unknown host'}`,
    callbackInjected ? 'callback endpoint injected into replay request' : 'callback endpoint injection missing',
    observedInteractionsMatched ? `${linkedInteractions.length} observed callback interaction(s) linked` : 'no observed callback interaction linked',
    scannerIssueLinked ? `${replay.scannerIssueIds.length} scanner issue link(s)` : 'no scanner issue link',
    exploitRunLinked ? `${replay.exploitRunIds.length} exploit run link(s)` : 'no exploit run link',
    replay.reportReady ? 'report evidence ready' : 'report evidence not ready',
  ];

  return {
    id: `callback-replay-result-${requestDigestPreview.slice(0, 8)}-${options.index}`,
    replayPackageId: replay.id,
    targetTool: replay.targetTool,
    status,
    command,
    requestDigestPreview,
    sourceExchangeId: replay.sourceExchangeId,
    sourceHost,
    interactionIds: replay.interactionIds,
    scannerIssueIds: replay.scannerIssueIds,
    exploitRunIds: replay.exploitRunIds,
    verification: {
      scopeMatched,
      replayRequestReady,
      callbackInjected,
      observedInteractionsMatched,
      scannerIssueLinked,
      exploitRunLinked,
      reportReady: replay.reportReady,
    },
    evidence,
    summary: `${replay.targetTool} replay ${status}: ${evidence.join('; ')}.`,
  };
}

function ciCommandForProvider(provider: CallbackCiProvider, profile: CallbackListenerProfile | undefined, payloadIds: string[]) {
  const listener = profile?.id ?? 'browser-preview';
  const payloadArg = payloadIds.length ? ` --payload-ids ${payloadIds.join(',')}` : '';
  if (provider === 'github-actions') return `proxyforge oast poll --listener ${listener}${payloadArg} --report bundle --sarif`;
  if (provider === 'gitlab-ci') return `proxyforge oast poll --listener ${listener}${payloadArg} --report json --junit`;
  if (provider === 'azure-pipelines') return `proxyforge oast poll --listener ${listener}${payloadArg} --report markdown,bundle`;
  return `proxyforge oast poll --listener ${listener}${payloadArg} --report bundle && archiveArtifacts artifacts: 'proxyforge-oast/**'`;
}

function callbackReplayCommand(replay: CallbackCorrelationReplayPackage, mode: CallbackReplayExecutionMode) {
  const modeFlag = mode === 'live' ? ' --live --require-approval' : mode === 'dry-run' ? ' --dry-run' : ' --local-verify';
  if (replay.targetTool === 'scanner') return `proxyforge callback replay-run --target scanner --package ${replay.id}${modeFlag} --report json`;
  if (replay.targetTool === 'exploit-lab') return `proxyforge callback replay-run --target exploit-lab --package ${replay.id}${modeFlag} --stop-on-proof --report bundle`;
  if (replay.targetTool === 'reports') return `proxyforge callback replay-run --target reports --package ${replay.id}${modeFlag} --attach evidence`;
  return `proxyforge callback replay-run --target repeater --package ${replay.id}${modeFlag} --capture response`;
}

function hasCallbackInjection(rawRequest: string, payloads: CallbackPayload[]) {
  if (/X-ProxyForge-Callback:\s*\S+/i.test(rawRequest)) return true;
  if (/https?:\/\/[A-Za-z0-9.-]*(?:oast|callback|callbacks|proxyforge)[^\s"']*/i.test(rawRequest)) return true;
  return payloads.some((payload) => (
    rawRequest.includes(payload.endpoint)
    || rawRequest.includes(payload.token)
  ));
}

function findHostInRawRequest(rawRequest: string) {
  const hostMatch = rawRequest.match(/^Host:\s*([^\s:]+)(?::\d+)?\s*$/im);
  if (hostMatch?.[1]) return hostMatch[1].toLowerCase();
  const urlMatch = rawRequest.match(/\bhttps?:\/\/([^/\s"':]+)(?::\d+)?/i);
  return urlMatch?.[1]?.toLowerCase();
}

function isHostInScope(host: string | undefined, scopeAllowlist: string[]) {
  if (scopeAllowlist.length === 0) return true;
  if (!host) return false;
  const normalized = host.toLowerCase();
  return scopeAllowlist.some((scope) => (
    normalized === scope
    || normalized.endsWith(`.${scope}`)
    || (scope.startsWith('*.') && normalized.endsWith(scope.slice(1)))
  ));
}

function makeCallbackToken(protocol: CallbackProtocol) {
  const prefix = protocol === 'dns' ? 'pf-dns' : protocol === 'smtp' ? 'pf-mail' : 'pf-http';
  const random = getRandomHex(5);
  return `${prefix}-${random}`;
}

function getRandomHex(bytes: number) {
  const buffer = new Uint8Array(bytes);
  if (globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(buffer);
  } else {
    for (let index = 0; index < buffer.length; index += 1) {
      buffer[index] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(buffer, (value) => value.toString(16).padStart(2, '0')).join('');
}
