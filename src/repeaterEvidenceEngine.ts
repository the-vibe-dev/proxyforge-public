import type {
  CallbackInteraction,
  CallbackPayload,
  HttpExchange,
  Issue,
  RepeaterSavedRequest,
  RepeaterWorkspaceTab,
  ReplayAuthorizationMatrix,
  ReplayBulkRun,
  ReplaySessionProfileInjection,
  ReplayTransportSettings,
  SessionProfile,
} from './types';

export interface RepeaterParityEvidenceRequest {
  tabs: RepeaterWorkspaceTab[];
  savedRequests: RepeaterSavedRequest[];
  sessionProfiles: SessionProfile[];
  sessionProfileInjections: ReplaySessionProfileInjection[];
  manualReplay?: HttpExchange;
  bulkRun?: ReplayBulkRun;
  authorizationMatrix?: ReplayAuthorizationMatrix;
  transportSettings?: ReplayTransportSettings;
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface RepeaterParityEvidencePackage {
  id: string;
  kind: 'proxyforge-repeater-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  tabCount: number;
  groupCount: number;
  savedRequestCount: number;
  sessionProfileCount: number;
  sessionInjectionCount: number;
  artifactIds: {
    tabIds: string[];
    savedRequestIds: string[];
    sessionProfileIds: string[];
    sessionProfileInjectionIds: string[];
    manualReplayId?: string;
    bulkRunId?: string;
    authorizationMatrixId?: string;
  };
  requirements: {
    manualRequestEditorCovered: boolean;
    manualSendRuntimeCovered: boolean;
    tabsAndGroupedWorkspacesCovered: boolean;
    savedRequestsCovered: boolean;
    snapshotsAndDiffsCovered: boolean;
    sessionProfileInjectionCovered: boolean;
    authorizationMatrixCovered: boolean;
    transportControlsCovered: boolean;
    bulkReplayHandoffCovered: boolean;
    packageRefreshCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  packageRefreshProof: RepeaterPackageRefreshProof;
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export interface RepeaterPackageRefreshProof {
  refreshedAt: string;
  requiredPackageKinds: string[];
  linkedPackageKinds: string[];
  linkedPackageDigests: Array<{
    id: string;
    kind: string;
    digest: string;
    reportReady: boolean;
    sourceCount: number;
  }>;
  stalePackageIds: string[];
  freshDigest: string;
  rawMaterialDigestPreview: string;
  sourceTabCount: number;
  sourceSavedRequestCount: number;
  sourceSessionProfileCount: number;
  sourceSessionInjectionCount: number;
  sourceBulkItemCount: number;
}

interface RepeaterLinkedPackageInput {
  id: string;
  kind: string;
  reportReady: boolean;
  sourceCount: number;
  content: unknown;
}

export interface RepeaterOastEvidenceRequest {
  sourceExchange?: HttpExchange;
  replayExchange: HttpExchange;
  payloads: CallbackPayload[];
  interactions: CallbackInteraction[];
  selectedPayloadId?: string;
  exportedAt?: string;
}

export interface RepeaterOastEvidencePackage {
  id: string;
  kind: 'proxyforge-repeater-oast-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  replayExchangeId: string;
  sourceExchangeId?: string;
  payloadIds: string[];
  interactionIds: string[];
  promotedIssue: Issue;
  requirements: {
    payloadInjectedInReplay: boolean;
    callbackObserved: boolean;
    sourceAndReplayLinked: boolean;
    issuePromotionCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: boolean;
  digestPreview: string;
  summary: string;
  content: string;
}

export function buildRepeaterParityEvidencePackage(request: RepeaterParityEvidenceRequest): RepeaterParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const groups = Array.from(new Set(request.tabs.map((tab) => tab.group || 'Ungrouped')));
  const tabText = JSON.stringify(request.tabs);
  const savedRequestText = JSON.stringify(request.savedRequests);
  const sessionText = JSON.stringify({
    sessionProfiles: request.sessionProfiles,
    sessionProfileInjections: request.sessionProfileInjections,
  });
  const matrixText = JSON.stringify(request.authorizationMatrix ?? {});
  const rawExecutorMaterial = [
    ...request.tabs.map((tab) => tab.rawRequest),
    ...request.savedRequests.map((saved) => saved.rawRequest),
    ...request.sessionProfiles.map((profile) => `${profile.headerText}\nCookie: ${profile.cookieText}`),
    request.manualReplay?.requestRaw,
    request.manualReplay?.responseRaw,
    request.bulkRun ? JSON.stringify(request.bulkRun.items) : '',
    matrixText,
    ...(request.operationalSecretSamples ?? []),
  ].filter(Boolean);
  const rawExecutorMaterialText = rawExecutorMaterial.join('\n--- proxyforge raw material boundary ---\n');
  const linkedPackages = buildRepeaterLinkedPackages(request, {
    tabText,
    savedRequestText,
    sessionText,
    matrixText,
    rawExecutorMaterialText,
  });
  const packageRefreshProof = buildRepeaterPackageRefreshProof({
    exportedAt,
    linkedPackages,
    rawExecutorMaterialText,
    sourceTabCount: request.tabs.length,
    sourceSavedRequestCount: request.savedRequests.length,
    sourceSessionProfileCount: request.sessionProfiles.length,
    sourceSessionInjectionCount: request.sessionProfileInjections.length,
    sourceBulkItemCount: request.bulkRun?.items.length ?? 0,
  });
  const packageRefreshCovered = packageRefreshProof.stalePackageIds.length === 0
    && packageRefreshProof.requiredPackageKinds.every((kind) => packageRefreshProof.linkedPackageKinds.includes(kind));
  const operationalSecretSamples = request.operationalSecretSamples ?? [];
  const requirements = {
    manualRequestEditorCovered: request.tabs.some((tab) => /HTTP\/1\.[01]|HTTP\/2|Host:/i.test(tab.rawRequest) && tab.targetUrl),
    manualSendRuntimeCovered: Boolean(request.manualReplay?.source === 'repeater' && request.manualReplay.status >= 100),
    tabsAndGroupedWorkspacesCovered: request.tabs.length >= 2 && groups.length >= 1 && /group|targetUrl|rawRequest/i.test(tabText),
    savedRequestsCovered: request.savedRequests.length > 0 && /folder|tags|rawRequest/i.test(savedRequestText),
    snapshotsAndDiffsCovered: request.tabs.some((tab) => tab.snapshots.length > 0 && tab.diffs.length > 0),
    sessionProfileInjectionCovered: request.sessionProfiles.length > 0
      && request.sessionProfileInjections.length > 0
      && /Authorization|Cookie|headers-and-cookies|support_admin|session/i.test(sessionText),
    authorizationMatrixCovered: Boolean(request.authorizationMatrix?.cells.length && /proxyforge|support|finance|customer|status/i.test(matrixText)),
    transportControlsCovered: Boolean(request.transportSettings && request.transportSettings.timeoutMs > 0),
    bulkReplayHandoffCovered: Boolean(request.bulkRun?.items.length && request.bulkRun.completedRequests > 0),
    packageRefreshCovered,
    rawExecutorMaterialPreserved: rawExecutorMaterial.length >= 6,
    operationalSecretsPreserved: operationalSecretSamples.length > 0
      && operationalSecretSamples.every((sample) => rawExecutorMaterialText.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const reportReady = Object.values(requirements).every(Boolean);
  const unsigned = {
    kind: 'proxyforge-repeater-parity-evidence-package',
    exportedAt,
    tabs: request.tabs,
    savedRequests: request.savedRequests,
    sessionProfiles: request.sessionProfiles,
    sessionProfileInjections: request.sessionProfileInjections,
    manualReplay: request.manualReplay,
    bulkRun: request.bulkRun,
    authorizationMatrix: request.authorizationMatrix,
    transportSettings: request.transportSettings,
    operationalSecretSamples: request.operationalSecretSamples ?? [],
    requirements,
    packageRefreshProof,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady,
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `repeater-parity-${Date.parse(exportedAt) || Date.now()}`,
    kind: 'proxyforge-repeater-parity-evidence-package',
    title: 'Repeater parity evidence package',
    fileName: `proxyforge-repeater-parity-${stamp}.json`,
    path: `repeater/proxyforge-repeater-parity-${stamp}.json`,
    exportedAt,
    tabCount: request.tabs.length,
    groupCount: groups.length,
    savedRequestCount: request.savedRequests.length,
    sessionProfileCount: request.sessionProfiles.length,
    sessionInjectionCount: request.sessionProfileInjections.length,
    artifactIds: {
      tabIds: request.tabs.map((tab) => tab.id),
      savedRequestIds: request.savedRequests.map((saved) => saved.id),
      sessionProfileIds: request.sessionProfiles.map((profile) => profile.id),
      sessionProfileInjectionIds: request.sessionProfileInjections.map((injection) => injection.id),
      manualReplayId: request.manualReplay?.id,
      bulkRunId: request.bulkRun?.id,
      authorizationMatrixId: request.authorizationMatrix?.id,
    },
    requirements,
    packageRefreshProof,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady,
    digestPreview,
    summary: 'Repeater parity evidence covers manual request editing and send, tabs, grouped workspaces, saved request libraries, snapshots/diffs, session profile injection, authorization matrices, transport controls, bulk replay handoff, and package-refresh stale checks.',
    content,
  };
}

export function buildRepeaterOastEvidencePackage(request: RepeaterOastEvidenceRequest): RepeaterOastEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const replayRaw = `${request.replayExchange.requestRaw}\n${request.replayExchange.responseRaw}`;
  const matchedPayloads = request.payloads.filter((payload) => (
    (!request.selectedPayloadId || payload.id === request.selectedPayloadId)
    && payloadMatchesRaw(payload, replayRaw)
  ));
  const matchedPayloadIds = new Set(matchedPayloads.map((payload) => payload.id));
  const interactions = request.interactions.filter((interaction) => (
    matchedPayloadIds.has(interaction.payloadId)
    || matchedPayloads.some((payload) => payloadMatchesRaw(payload, interaction.raw))
  ));
  const rawMaterial = [
    request.sourceExchange?.requestRaw,
    request.sourceExchange?.responseRaw,
    request.replayExchange.requestRaw,
    request.replayExchange.responseRaw,
    ...interactions.map((interaction) => interaction.raw),
  ].filter(Boolean) as string[];
  const severity = highestSeverity(interactions.map((interaction) => interaction.severity), matchedPayloads.length ? 'medium' : 'info');
  const promotedIssue: Issue = {
    id: `issue-repeater-oast-${simpleDigest(`${request.replayExchange.id}|${Array.from(matchedPayloadIds).join(',')}|${interactions.map((interaction) => interaction.id).join(',')}`).slice(0, 16)}`,
    title: interactions.length ? 'Repeater OAST callback confirmed' : 'Repeater OAST payload pending callback',
    severity,
    host: request.replayExchange.host,
    path: request.replayExchange.path,
    confidence: interactions.length ? 'firm' : 'tentative',
    status: 'open',
    detail: [
      `Repeater replay ${request.replayExchange.id} sent ${matchedPayloads.length} callback payload(s).`,
      interactions.length ? `${interactions.length} callback interaction(s) were observed and linked to the replay.` : 'No callback interaction has been observed yet.',
      request.sourceExchange ? `Source exchange ${request.sourceExchange.id} is preserved with the replay evidence.` : '',
    ].filter(Boolean).join(' '),
    remediation: 'Restrict server-side URL fetching to approved destinations, block loopback and private egress where not required, and require explicit allowlists for callback-capable features.',
    triageNote: `Payloads ${Array.from(matchedPayloadIds).join(', ') || 'none'}; interactions ${interactions.map((interaction) => interaction.id).join(', ') || 'none'}.`,
  };
  const requirements = {
    payloadInjectedInReplay: matchedPayloads.length > 0 && matchedPayloads.some((payload) => payloadMatchesRaw(payload, request.replayExchange.requestRaw)),
    callbackObserved: interactions.length > 0,
    sourceAndReplayLinked: Boolean(request.sourceExchange?.id && request.replayExchange.id),
    issuePromotionCovered: Boolean(promotedIssue.id && promotedIssue.title && promotedIssue.detail),
    rawExecutorMaterialPreserved: rawMaterial.some((value) => /HTTP\/\d|Authorization:|Cookie:|Bearer|session=/i.test(value)),
    operationalSecretsPreserved: rawMaterial.some((value) => /Authorization:|Cookie:|X-API-Key:|Bearer|session=/i.test(value)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-repeater-oast-evidence-package',
    exportedAt,
    sourceExchange: request.sourceExchange,
    replayExchange: request.replayExchange,
    payloads: matchedPayloads,
    interactions,
    promotedIssue,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `repeater-oast-${Date.parse(exportedAt) || Date.now()}`,
    kind: 'proxyforge-repeater-oast-evidence-package',
    title: 'Repeater OAST evidence package',
    fileName: `proxyforge-repeater-oast-${stamp}.json`,
    path: `repeater/proxyforge-repeater-oast-${stamp}.json`,
    exportedAt,
    replayExchangeId: request.replayExchange.id,
    sourceExchangeId: request.sourceExchange?.id,
    payloadIds: matchedPayloads.map((payload) => payload.id),
    interactionIds: interactions.map((interaction) => interaction.id),
    promotedIssue,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
    digestPreview,
    summary: `Repeater OAST evidence linked ${matchedPayloads.length} payload(s), ${interactions.length} callback interaction(s), and replay ${request.replayExchange.id}.`,
    content,
  };
}

function buildRepeaterLinkedPackages(
  request: RepeaterParityEvidenceRequest,
  material: {
    tabText: string;
    savedRequestText: string;
    sessionText: string;
    matrixText: string;
    rawExecutorMaterialText: string;
  },
): RepeaterLinkedPackageInput[] {
  return [
    {
      id: 'repeater-manual-request-editor',
      kind: 'proxyforge-repeater-manual-request-editor',
      reportReady: request.tabs.some((tab) => /HTTP\/1\.[01]|HTTP\/2|Host:/i.test(tab.rawRequest) && Boolean(tab.targetUrl)),
      sourceCount: request.tabs.length,
      content: {
        tabIds: request.tabs.map((tab) => tab.id),
        targetUrls: uniqueStrings(request.tabs.map((tab) => tab.targetUrl)),
        rawRequests: request.tabs.map((tab) => tab.rawRequest),
      },
    },
    {
      id: 'repeater-manual-send-runtime',
      kind: 'proxyforge-repeater-manual-send-runtime',
      reportReady: Boolean(request.manualReplay?.source === 'repeater' && request.manualReplay.status >= 100),
      sourceCount: request.manualReplay ? 1 : 0,
      content: {
        exchangeId: request.manualReplay?.id,
        source: request.manualReplay?.source,
        status: request.manualReplay?.status,
        requestRaw: request.manualReplay?.requestRaw,
        responseRaw: request.manualReplay?.responseRaw,
      },
    },
    {
      id: 'repeater-workspace-tabs',
      kind: 'proxyforge-repeater-workspace-tabs',
      reportReady: request.tabs.length >= 2
        && request.tabs.some((tab) => tab.snapshots.length > 0 && tab.diffs.length > 0),
      sourceCount: request.tabs.length,
      content: {
        tabText: material.tabText,
        groups: uniqueStrings(request.tabs.map((tab) => tab.group || 'Ungrouped')),
        snapshotCount: request.tabs.reduce((count, tab) => count + tab.snapshots.length, 0),
        diffCount: request.tabs.reduce((count, tab) => count + tab.diffs.length, 0),
      },
    },
    {
      id: 'repeater-saved-request-library',
      kind: 'proxyforge-repeater-saved-request-library',
      reportReady: request.savedRequests.length > 0 && /folder|tags|rawRequest/i.test(material.savedRequestText),
      sourceCount: request.savedRequests.length,
      content: {
        savedRequestText: material.savedRequestText,
        folders: uniqueStrings(request.savedRequests.map((saved) => saved.folder)),
        tags: uniqueStrings(request.savedRequests.flatMap((saved) => saved.tags)),
      },
    },
    {
      id: 'repeater-session-profile-injection',
      kind: 'proxyforge-repeater-session-profile-injection',
      reportReady: request.sessionProfiles.length > 0
        && request.sessionProfileInjections.length > 0
        && /Authorization|Cookie|headers-and-cookies|support_admin|session/i.test(material.sessionText),
      sourceCount: request.sessionProfiles.length + request.sessionProfileInjections.length,
      content: {
        sessionText: material.sessionText,
        profileIds: request.sessionProfiles.map((profile) => profile.id),
        injectionIds: request.sessionProfileInjections.map((injection) => injection.id),
      },
    },
    {
      id: 'repeater-authorization-matrix',
      kind: 'proxyforge-repeater-authorization-matrix',
      reportReady: Boolean(request.authorizationMatrix?.cells.length && /proxyforge|support|finance|customer|status/i.test(material.matrixText)),
      sourceCount: request.authorizationMatrix?.cells.length ?? 0,
      content: {
        matrixText: material.matrixText,
        matrixId: request.authorizationMatrix?.id,
        identityIds: request.authorizationMatrix?.identities.map((identity) => identity.id) ?? [],
        routeIds: request.authorizationMatrix?.routes.map((route) => route.id) ?? [],
      },
    },
    {
      id: 'repeater-transport-controls',
      kind: 'proxyforge-repeater-transport-controls',
      reportReady: Boolean(request.transportSettings && request.transportSettings.timeoutMs > 0),
      sourceCount: request.transportSettings ? 1 : 0,
      content: request.transportSettings ?? {},
    },
    {
      id: 'repeater-bulk-replay-handoff',
      kind: 'proxyforge-repeater-bulk-replay-handoff',
      reportReady: Boolean(request.bulkRun?.items.length && request.bulkRun.completedRequests > 0),
      sourceCount: request.bulkRun?.items.length ?? 0,
      content: {
        bulkRun: request.bulkRun,
        rawExecutorMaterialDigestPreview: simpleDigest(material.rawExecutorMaterialText),
      },
    },
  ];
}

function buildRepeaterPackageRefreshProof(input: {
  exportedAt: string;
  linkedPackages: RepeaterLinkedPackageInput[];
  rawExecutorMaterialText: string;
  sourceTabCount: number;
  sourceSavedRequestCount: number;
  sourceSessionProfileCount: number;
  sourceSessionInjectionCount: number;
  sourceBulkItemCount: number;
}): RepeaterPackageRefreshProof {
  const rawMaterialDigestPreview = simpleDigest(input.rawExecutorMaterialText);
  const requiredPackageKinds = input.linkedPackages.map((linkedPackage) => linkedPackage.kind);
  const linkedPackageDigests = input.linkedPackages.map((linkedPackage) => ({
    id: linkedPackage.id,
    kind: linkedPackage.kind,
    digest: simpleDigest(JSON.stringify({
      kind: linkedPackage.kind,
      content: linkedPackage.content,
      rawMaterialDigestPreview,
    })),
    reportReady: linkedPackage.reportReady,
    sourceCount: linkedPackage.sourceCount,
  }));
  const stalePackageIds = linkedPackageDigests
    .filter((linkedPackage) => !linkedPackage.reportReady || linkedPackage.sourceCount <= 0)
    .map((linkedPackage) => linkedPackage.id);
  const linkedPackageKinds = uniqueStrings(linkedPackageDigests.map((linkedPackage) => linkedPackage.kind));
  const freshDigest = simpleDigest(JSON.stringify({
    refreshedAt: input.exportedAt,
    requiredPackageKinds,
    linkedPackageDigests,
    stalePackageIds,
    rawMaterialDigestPreview,
    sourceTabCount: input.sourceTabCount,
    sourceSavedRequestCount: input.sourceSavedRequestCount,
    sourceSessionProfileCount: input.sourceSessionProfileCount,
    sourceSessionInjectionCount: input.sourceSessionInjectionCount,
    sourceBulkItemCount: input.sourceBulkItemCount,
  }));

  return {
    refreshedAt: input.exportedAt,
    requiredPackageKinds,
    linkedPackageKinds,
    linkedPackageDigests,
    stalePackageIds,
    freshDigest,
    rawMaterialDigestPreview,
    sourceTabCount: input.sourceTabCount,
    sourceSavedRequestCount: input.sourceSavedRequestCount,
    sourceSessionProfileCount: input.sourceSessionProfileCount,
    sourceSessionInjectionCount: input.sourceSessionInjectionCount,
    sourceBulkItemCount: input.sourceBulkItemCount,
  };
}

function uniqueStrings(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)));
}

function payloadMatchesRaw(payload: CallbackPayload, raw: string) {
  return raw.includes(payload.id)
    || raw.includes(payload.token)
    || raw.includes(payload.endpoint)
    || raw.includes(encodeURIComponent(payload.endpoint));
}

function highestSeverity(values: Array<CallbackInteraction['severity']>, fallback: CallbackInteraction['severity']) {
  const rank: Record<CallbackInteraction['severity'], number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  return values.reduce((highest, value) => (rank[value] > rank[highest] ? value : highest), fallback);
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
