import type {
  ActiveScanRequest,
  ActiveScanSummary,
  ActiveScanCheckId,
  AutomationExecution,
  AiProviderConfig,
  AiProviderRuntime,
  AiRunRequest,
  AiRunResult,
  BrowserLaunchRequest,
  BrowserLaunchResult,
  BrowserCookieExtractionRequest,
  BrowserCookieExtractionResult,
  CallbackListenerPollResult,
  CallbackListenerProfile,
  CallbackListenerRuntimeStatus,
  CallbackPayload,
  CallbackProtocol,
  CertificateAuthorityExport,
  CertificateAuthorityStatus,
  CrawlAuditRequest,
  CrawlAuditSummary,
  CrawlInsertionPoint,
  CrawlRequest,
  CrawlRoute,
  CrawlSummary,
  EnterprisePolicyTransportRuntimeRequest,
  EnterprisePolicyTransportRuntimeResult,
  ExtensionRun,
  HttpExchange,
  HttpsInspectionStatus,
  InterceptDecision,
  InterceptedRequest,
  InterceptStatus,
  IntruderAttackMode,
  IntruderPayloadProcessor,
  IntruderPayloadRuleId,
  IntruderAttackRequest,
  IntruderAttackSummary,
  MatchReplaceRule,
  ProjectLifecycleBackupRequest,
  ProjectLifecycleBackupResponse,
  ProjectLifecycleCloseRequest,
  ProjectLifecycleCreateRequest,
  ProjectLifecycleOpenRequest,
  ProjectLifecycleState,
  ProjectFileArtifact,
  ProjectRunStatePersistResult,
  ProjectSnapshot,
  ProxyStatus,
  ReportArtifact,
  ReportExportRequest,
  ReplayRequest,
  RepeaterDesyncRuntimeRequest,
  RepeaterDesyncRuntimeResult,
  SequencerAnalysisResult,
  SequencerBitStat,
  SequencerCharacterSet,
  SequencerEntropySignificancePoint,
  SequencerFinding,
  SequencerPositionStat,
  SequencerReliabilitySummary,
  SequencerSampleRequest,
  SequencerStatisticalTest,
  SessionProfileRefreshRequest,
  SessionProfileRefreshResult,
  SignedAuditExport,
  WebSocketFrameDecision,
  WebSocketFrameRewriteRule,
  WebSocketInterceptStatus,
  WebSocketInterceptSettings,
  WebSocketMessage,
  WebSocketReplayRequest,
  WebSocketTranscriptExport,
  WebSocketTranscriptImportResult,
} from './types';

const PROJECT_STORAGE_KEY = 'proxyforge.project.v1';
const AI_PROVIDER_STORAGE_KEY = 'proxyforge.ai.providers.v1';
const INTRUDER_MAX_PAYLOAD_VALUES = 1000;
const INTRUDER_MAX_PAYLOAD_PLANS = 5000;
const INTRUDER_MAX_PAYLOAD_REQUESTS = 5000;
const INTRUDER_DEFAULT_STREAM_CHUNK_SIZE = 50;
const INTRUDER_MAX_MEMORY_BUDGET_BYTES = 512 * 1024 * 1024;

const browserMatchReplaceRules: MatchReplaceRule[] = [];
const browserWebSocketFrameRewriteRules: WebSocketFrameRewriteRule[] = [];
let browserCertificateProject = 'Browser Preview Project';
let browserUpstreamTlsMode: HttpsInspectionStatus['upstreamTlsMode'] = 'strict';

const browserInterceptState: InterceptStatus = {
  enabled: false,
  responseEnabled: false,
  pendingCount: 0,
  message: 'Browser preview intercept is local to the renderer.',
};

const browserWebSocketPending: WebSocketMessage[] = [];
let browserLifecycleState: ProjectLifecycleState = {
  kind: 'proxyforge-project-lifecycle-state',
  status: 'closed',
  projectsRootDir: 'browser-preview',
  backupsRootDir: 'browser-preview',
  recentProjects: [],
  requirements: {
    typedIpcContract: true,
    projectStoreBackbone: false,
    activeProjectRebindsRecorders: false,
    lifecycleAuditLedger: false,
    pathTraversalRejected: true,
    rawOperationalSecretsPreserved: true,
    reportPhaseOnlyRedaction: true,
  },
};
const browserLifecycleProjects = new Map<string, NonNullable<ProjectLifecycleState['activeProject']>>();

const browserWebSocketInterceptState: WebSocketInterceptStatus = {
  enabled: false,
  clientEnabled: true,
  serverEnabled: true,
  pendingCount: 0,
  message: 'Browser preview WebSocket intercept is local to the renderer.',
};

const defaultAiProviders: AiProviderRuntime[] = [
  {
    id: 'codex',
    label: 'Codex',
    mode: 'cli',
    enabled: true,
    model: 'configured-default',
    command: 'codex',
    args: ['exec', '--skip-git-repo-check', '--ephemeral', '--sandbox', 'read-only', '-'],
    timeoutMs: 90000,
    available: Boolean(window.proxyForge),
    secretPresent: true,
    status: window.proxyForge ? 'configured' : 'offline',
    message: window.proxyForge ? 'Desktop bridge can run Codex CLI when available.' : 'Browser preview cannot launch local CLIs.',
  },
  {
    id: 'claude',
    label: 'Claude',
    mode: 'cli',
    enabled: true,
    model: 'configured-default',
    command: 'claude',
    args: ['--print', '--no-session-persistence', '--permission-mode', 'dontAsk', '--tools', ''],
    timeoutMs: 90000,
    available: Boolean(window.proxyForge),
    secretPresent: true,
    status: window.proxyForge ? 'configured' : 'offline',
    message: window.proxyForge ? 'Desktop bridge can run Claude CLI when available.' : 'Browser preview cannot launch local CLIs.',
  },
  {
    id: 'local',
    label: 'OpenAI-compatible Local',
    mode: 'http',
    enabled: false,
    model: 'local-security-model',
    endpoint: 'http://127.0.0.1:11434/v1/chat/completions',
    apiKeyEnv: '',
    timeoutMs: 60000,
    available: false,
    secretPresent: true,
    status: 'offline',
    message: 'Configure a local OpenAI-compatible endpoint in desktop mode.',
  },
];

const defaultCustomReportTemplate = [
  '# {{projectName}} Operator Report',
  '',
  'Prepared for: {{preparedFor}}',
  'Brand: {{brandName}}',
  'Engagement: {{engagementId}}',
  'Generated: {{generatedAt}}',
  'Scope: {{scope}}',
  '',
  '{{executiveMarkdown}}',
  '',
  '{{findingsMarkdown}}',
  '',
  '{{remediationMarkdown}}',
  '',
  '{{evidenceMarkdown}}',
  '',
  '{{appendixMarkdown}}',
].join('\n');

export const defaultProxyStatus: ProxyStatus = {
  running: false,
  port: 8080,
  mode: window.proxyForge ? 'electron' : 'browser',
  message: window.proxyForge
    ? 'Electron bridge ready'
    : 'Browser preview mode. Desktop proxy is available in Electron.',
};

export function isElectronBridgeReady() {
  return Boolean(window.proxyForge);
}

export async function startProxy(port: number): Promise<ProxyStatus> {
  if (!window.proxyForge) {
    return {
      running: true,
      port,
      mode: 'browser',
      message: 'Simulated capture is enabled in browser preview.',
    };
  }

  return window.proxyForge.startProxy(port);
}

export async function stopProxy(): Promise<ProxyStatus> {
  if (!window.proxyForge) {
    return {
      running: false,
      port: 8080,
      mode: 'browser',
      message: 'Simulated capture stopped.',
    };
  }

  return window.proxyForge.stopProxy();
}

export async function getProxyStatus(): Promise<ProxyStatus> {
  if (!window.proxyForge) {
    return defaultProxyStatus;
  }

  return window.proxyForge.getProxyStatus();
}

export async function launchBrowser(request: BrowserLaunchRequest): Promise<BrowserLaunchResult> {
  if (window.proxyForge) {
    return window.proxyForge.launchBrowser(request);
  }

  const proxyHost = request.proxyHost?.trim() || '127.0.0.1';
  const proxyPort = Number.isFinite(request.proxyPort) ? request.proxyPort : 8080;
  const targetUrl = request.targetUrl.trim() || 'https://app.shop.local/';
  return {
    id: `browser-preview-launch-${Date.now()}`,
    status: 'preview',
    browser: request.browser,
    browserName: request.browser === 'auto' ? 'Managed browser' : request.browser,
    targetUrl,
    proxyHost,
    proxyPort,
    profilePath: 'browser-preview',
    command: 'browser-preview',
    args: [`--proxy-server=http=${proxyHost}:${proxyPort};https=${proxyHost}:${proxyPort}`, targetUrl],
    startedAt: new Date().toISOString(),
    message: `Browser preview launch plan ready for ${targetUrl}; desktop bridge required to start a local browser.`,
  };
}

export async function extractBrowserCookies(request: BrowserCookieExtractionRequest): Promise<BrowserCookieExtractionResult> {
  if (window.proxyForge) {
    return window.proxyForge.extractBrowserCookies(request);
  }

  const targetUrl = request.targetUrl.trim() || 'https://app.shop.local/';
  const host = safeHostname(targetUrl);
  const cookieHeader = host.endsWith('shop.local')
    ? 'session=browser-preview-session; csrf=browser-preview-csrf'
    : 'session=browser-preview-session';
  return {
    id: `browser-preview-cookie-capture-${Date.now()}`,
    status: 'complete',
    targetUrl,
    browser: request.browser,
    profilePath: request.profilePath || 'browser-preview',
    cookieHeader,
    cookieCount: cookieHeader.split(';').length,
    decryptedCount: 0,
    encryptedCount: 0,
    skippedCount: 0,
    extractedAt: new Date().toISOString(),
    cookies: cookieHeader.split(';').map((item) => {
      const [name, ...valueParts] = item.trim().split('=');
      return {
        name,
        value: valueParts.join('='),
        domain: host,
        path: '/',
        secure: true,
        httpOnly: name === 'session',
        sameSite: 'lax',
        source: request.browser === 'firefox' ? 'firefox' : 'chromium',
      };
    }),
    message: `Browser preview extracted ${cookieHeader.split(';').length} demo cookie values for ${host}.`,
  };
}

export async function refreshSessionProfile(request: SessionProfileRefreshRequest): Promise<SessionProfileRefreshResult> {
  if (window.proxyForge) {
    return window.proxyForge.refreshSessionProfile(request);
  }

  const now = new Date().toISOString();
  const refreshUrl = request.profile.refreshUrl?.trim() || request.profile.targetUrl || 'https://app.shop.local/session/refresh';
  const host = safeHostname(refreshUrl);
  const refreshedCookieText = mergeBrowserPreviewCookies(
    request.profile.cookieText,
    host.endsWith('shop.local')
      ? ['session=browser-preview-refreshed', 'csrf=browser-preview-csrf-refreshed']
      : ['session=browser-preview-refreshed'],
  );
  const profile = {
    ...request.profile,
    refreshUrl,
    status: 'ready',
    cookieText: refreshedCookieText,
    lastRefreshAt: now,
    updatedAt: now,
    refreshStatus: 'refreshed',
    refreshCookieCount: host.endsWith('shop.local') ? 2 : 1,
    refreshMessage: `Browser preview refreshed ${host} session cookies for desktop refresh workflow validation.`,
  } satisfies SessionProfileRefreshResult['profile'];
  const cookieCount = countCookiePairs(refreshedCookieText);
  return {
    profile: {
      ...profile,
      headerCount: Object.keys(parseHeaderText(profile.headerText)).length + (refreshedCookieText ? 1 : 0),
      cookieCount,
    },
    status: 'refreshed',
    statusCode: 200,
    setCookieCount: profile.refreshCookieCount ?? 0,
    headerCount: Object.keys(parseHeaderText(profile.headerText)).length + (refreshedCookieText ? 1 : 0),
    cookieCount,
    message: profile.refreshMessage ?? '',
    rawResponseHead: 'HTTP/1.1 200 OK\nSet-Cookie: session=browser-preview-refreshed\n\n',
  };
}

export async function resetProject(): Promise<void> {
  if (window.proxyForge) {
    await window.proxyForge.resetProject();
    return;
  }
  window.localStorage.removeItem(PROJECT_STORAGE_KEY);
}

export async function loadProject(): Promise<ProjectSnapshot | null> {
  if (window.proxyForge) {
    return window.proxyForge.loadProject();
  }

  const raw = window.localStorage.getItem(PROJECT_STORAGE_KEY);
  if (!raw) return null;

  try {
    return JSON.parse(raw) as ProjectSnapshot;
  } catch {
    window.localStorage.removeItem(PROJECT_STORAGE_KEY);
    return null;
  }
}

export async function createProject(request: ProjectLifecycleCreateRequest): Promise<ProjectLifecycleState> {
  if (window.proxyForge) return window.proxyForge.createProject(request);
  const now = new Date().toISOString();
  const projectName = request.projectName?.trim() || 'Browser Preview Project';
  const rootDir = request.rootDir?.trim() || 'browser-preview/project.proxyforge';
  const projectId = request.projectId?.trim() || slugifyFileName(projectName);
  const activeProject: NonNullable<ProjectLifecycleState['activeProject']> = {
    projectId,
    projectName,
    rootDir,
    snapshotPath: 'browser-preview/snapshot.proxyforge.json',
    manifest: {
      kind: 'proxyforge-project-store',
      schemaVersion: 2,
      projectId,
      projectName,
      createdAt: now,
      updatedAt: now,
    },
    stats: emptyProjectStoreStats(projectName),
    auditEvents: [{
      id: `browser-preview-audit-${Date.now()}`,
      actor: request.operator || 'browser-preview',
      action: 'project.create',
      targetRef: rootDir,
      decision: 'completed',
      detail: 'Browser preview project lifecycle event.',
      createdAt: now,
      hash: `browser-preview-${Date.now()}`,
    }],
  };
  browserLifecycleProjects.set(rootDir, activeProject);
  browserLifecycleState = {
    ...browserLifecycleState,
    status: 'open',
    activeProject,
    recentProjects: rememberBrowserLifecycleProject(activeProject),
  };
  return browserLifecycleState;
}

export async function openProject(request: ProjectLifecycleOpenRequest): Promise<ProjectLifecycleState> {
  if (window.proxyForge) return window.proxyForge.openProject(request);
  const rootDir = request.rootDir.trim();
  const existing = browserLifecycleProjects.get(rootDir);
  if (existing) {
    const now = new Date().toISOString();
    const auditEvents = [{
      id: `browser-preview-audit-${Date.now()}`,
      actor: request.operator || 'browser-preview',
      action: 'project.open',
      targetRef: rootDir,
      decision: 'completed' as const,
      detail: 'Browser preview reopened Project Store lifecycle state.',
      createdAt: now,
      previousHash: existing.auditEvents[0]?.hash,
      hash: `browser-preview-${Date.now()}`,
    }, ...existing.auditEvents].slice(0, 50);
    const activeProject = {
      ...existing,
      auditEvents,
      stats: {
        ...existing.stats,
        auditEventCount: auditEvents.length,
      },
    };
    browserLifecycleProjects.set(rootDir, activeProject);
    browserLifecycleState = {
      ...browserLifecycleState,
      status: 'open',
      activeProject,
      recentProjects: rememberBrowserLifecycleProject(activeProject),
    };
    return browserLifecycleState;
  }
  return createProject({
    projectName: request.rootDir.split(/[\\/]/).pop()?.replace(/\.proxyforge(?:-backup)?$/, '') || 'Browser Preview Project',
    rootDir: request.rootDir,
    operator: request.operator,
    allowExternalRoot: request.allowExternalRoot,
  });
}

export async function closeProject(request?: ProjectLifecycleCloseRequest): Promise<ProjectLifecycleState> {
  if (window.proxyForge) return window.proxyForge.closeProject(request);
  const recent = browserLifecycleState.activeProject
    ? rememberBrowserLifecycleProject(browserLifecycleState.activeProject)
    : browserLifecycleState.recentProjects;
  browserLifecycleState = {
    ...browserLifecycleState,
    status: 'closed',
    activeProject: undefined,
    recentProjects: recent,
  };
  return browserLifecycleState;
}

export async function getProjectLifecycle(): Promise<ProjectLifecycleState> {
  if (window.proxyForge) return window.proxyForge.getProjectLifecycle();
  return browserLifecycleState;
}

export async function backupProject(request?: ProjectLifecycleBackupRequest): Promise<ProjectLifecycleBackupResponse> {
  if (window.proxyForge) return window.proxyForge.backupProject(request);
  if (!browserLifecycleState.activeProject) throw new Error('Open or create a project before creating a browser-preview backup.');
  const now = new Date().toISOString();
  return {
    kind: 'proxyforge-project-lifecycle-backup-response',
    backup: {
      kind: 'proxyforge-project-store-backup',
      schemaVersion: 1,
      projectId: browserLifecycleState.activeProject.projectId,
      projectName: browserLifecycleState.activeProject.projectName,
      sourceRootDir: browserLifecycleState.activeProject.rootDir,
      backupRootDir: request?.backupRootDir || 'browser-preview/backups',
      backupDir: 'browser-preview/backups/project.proxyforge-backup',
      label: request?.label || browserLifecycleState.activeProject.projectName,
      createdAt: now,
      manifestPath: 'browser-preview/backups/project.proxyforge-backup/backup-manifest.json',
      stats: browserLifecycleState.activeProject.stats,
      content: JSON.stringify({ kind: 'proxyforge-project-store-backup', browserPreview: true }),
      requirements: {
        manifestCopied: false,
        databaseCopied: false,
        blobsCopied: false,
        recoveryJournalCopied: false,
        rawOperationalSecretsPreserved: true,
        reportPhaseOnlyRedaction: true,
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    },
    state: browserLifecycleState,
  };
}

export async function saveProject(snapshot: ProjectSnapshot): Promise<ProjectSnapshot> {
  if (window.proxyForge) {
    return window.proxyForge.saveProject(snapshot);
  }

  window.localStorage.setItem(PROJECT_STORAGE_KEY, JSON.stringify(snapshot));
  return snapshot;
}

export async function exportProjectFile(snapshot: ProjectSnapshot): Promise<ProjectFileArtifact | null> {
  const next = {
    ...snapshot,
    savedAt: new Date().toISOString(),
  } satisfies ProjectSnapshot;

  if (window.proxyForge) {
    return window.proxyForge.exportProjectFile(next);
  }

  const content = JSON.stringify(next, null, 2);
  const exportedAt = new Date().toISOString();
  return {
    id: `project-export-${Date.now()}`,
    fileName: `${slugifyFileName(next.projectName)}.proxyforge.json`,
    path: 'browser-preview',
    exportedAt,
    projectName: next.projectName,
    exchangeCount: next.exchanges.length,
    scopeCount: next.scopeAllowlist.length,
    sizeBytes: new Blob([content]).size,
    content,
  };
}

export async function importProjectFile(content?: string): Promise<ProjectSnapshot | null> {
  if (window.proxyForge && !content?.trim()) {
    return window.proxyForge.importProjectFile();
  }

  const snapshot = parseProjectSnapshotContent(content ?? '');
  return saveProject(snapshot);
}

export async function exportSignedAuditPackage(artifact: SignedAuditExport): Promise<SignedAuditExport | null> {
  if (window.proxyForge) {
    return window.proxyForge.exportSignedAuditPackage(artifact);
  }

  const content = artifact.content ?? '';
  return {
    ...artifact,
    path: 'browser-preview',
    sizeBytes: new Blob([content]).size,
    content,
  };
}

export async function exportWebSocketTranscript(artifact: WebSocketTranscriptExport): Promise<WebSocketTranscriptExport | null> {
  if (window.proxyForge) {
    return window.proxyForge.exportWebSocketTranscript(artifact);
  }

  const content = artifact.content ?? '';
  return {
    ...artifact,
    filePath: 'browser-preview',
    sizeBytes: new Blob([content]).size,
    content,
  };
}

export async function importWebSocketTranscript(content?: string): Promise<WebSocketTranscriptImportResult | null> {
  if (window.proxyForge && !content?.trim()) {
    return window.proxyForge.importWebSocketTranscript();
  }

  return parseWebSocketTranscriptContent(content ?? '');
}

export async function pushEnterprisePolicyRemote(request: EnterprisePolicyTransportRuntimeRequest): Promise<EnterprisePolicyTransportRuntimeResult> {
  if (!window.proxyForge) throw new Error('Remote enterprise policy HTTP transport requires the desktop bridge.');
  if (!request.policyPackage) throw new Error('Enterprise policy push requires a policy package.');
  return window.proxyForge.pushEnterprisePolicy(request);
}

export async function pullEnterprisePolicyRemote(request: EnterprisePolicyTransportRuntimeRequest): Promise<EnterprisePolicyTransportRuntimeResult> {
  if (!window.proxyForge) throw new Error('Remote enterprise policy HTTP transport requires the desktop bridge.');
  return window.proxyForge.pullEnterprisePolicy(request);
}

export async function replayRequest(request: ReplayRequest): Promise<HttpExchange> {
  if (window.proxyForge) {
    return window.proxyForge.replayRequest(request);
  }

  return simulateReplay(request);
}

export async function runRepeaterDesyncProbe(request: RepeaterDesyncRuntimeRequest): Promise<RepeaterDesyncRuntimeResult> {
  if (window.proxyForge) {
    return window.proxyForge.runRepeaterDesyncProbe(request);
  }

  return simulateRepeaterDesyncRuntime(request, 'single-connection');
}

export async function runRepeaterParallelRace(request: RepeaterDesyncRuntimeRequest): Promise<RepeaterDesyncRuntimeResult> {
  if (window.proxyForge) {
    return window.proxyForge.runRepeaterParallelRace(request);
  }

  return simulateRepeaterDesyncRuntime(request, request.syncTechnique === 'single-packet' ? 'parallel-single-packet' : 'parallel-last-byte');
}

function parseProjectSnapshotContent(content: string): ProjectSnapshot {
  if (!content.trim()) throw new Error('Paste a ProxyForge project JSON file before importing.');
  const parsed = JSON.parse(content) as ProjectSnapshot;
  if (parsed.version !== 1 || typeof parsed.projectName !== 'string' || !Array.isArray(parsed.scopeAllowlist) || !Array.isArray(parsed.exchanges)) {
    throw new Error('This is not a valid ProxyForge v1 project file.');
  }
  return {
    ...parsed,
    savedAt: new Date().toISOString(),
  };
}

function parseWebSocketTranscriptContent(content: string): WebSocketTranscriptImportResult {
  if (!content.trim()) throw new Error('Paste or choose a ProxyForge WebSocket transcript before importing.');
  const now = new Date().toISOString();
  try {
    const parsed = JSON.parse(content) as Partial<WebSocketTranscriptExport> & {
      kind?: string;
      exportedAt?: string;
      frames?: unknown[];
      fuzzRuns?: unknown[];
      stateDiffs?: unknown[];
      closeCodeInsights?: unknown[];
    };
    if (parsed.kind && parsed.kind !== 'proxyforge-websocket-transcript') throw new Error('Unsupported WebSocket transcript JSON.');
    if (typeof parsed.connectionId !== 'string' || typeof parsed.host !== 'string' || typeof parsed.path !== 'string') {
      throw new Error('Transcript JSON is missing connection metadata.');
    }
    const artifact: WebSocketTranscriptImportResult = {
      id: typeof parsed.id === 'string' ? parsed.id : `ws-transcript-import-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      title: typeof parsed.title === 'string' ? parsed.title : `${parsed.host}${parsed.path} WebSocket transcript`,
      fileName: typeof parsed.fileName === 'string' ? parsed.fileName : `${slugifyFileName(`${parsed.host}-${parsed.path}`)}.proxyforge-ws.json`,
      filePath: 'browser-preview',
      createdAt: typeof parsed.createdAt === 'string' ? parsed.createdAt : parsed.exportedAt ?? now,
      connectionId: parsed.connectionId,
      host: parsed.host,
      path: parsed.path,
      format: parsed.format === 'markdown' ? 'markdown' : 'json',
      frameCount: typeof parsed.frameCount === 'number' ? parsed.frameCount : Array.isArray(parsed.frames) ? parsed.frames.length : 0,
      fuzzRunIds: Array.isArray(parsed.fuzzRunIds)
        ? parsed.fuzzRunIds.filter((item): item is string => typeof item === 'string')
        : Array.isArray(parsed.fuzzRuns) ? parsed.fuzzRuns.map((item) => (item && typeof item === 'object' && 'id' in item ? String(item.id) : '')).filter(Boolean) : [],
      stateDiffIds: Array.isArray(parsed.stateDiffIds)
        ? parsed.stateDiffIds.filter((item): item is string => typeof item === 'string')
        : Array.isArray(parsed.stateDiffs) ? parsed.stateDiffs.map((item) => (item && typeof item === 'object' && 'id' in item ? String(item.id) : '')).filter(Boolean) : [],
      closeCodeCount: typeof parsed.closeCodeCount === 'number' ? parsed.closeCodeCount : Array.isArray(parsed.closeCodeInsights) ? parsed.closeCodeInsights.length : 0,
      sizeBytes: new Blob([content]).size,
      content,
    };
    return artifact;
  } catch (error) {
    if (content.trim().startsWith('{')) throw error;
    const title = content.match(/^#\s+(.+)$/m)?.[1]?.trim() || 'Imported WebSocket transcript';
    const connection = content.match(/^Connection:\s*(.+)$/m)?.[1]?.trim() || `imported-${Date.now()}`;
    const frameCount = (content.match(/^###\s+/gm) ?? []).length;
    return {
      id: `ws-transcript-import-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      title,
      fileName: `${slugifyFileName(title)}.md`,
      filePath: 'browser-preview',
      createdAt: now,
      connectionId: connection,
      host: 'imported.websocket.local',
      path: '/imported-transcript',
      format: 'markdown',
      frameCount,
      fuzzRunIds: [],
      stateDiffIds: [],
      closeCodeCount: (content.match(/Close\s+\d{4}/g) ?? []).length,
      sizeBytes: new Blob([content]).size,
      content,
    };
  }
}

function slugifyFileName(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'proxyforge-project';
}

function emptyProjectStoreStats(projectName: string) {
  return {
    projectName,
    schemaVersion: 2 as const,
    exchangeCount: 0,
    scopeRuleCount: 0,
    auditEventCount: 1,
    projectSettingCount: 0,
    sessionCookieCount: 0,
    targetHostCount: 0,
    targetRouteCount: 0,
    parameterCount: 0,
    callbackPayloadCount: 0,
    callbackInteractionCount: 0,
    repeaterTabCount: 0,
    repeaterSendCount: 0,
    webSocketConnectionCount: 0,
    webSocketFrameCount: 0,
    intruderAttackCount: 0,
    intruderResultCount: 0,
    scannerTaskCount: 0,
    scannerFindingCount: 0,
    scannerSuppressedFindingCount: 0,
    issueCount: 0,
    reportExportCount: 0,
    automationRunCount: 0,
    aiRunCount: 0,
    extensionRunCount: 0,
    blobCount: 0,
    requestBytes: 0,
    responseBytes: 0,
    callbackBytes: 0,
    repeaterRequestBytes: 0,
    repeaterResponseBytes: 0,
    webSocketPayloadBytes: 0,
    intruderRequestBytes: 0,
    intruderResponseBytes: 0,
    reportBytes: 0,
    aiPromptBytes: 0,
    aiOutputBytes: 0,
  };
}

function rememberBrowserLifecycleProject(project: NonNullable<ProjectLifecycleState['activeProject']>) {
  return [
    {
      projectId: project.projectId,
      projectName: project.projectName,
      rootDir: project.rootDir,
      openedAt: new Date().toISOString(),
    },
    ...browserLifecycleState.recentProjects.filter((recent) => recent.rootDir !== project.rootDir),
  ].slice(0, 20);
}

function safeHostname(value: string) {
  try {
    return new URL(value).hostname;
  } catch {
    return value.replace(/^https?:\/\//i, '').split('/')[0] || 'browser-preview.local';
  }
}

function parseHeaderText(headerText: string) {
  const headers: Record<string, string> = {};
  for (const line of headerText.split(/\r?\n/)) {
    const separator = line.indexOf(':');
    if (separator <= 0) continue;
    const name = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!name || !value || /[\r\n]/.test(value)) continue;
    headers[name] = value;
  }
  return headers;
}

function normalizeCookieText(cookieText: string) {
  return cookieText
    .replace(/^cookie:\s*/i, '')
    .split(/[;\n]+/)
    .map((item) => item.trim())
    .filter((item) => item && item.includes('=') && !/[\r\n]/.test(item));
}

function countCookiePairs(cookieText: string) {
  return normalizeCookieText(cookieText).length;
}

function mergeBrowserPreviewCookies(existingCookieText: string, refreshedCookies: string[]) {
  const cookies = new Map<string, string>();
  for (const cookie of normalizeCookieText(existingCookieText)) {
    const [name, ...valueParts] = cookie.split('=');
    if (name && valueParts.length) cookies.set(name.trim(), valueParts.join('=').trim());
  }
  for (const cookie of refreshedCookies) {
    const [name, ...valueParts] = cookie.split('=');
    if (name && valueParts.length) cookies.set(name.trim(), valueParts.join('=').trim());
  }
  return Array.from(cookies.entries()).map(([name, value]) => `${name}=${value}`).join('; ');
}

export async function runIntruderAttack(request: IntruderAttackRequest): Promise<IntruderAttackSummary> {
  if (window.proxyForge) {
    return window.proxyForge.runIntruderAttack(request);
  }

  return simulateIntruderAttack(request);
}

export async function runCrawl(request: CrawlRequest): Promise<CrawlSummary> {
  if (window.proxyForge) {
    return window.proxyForge.runCrawl(request);
  }

  return simulateCrawl(request);
}

export async function runActiveScan(request: ActiveScanRequest): Promise<ActiveScanSummary> {
  if (window.proxyForge) {
    return window.proxyForge.runActiveScan(request);
  }

  return simulateActiveScan(request);
}

export async function runCrawlAudit(request: CrawlAuditRequest): Promise<CrawlAuditSummary> {
  if (window.proxyForge) {
    return window.proxyForge.runCrawlAudit(request);
  }

  return simulateCrawlAudit(request);
}

export async function getInterceptStatus(): Promise<InterceptStatus> {
  if (window.proxyForge) {
    return window.proxyForge.getInterceptStatus();
  }

  return browserInterceptState;
}

export async function setIntercept(enabled: boolean): Promise<InterceptStatus> {
  if (window.proxyForge) {
    return window.proxyForge.setIntercept(enabled);
  }

  browserInterceptState.enabled = enabled;
  browserInterceptState.message = enabled ? 'Browser preview holds simulated requests in the UI queue.' : 'Browser preview intercept disabled.';
  return browserInterceptState;
}

export async function setResponseIntercept(enabled: boolean): Promise<InterceptStatus> {
  if (window.proxyForge) {
    return window.proxyForge.setResponseIntercept(enabled);
  }

  browserInterceptState.responseEnabled = enabled;
  browserInterceptState.message = enabled ? 'Browser preview will hold simulated responses.' : 'Browser preview response intercept disabled.';
  return browserInterceptState;
}

export async function listIntercepts(): Promise<InterceptedRequest[]> {
  if (window.proxyForge) {
    return window.proxyForge.listIntercepts();
  }

  return [];
}

export async function resolveIntercept(decision: InterceptDecision): Promise<InterceptStatus> {
  if (window.proxyForge) {
    return window.proxyForge.resolveIntercept(decision);
  }

  browserInterceptState.pendingCount = Math.max(0, browserInterceptState.pendingCount - 1);
  browserInterceptState.message = `Browser preview ${decision.action} decision applied.`;
  return browserInterceptState;
}

export async function getWebSocketInterceptStatus(): Promise<WebSocketInterceptStatus> {
  if (window.proxyForge) {
    return window.proxyForge.getWebSocketInterceptStatus();
  }

  return { ...browserWebSocketInterceptState, pendingCount: browserWebSocketPending.length };
}

export async function setWebSocketIntercept(settings: boolean | WebSocketInterceptSettings): Promise<WebSocketInterceptStatus> {
  if (window.proxyForge) {
    return window.proxyForge.setWebSocketIntercept(settings);
  }

  const next = typeof settings === 'boolean'
    ? { enabled: settings, clientEnabled: true, serverEnabled: true }
    : settings;
  const enabled = next.enabled;
  browserWebSocketInterceptState.enabled = enabled;
  browserWebSocketInterceptState.clientEnabled = next.clientEnabled;
  browserWebSocketInterceptState.serverEnabled = next.serverEnabled;
  if (enabled && browserWebSocketPending.length === 0) {
    const direction = browserWebSocketInterceptState.clientEnabled ? 'client' : 'server';
    browserWebSocketPending.push(makePreviewWebSocketFrame(['held', 'preview'], { direction }));
  }
  browserWebSocketInterceptState.pendingCount = browserWebSocketPending.length;
  browserWebSocketInterceptState.message = enabled
    ? browserWebSocketInterceptMessage(browserWebSocketInterceptState)
    : 'Browser preview WebSocket intercept disabled.';
  return { ...browserWebSocketInterceptState };
}

export async function listWebSocketIntercepts(): Promise<WebSocketMessage[]> {
  if (window.proxyForge) {
    return window.proxyForge.listWebSocketIntercepts();
  }

  return [...browserWebSocketPending];
}

export async function resolveWebSocketIntercept(decision: WebSocketFrameDecision): Promise<WebSocketInterceptStatus> {
  if (window.proxyForge) {
    return window.proxyForge.resolveWebSocketIntercept(decision);
  }

  const index = browserWebSocketPending.findIndex((frame) => frame.id === decision.id);
  if (index !== -1) browserWebSocketPending.splice(index, 1);
  browserWebSocketInterceptState.pendingCount = browserWebSocketPending.length;
  browserWebSocketInterceptState.message = `Browser preview ${decision.action === 'drop' ? 'dropped' : 'forwarded'} WebSocket frame.`;
  return { ...browserWebSocketInterceptState };
}

export async function replayWebSocketFrame(request: WebSocketReplayRequest): Promise<WebSocketMessage> {
  if (window.proxyForge) {
    return window.proxyForge.replayWebSocketFrame(request);
  }

  return makePreviewWebSocketFrame(['replayed', 'preview'], request);
}

export async function getMatchReplaceRules(): Promise<MatchReplaceRule[]> {
  if (window.proxyForge) {
    return window.proxyForge.getMatchReplaceRules();
  }

  return browserMatchReplaceRules;
}

export async function setMatchReplaceRules(rules: MatchReplaceRule[]): Promise<MatchReplaceRule[]> {
  if (window.proxyForge) {
    return window.proxyForge.setMatchReplaceRules(rules);
  }

  browserMatchReplaceRules.splice(0, browserMatchReplaceRules.length, ...rules);
  return browserMatchReplaceRules;
}

export async function getWebSocketFrameRewriteRules(): Promise<WebSocketFrameRewriteRule[]> {
  if (window.proxyForge) {
    return window.proxyForge.getWebSocketFrameRewriteRules();
  }

  return browserWebSocketFrameRewriteRules;
}

export async function setWebSocketFrameRewriteRules(rules: WebSocketFrameRewriteRule[]): Promise<WebSocketFrameRewriteRule[]> {
  if (window.proxyForge) {
    return window.proxyForge.setWebSocketFrameRewriteRules(rules);
  }

  browserWebSocketFrameRewriteRules.splice(0, browserWebSocketFrameRewriteRules.length, ...rules);
  return browserWebSocketFrameRewriteRules;
}

export async function getCertificateStatus(): Promise<CertificateAuthorityStatus> {
  if (window.proxyForge) {
    return window.proxyForge.getCertificateStatus();
  }

  return browserCertificateStatus('Root CA generation is available in the desktop shell.');
}

export async function setCertificateProject(projectName: string): Promise<CertificateAuthorityStatus> {
  if (window.proxyForge) {
    return window.proxyForge.setCertificateProject(projectName);
  }

  browserCertificateProject = projectName.trim() || browserCertificateProject;
  return browserCertificateStatus(`Browser preview certificate workspace switched to ${browserCertificateProject}.`);
}

function browserCertificateStatus(message: string): CertificateAuthorityStatus {
  const projectId = browserCertificateProject.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'browser-preview-project';
  return {
    ready: false,
    rootCertificatePath: 'Electron desktop mode',
    projectId,
    projectLabel: browserCertificateProject,
    projectCertificateDir: `Electron desktop mode / certificates/projects/${projectId}`,
    hostCertificateCount: 0,
    message,
  };
}

export async function ensureRootCertificate(): Promise<CertificateAuthorityStatus> {
  if (window.proxyForge) {
    return window.proxyForge.ensureRootCertificate();
  }

  return browserCertificateStatus('Browser preview cannot create a local root CA. Launch Electron desktop mode.');
}

export async function exportRootCertificate(): Promise<CertificateAuthorityExport> {
  if (window.proxyForge) {
    return window.proxyForge.exportRootCertificate();
  }

  return {
    pem: '',
    path: 'Electron desktop mode',
    fingerprintSha256: undefined,
  };
}

export async function rotateRootCertificate(): Promise<CertificateAuthorityStatus> {
  if (window.proxyForge) {
    return window.proxyForge.rotateRootCertificate();
  }

  return browserCertificateStatus('Browser preview cannot rotate a desktop root CA. Launch Electron desktop mode.');
}

export async function revokeRootCertificate(): Promise<CertificateAuthorityStatus> {
  if (window.proxyForge) {
    return window.proxyForge.revokeRootCertificate();
  }

  return {
    ...browserCertificateStatus('Browser preview cannot revoke a desktop root CA. Remove trusted PEMs outside the app.'),
    revokedAt: new Date().toISOString(),
  };
}

export async function getHttpsInspectionStatus(): Promise<HttpsInspectionStatus> {
  if (window.proxyForge) {
    return window.proxyForge.getHttpsInspectionStatus();
  }

  return {
    enabled: false,
    upstreamTlsMode: browserUpstreamTlsMode,
    message: 'HTTPS inspection is available in the desktop shell after the root CA is trusted.',
  };
}

export async function setHttpsInspection(enabled: boolean): Promise<HttpsInspectionStatus> {
  if (window.proxyForge) {
    return window.proxyForge.setHttpsInspection(enabled);
  }

  return {
    enabled: false,
    upstreamTlsMode: browserUpstreamTlsMode,
    message: enabled
      ? 'Browser preview cannot intercept HTTPS. Launch Electron desktop mode.'
      : 'HTTPS inspection disabled in browser preview.',
  };
}

export async function setUpstreamTlsValidation(mode: HttpsInspectionStatus['upstreamTlsMode']): Promise<HttpsInspectionStatus> {
  if (window.proxyForge) {
    return window.proxyForge.setUpstreamTlsValidation(mode);
  }

  browserUpstreamTlsMode = mode === 'strict' ? 'strict' : 'relaxed';
  return {
    enabled: false,
    upstreamTlsMode: browserUpstreamTlsMode,
    message: `Browser preview recorded ${browserUpstreamTlsMode} upstream TLS validation for desktop mode.`,
  };
}

export async function startCallbackListener(profile: CallbackListenerProfile, payloads: CallbackPayload[]): Promise<CallbackListenerRuntimeStatus> {
  if (window.proxyForge) {
    return window.proxyForge.startCallbackListener(profile, payloads);
  }
  return browserCallbackListenerStatus(profile, false, 'Desktop bridge required to start local HTTP/DNS/SMTP callback listeners.');
}

export async function stopCallbackListener(profileId: string): Promise<CallbackListenerRuntimeStatus> {
  if (window.proxyForge) {
    return window.proxyForge.stopCallbackListener(profileId);
  }
  return browserCallbackListenerStatus({ id: profileId } as CallbackListenerProfile, false, 'Browser preview has no local callback listener to stop.');
}

export async function pollCallbackListener(profileId: string, payloads: CallbackPayload[]): Promise<CallbackListenerPollResult> {
  if (window.proxyForge) {
    return window.proxyForge.pollCallbackListener(profileId, payloads);
  }
  return {
    status: browserCallbackListenerStatus({ id: profileId } as CallbackListenerProfile, false, 'Browser preview callback polling uses deterministic simulator interactions.'),
    interactions: [],
    newInteractionIds: [],
  };
}

export async function getCallbackListenerStatus(profileId: string): Promise<CallbackListenerRuntimeStatus> {
  if (window.proxyForge) {
    return window.proxyForge.getCallbackListenerStatus(profileId);
  }
  return browserCallbackListenerStatus({ id: profileId } as CallbackListenerProfile, false, 'Browser preview callback listener is not running.');
}

function browserCallbackListenerStatus(profile: CallbackListenerProfile, running: boolean, message: string): CallbackListenerRuntimeStatus {
  return {
    profileId: profile.id,
    running,
    mode: profile.mode ?? 'browser-preview',
    host: profile.host ?? '127.0.0.1',
    protocols: profile.protocols ?? ([] as CallbackProtocol[]),
    ports: {},
    interactionCount: 0,
    stoppedAt: running ? undefined : new Date().toISOString(),
    healthChecks: [],
    message,
  };
}

export async function getAiProviders(): Promise<AiProviderRuntime[]> {
  if (window.proxyForge) {
    return window.proxyForge.getAiProviders();
  }

  const raw = window.localStorage.getItem(AI_PROVIDER_STORAGE_KEY);
  if (!raw) return defaultAiProviders;

  try {
    const configs = JSON.parse(raw) as AiProviderConfig[];
    return mergeBrowserAiProviders(configs);
  } catch {
    window.localStorage.removeItem(AI_PROVIDER_STORAGE_KEY);
    return defaultAiProviders;
  }
}

export async function setAiProviders(configs: AiProviderConfig[]): Promise<AiProviderRuntime[]> {
  if (window.proxyForge) {
    return window.proxyForge.setAiProviders(configs);
  }

  window.localStorage.setItem(AI_PROVIDER_STORAGE_KEY, JSON.stringify(configs));
  return mergeBrowserAiProviders(configs);
}

export async function runAiTask(request: AiRunRequest): Promise<AiRunResult> {
  if (window.proxyForge) {
    return window.proxyForge.runAiTask(request);
  }

  const startedAt = new Date();
  const output = buildBrowserAiFallback(request);
  const completedAt = new Date();
  const promptEvaluation = buildBrowserPromptEvaluation(request);
  const promptTokens = estimateBrowserTokens(request.prompt);
  const completionTokens = estimateBrowserTokens(output);
  return {
    id: `ai-preview-${startedAt.getTime()}`,
    providerId: request.providerId,
    task: request.task,
    status: 'complete',
    model: 'browser-preview',
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    summary: 'Browser preview generated a local AI workflow plan',
    output,
    evidenceCount: request.context.exchanges.length + request.context.issues.length,
    command: 'browser-preview',
    usage: {
      promptTokens,
      completionTokens,
      totalTokens: promptTokens + completionTokens,
      estimatedCostUsd: 0,
      latencyMs: completedAt.getTime() - startedAt.getTime(),
      source: 'browser-preview',
    },
    streamEvents: [
      {
        id: `ai-stream-preview-${startedAt.getTime()}-prompt`,
        at: startedAt.toISOString(),
        source: 'prompt',
        text: `Browser preview staged ${request.providerId} ${request.task} prompt.`,
      },
      {
        id: `ai-stream-preview-${startedAt.getTime()}-fallback`,
        at: completedAt.toISOString(),
        source: 'fallback',
        text: 'Browser preview generated deterministic local AI workflow plan.',
      },
      {
        id: `ai-stream-preview-${startedAt.getTime()}-complete`,
        at: completedAt.toISOString(),
        source: 'complete',
        text: `Prompt evaluation score ${promptEvaluation.score}.`,
      },
    ],
    promptEvaluation,
    suggestedActions: buildBrowserAiSuggestedActions(request),
  };
}

export async function recordAutomationRun(execution: AutomationExecution): Promise<ProjectRunStatePersistResult | null> {
  if (window.proxyForge) {
    return window.proxyForge.recordAutomationRun(execution);
  }
  return null;
}

export async function recordExtensionRun(run: ExtensionRun): Promise<ProjectRunStatePersistResult | null> {
  if (window.proxyForge) {
    return window.proxyForge.recordExtensionRun(run);
  }
  return null;
}

export async function exportReport(request: ReportExportRequest): Promise<ReportArtifact> {
  if (window.proxyForge) {
    return window.proxyForge.exportReport(request);
  }

  const generatedAt = new Date();
  const content = await renderBrowserReportForExport(request, generatedAt);
  const extension = reportExtension(request.format);
  return {
    id: `report-preview-${generatedAt.getTime()}`,
    format: request.format,
    fileName: `${request.projectName.toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'proxyforge-report'}.${extension}`,
    path: 'browser-preview',
    generatedAt: generatedAt.toISOString(),
    issueCount: request.issues.length,
    exchangeCount: request.exchanges.length,
    content,
  };
}

async function renderBrowserReportForExport(request: ReportExportRequest, generatedAt: Date): Promise<string> {
  if (request.format !== 'bundle' || !request.signEvidenceBundle) {
    return renderBrowserReport(request, generatedAt);
  }

  const unsignedBundle = JSON.parse(renderBrowserReport({ ...request, signEvidenceBundle: false }, generatedAt)) as Record<string, unknown>;
  unsignedBundle.signature = await signBrowserEvidenceBundle(unsignedBundle, request, generatedAt);
  return JSON.stringify(unsignedBundle, null, 2);
}

export async function analyzeSequencerSamples(request: SequencerSampleRequest): Promise<SequencerAnalysisResult> {
  if (window.proxyForge) {
    return window.proxyForge.analyzeSequencerSamples(request);
  }

  return analyzeBrowserSequencerSamples({
    ...request,
    source: request.source === 'manual' ? 'manual' : 'browser-preview',
  });
}

export function subscribeToProxyExchange(handler: (exchange: HttpExchange) => void) {
  if (!window.proxyForge) {
    return () => undefined;
  }

  return window.proxyForge.onExchange(handler);
}

export function subscribeToInterceptQueue(handler: (pending: InterceptedRequest[]) => void) {
  if (!window.proxyForge) {
    return () => undefined;
  }

  return window.proxyForge.onInterceptQueue(handler);
}

export function subscribeToWebSocketMessages(handler: (message: WebSocketMessage) => void) {
  if (!window.proxyForge) {
    return () => undefined;
  }

  return window.proxyForge.onWebSocketMessage(handler);
}

export function subscribeToWebSocketInterceptQueue(handler: (pending: WebSocketMessage[]) => void) {
  if (!window.proxyForge) {
    return () => undefined;
  }

  return window.proxyForge.onWebSocketInterceptQueue(handler);
}

function makePreviewWebSocketFrame(tags: string[], request?: Partial<WebSocketReplayRequest>): WebSocketMessage {
  const now = new Date();
  const opcode = request?.opcode ?? 1;
  const payload = request?.payload ?? (opcode === 2 ? '7b2274797065223a2262696e6172792d70726f6265227d' : '{"subscribe":"orders","scope":"mine"}');
  const payloadEncoding = request?.payloadEncoding ?? (opcode === 2 ? 'hex' : 'text');
  return {
    id: `ws-preview-${now.getTime()}-${Math.random().toString(16).slice(2)}`,
    connectionId: request?.connectionId ?? 'ws-seed',
    time: now.toLocaleTimeString([], { hour12: false }),
    direction: request?.direction ?? 'client',
    host: 'stream.shop.local',
    path: '/socket/orders',
    url: 'wss://stream.shop.local/socket/orders',
    opcode,
    type: opcode === 2 ? 'binary' : 'text',
    payload,
    payloadEncoding,
    length: payload.length,
    tags: ['websocket', ...tags],
  };
}

function browserWebSocketInterceptMessage(status: WebSocketInterceptStatus) {
  if (status.clientEnabled && status.serverEnabled) return 'Browser preview WebSocket frame held for client and server intercept.';
  if (status.clientEnabled) return 'Browser preview WebSocket client frame held for intercept.';
  if (status.serverEnabled) return 'Browser preview WebSocket server frame held for intercept.';
  return 'Browser preview WebSocket intercept enabled with no frame directions selected.';
}

function mergeBrowserAiProviders(configs: AiProviderConfig[]): AiProviderRuntime[] {
  return defaultAiProviders.map((fallback) => {
    const saved = configs.find((config) => config.id === fallback.id);
    return {
      ...fallback,
      ...saved,
      available: false,
      secretPresent: true,
      status: saved?.enabled === false ? 'offline' : 'offline',
      message: 'Browser preview stores settings but cannot launch local providers.',
    };
  });
}

function buildBrowserAiFallback(request: AiRunRequest) {
  const highRisk = request.context.issues.filter((issue) => ['critical', 'high'].includes(issue.severity));
  const authz = request.context.exchanges.filter((exchange) => exchange.tags.includes('authz') || exchange.status === 403);
  const selected = request.context.exchanges[0];

  return [
    `Provider: ${request.providerId}`,
    `Task: ${request.task}`,
    `Scope: ${request.context.scopeAllowlist.join(', ')}`,
    `Evidence: ${request.context.exchanges.length} exchanges, ${request.context.issues.length} issues`,
    '',
    'Suggested plan:',
    highRisk.length > 0 ? `- Start with ${highRisk[0].title} on ${highRisk[0].host}${highRisk[0].path}.` : '- No critical/high issue is in the current context bundle.',
    authz.length > 0 ? `- Build an authorization replay matrix from ${authz[0].method} ${authz[0].path}.` : '- Capture an allowed and denied identity pair before active validation.',
    selected ? `- Anchor evidence on ${selected.method} ${selected.host}${selected.path} and keep request/response pairs attached.` : '- Select traffic before asking for report-ready output.',
    '- Keep probes scoped, throttled, and approval-gated before exploit validation.',
  ].join('\n');
}

function estimateBrowserTokens(value: string) {
  return Math.max(1, Math.ceil(value.length / 4));
}

function buildBrowserAiSuggestedActions(request: AiRunRequest): NonNullable<AiRunResult['suggestedActions']> {
  const selected = request.context.exchanges[0];
  const target = selected ? `${selected.method} ${selected.host}${selected.path}` : request.context.projectName;
  const issue = request.context.issues.find((candidate) => ['critical', 'high'].includes(candidate.severity)) ?? request.context.issues[0];
  const authzCandidate = Boolean(selected && (selected.tags.includes('authz') || selected.status === 403 || /permission|role|admin/i.test(`${selected.notes} ${selected.responseRaw}`)));
  const graphqlCandidate = Boolean(selected && /graphql/i.test(`${selected.path} ${selected.requestRaw}`));
  const actions: NonNullable<AiRunResult['suggestedActions']> = [];

  if (selected) {
    actions.push({
      id: 'ai-action-stage-repeater',
      kind: 'stage-repeater',
      label: 'Stage in Repeater',
      detail: 'Load the selected evidence into Repeater for scoped validation.',
      target,
      priority: selected.risk as NonNullable<AiRunResult['suggestedActions']>[number]['priority'],
    });
  }

  if (authzCandidate || request.task === 'replay-plan') {
    actions.push({
      id: 'ai-action-replay-matrix',
      kind: 'stage-replay-matrix',
      label: 'Stage replay matrix',
      detail: 'Prepare an identity comparison matrix without sending traffic automatically.',
      target,
      priority: 'high',
    });
  }

  if (selected && request.task !== 'report-draft') {
    actions.push({
      id: 'ai-action-active-scan',
      kind: 'queue-active-scan',
      label: 'Queue active scan',
      detail: 'Move selected evidence to the scanner audit queue for throttled probes.',
      target,
      priority: selected.risk as NonNullable<AiRunResult['suggestedActions']>[number]['priority'],
    });
  }

  if (request.task === 'exploit-review' || authzCandidate || graphqlCandidate || issue) {
    actions.push({
      id: 'ai-action-exploit-review',
      kind: 'open-exploit-review',
      label: 'Open exploit review',
      detail: 'Open the closest non-destructive Exploit Lab template with approval gates visible.',
      target: issue ? `${issue.host}${issue.path}` : target,
      priority: (issue?.severity ?? 'medium') as NonNullable<AiRunResult['suggestedActions']>[number]['priority'],
    });
  }

  actions.push({
    id: 'ai-action-automation',
    kind: 'record-automation',
    label: 'Record automation',
    detail: 'Capture this request as a scoped macro workflow.',
    target,
    priority: 'low',
  });

  actions.push({
    id: 'ai-action-report',
    kind: 'draft-report',
    label: 'Draft report',
    detail: 'Open report drafting with current findings and evidence in context.',
    target: request.context.projectName,
    priority: (issue?.severity ?? 'info') as NonNullable<AiRunResult['suggestedActions']>[number]['priority'],
  });

  return actions.slice(0, 6);
}

function buildBrowserPromptEvaluation(request: AiRunRequest): NonNullable<AiRunResult['promptEvaluation']> {
  const prompt = request.prompt || request.context.taskHint;
  const providerId = request.providerId;
  const scopeReady = /scope|authorized|allowlist|engagement/i.test(prompt);
  const evidenceReady = /evidence|request|response|finding|issue/i.test(prompt);
  const safetyReady = /safe|non-destructive|approval|rate|throttle|stop/i.test(prompt);
  const providerReady = providerId === 'local'
    ? prompt.length < 2400
    : providerId === 'codex'
      ? /file|command|test|diff|implement|verify/i.test(prompt)
      : /section|bullet|assumption|xml/i.test(prompt);
  const checks: NonNullable<AiRunResult['promptEvaluation']>['checks'] = [
    {
      label: 'Scope boundary',
      status: scopeReady ? 'ready' : 'warning',
      detail: scopeReady ? 'Prompt references authorization or scope.' : 'Add explicit authorization and scope boundaries.',
    },
    {
      label: 'Evidence request',
      status: evidenceReady ? 'ready' : 'warning',
      detail: evidenceReady ? 'Prompt asks for evidence-linked reasoning.' : 'Ask for request, response, or finding references.',
    },
    {
      label: 'Safety gates',
      status: safetyReady ? 'ready' : 'warning',
      detail: safetyReady ? 'Prompt includes safety language.' : 'Add stop conditions or approval-gate language.',
    },
    {
      label: providerId === 'codex' ? 'Codex execution shape' : providerId === 'claude' ? 'Claude structure' : 'Local model brevity',
      status: providerReady ? 'ready' : 'warning',
      detail: providerReady
        ? providerId === 'codex'
          ? 'Prompt gives Codex implementation or verification shape.'
          : providerId === 'claude'
            ? 'Prompt gives Claude structure or assumption handling.'
            : 'Prompt is compact enough for local preview.'
        : providerId === 'codex'
          ? 'Codex prompts work better with files, commands, or verification gates.'
          : providerId === 'claude'
            ? 'Claude prompts work better with sections and explicit assumptions.'
            : 'Shorten local-model prompts or reduce context.',
    },
  ];
  const ready = checks.filter((check) => check.status === 'ready').length;
  return {
    score: Math.round((ready / checks.length) * 100),
    providerId,
    model: providerId === 'local' ? 'local-security-model' : 'configured-default',
    checks,
    recommendations: checks.filter((check) => check.status !== 'ready').map((check) => check.detail),
  };
}

function browserReportExchangeMatchesIssue(exchange: ReportExportRequest['exchanges'][number], issue: ReportExportRequest['issues'][number]) {
  if (exchange.host !== issue.host) return false;
  if (exchange.path === issue.path) return true;
  if (exchange.url.includes(issue.path)) return true;
  return issue.path !== '/' && exchange.path.startsWith(issue.path);
}

function browserReportRemediationPriority(severity: ReportExportRequest['issues'][number]['severity']) {
  if (severity === 'critical') return 'P0 - immediate containment';
  if (severity === 'high') return 'P1 - next release';
  if (severity === 'medium') return 'P2 - planned fix';
  if (severity === 'low') return 'P3 - backlog';
  return 'P4 - informational';
}

function browserReportRemediationValidation(issue: ReportExportRequest['issues'][number], evidenceCount: number) {
  if (issue.status === 'fixed') return 'Attach fixed-state replay evidence and close after owner signoff.';
  if (issue.status === 'false-positive') return 'Retain reviewer rationale and exclude from retest queue.';
  if (evidenceCount > 0) return 'Replay linked evidence after the fix and compare response/status deltas.';
  return 'Add at least one scoped request/response proof before retest.';
}

function buildBrowserReportRemediationPlan(request: ReportExportRequest) {
  return request.issues.map((issue) => {
    const evidenceCount = request.exchanges.filter((exchange) => browserReportExchangeMatchesIssue(exchange, issue)).length;
    return {
      id: issue.id,
      finding: issue.title,
      severity: issue.severity,
      priority: browserReportRemediationPriority(issue.severity),
      owner: issue.assignee?.trim() || 'Unassigned',
      status: issue.status,
      host: issue.host,
      path: issue.path,
      evidenceCount,
      validation: browserReportRemediationValidation(issue, evidenceCount),
      triageNote: issue.triageNote?.trim() || '',
      lastTriagedAt: issue.lastTriagedAt ?? '',
    };
  });
}

function browserMarkdownCell(value: string) {
  return value.replace(/\|/g, '\\|').replace(/\r?\n/g, ' ').trim();
}

function renderBrowserRemediationMarkdown(request: ReportExportRequest) {
  return [
    '## Remediation Plan',
    '',
    '| Priority | Finding | Owner | Status | Evidence | Validation |',
    '| --- | --- | --- | --- | ---: | --- |',
    ...buildBrowserReportRemediationPlan(request).map((item) => (
      `| ${item.priority} | ${browserMarkdownCell(item.finding)} | ${browserMarkdownCell(item.owner)} | ${browserMarkdownCell(item.status)} | ${item.evidenceCount} | ${browserMarkdownCell(item.validation)} |`
    )),
  ].join('\n');
}

function renderBrowserLoggerImportJobsMarkdown(request: ReportExportRequest) {
  const jobs = request.loggerImportJobs ?? [];
  if (!jobs.length) return '';
  return [
    '### Logger Import Jobs',
    '',
    '| Imported | Mapping | Hosts | Adds | Variants | Duplicates | Replays | Notes |',
    '| --- | --- | --- | ---: | ---: | ---: | ---: | --- |',
    ...jobs.map((job) => (
      `| ${browserMarkdownCell(job.importedAt)} | ${browserMarkdownCell(job.mappingPresetName)} | ${browserMarkdownCell(job.sourceHosts.join(', ') || 'none')} | ${job.addedEntries} | ${job.changedEntries} | ${job.duplicateEntries} | ${job.replayCount} | ${browserMarkdownCell(job.notes || 'No reviewer notes')} |`
    )),
  ].join('\n');
}

function renderBrowserComparerDiffPackagesMarkdown(request: ReportExportRequest) {
  const packages = (request.comparerDiffPackages ?? []).filter((item) => item.reportReady);
  if (!packages.length) return '';
  return [
    '### Comparer Diff Packages',
    '',
    '| Package | Similarity | Changes | Summary |',
    '| --- | ---: | ---: | --- |',
    ...packages.map((item) => (
      `| ${browserMarkdownCell(item.fileName)} | ${Math.round(item.similarity * 100)}% | ${item.changed + item.added + item.removed} | ${browserMarkdownCell(item.summary)} |`
    )),
  ].join('\n');
}

function renderBrowserComparerEvidenceAttachmentsMarkdown(request: ReportExportRequest) {
  const attachments = (request.comparerEvidenceAttachments ?? []).filter((item) => item.reportReady);
  if (!attachments.length) return '';
  return [
    '### Comparer Advanced Evidence',
    '',
    '| Attachment | Linked Issue | Summary |',
    '| --- | --- | --- |',
    ...attachments.map((item) => (
      `| ${browserMarkdownCell(item.fileName)} | ${browserMarkdownCell(item.issueId ?? 'pending')} | ${browserMarkdownCell(item.summary)} |`
    )),
  ].join('\n');
}

function renderBrowserTargetSiteMapEvidenceMarkdown(request: ReportExportRequest) {
  const attachments = (request.targetSiteMapEvidenceAttachments ?? []).filter((item) => item.reportReady);
  if (!attachments.length) return '';
  return [
    '### Target Site Map Evidence',
    '',
    '| Attachment | Linked Issue | Summary |',
    '| --- | --- | --- |',
    ...attachments.map((item) => (
      `| ${browserMarkdownCell(item.fileName)} | ${browserMarkdownCell(item.issueId ?? 'pending')} | ${browserMarkdownCell(item.summary)} |`
    )),
  ].join('\n');
}

function renderBrowserProxyHistoryEvidenceMarkdown(request: ReportExportRequest) {
  const attachments = (request.proxyHistoryEvidenceAttachments ?? []).filter((item) => item.reportReady);
  if (!attachments.length) return '';
  return [
    '### Proxy History Evidence',
    '',
    '| Attachment | Linked Issue | Summary |',
    '| --- | --- | --- |',
    ...attachments.map((item) => (
      `| ${browserMarkdownCell(item.fileName)} | ${browserMarkdownCell(item.issueId ?? 'pending')} | ${browserMarkdownCell(item.summary)} |`
    )),
  ].join('\n');
}

function renderBrowserScannerActiveScanEvidencePackagesMarkdown(request: ReportExportRequest) {
  const packages = (request.scannerActiveScanEvidencePackages ?? []).filter((item) => item.reportReady);
  if (!packages.length) return '';
  return [
    '### Scanner Active Scan Evidence Packages',
    '',
    '| Package | Plan | Findings | Exchanges | CI Handoff | Summary |',
    '| --- | --- | ---: | ---: | --- | --- |',
    ...packages.map((item) => (
      `| ${browserMarkdownCell(item.fileName)} | ${browserMarkdownCell(item.planId)} | ${item.findingCount} | ${item.exchangeIds.length} | ${browserMarkdownCell(item.ciCommand || 'not captured')} | ${browserMarkdownCell(item.summary)} |`
    )),
    '',
    ...packages.map((item) => [
      `#### ${item.title}`,
      '',
      item.summary,
      '',
      '```json',
      item.content.trim() || '{}',
      '```',
    ].join('\n')),
  ].join('\n');
}

function renderBrowserReport(request: ReportExportRequest, generatedAt: Date): string {
  const templateId = request.templateId ?? (request.format === 'bundle' ? 'evidence-bundle' : 'technical-remediation');
  const brandName = request.brandName?.trim() || 'ProxyForge';
  const preparedFor = request.preparedFor?.trim() || 'Authorized Security Team';
  const engagementId = request.engagementId?.trim() || `PF-${generatedAt.getFullYear()}`;
  const customTemplateName = request.customTemplateName?.trim() || 'Custom operator template';
  const customTemplateBody = request.customTemplateBody?.trim() || defaultCustomReportTemplate;
  const templateName = browserTemplateLabel(templateId, customTemplateName);
  const sections: ReportExportRequest['sections'] = request.sections.length ? request.sections : ['executive', 'technical', 'remediation', 'evidence'];
  const governanceAttestation = browserReportGovernanceAttestation(request);
  const summary = {
    totalIssues: request.issues.length,
    highOrCritical: request.issues.filter((issue) => ['high', 'critical'].includes(issue.severity)).length,
    affectedHosts: Array.from(new Set(request.issues.map((issue) => issue.host))).length,
    evidenceItems: request.exchanges.length,
    loggerImportJobs: request.loggerImportJobs?.length ?? 0,
    comparerDiffPackages: (request.comparerDiffPackages ?? []).filter((item) => item.reportReady).length,
    comparerEvidenceAttachments: (request.comparerEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    targetSiteMapEvidence: (request.targetSiteMapEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    proxyHistoryEvidence: (request.proxyHistoryEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    scannerActiveScanEvidencePackages: (request.scannerActiveScanEvidencePackages ?? []).filter((item) => item.reportReady).length,
  };

  if (request.format === 'json') {
    return JSON.stringify({
      version: 1,
      generatedAt: generatedAt.toISOString(),
      projectName: request.projectName,
      brandName,
      preparedFor,
      engagementId,
      templateId,
      templateName,
      scopeAllowlist: request.scopeAllowlist,
      sections,
      governanceAttestation,
      summary,
      issues: request.issues,
      remediationPlan: sections.includes('remediation') ? buildBrowserReportRemediationPlan(request) : [],
      exchanges: sections.includes('evidence') ? request.exchanges.map(redactReportExchange) : [],
      loggerImportJobs: sections.includes('evidence') ? request.loggerImportJobs ?? [] : [],
      comparerDiffPackages: sections.includes('evidence') ? (request.comparerDiffPackages ?? []).filter((item) => item.reportReady) : [],
      comparerEvidenceAttachments: sections.includes('evidence') ? (request.comparerEvidenceAttachments ?? []).filter((item) => item.reportReady) : [],
      targetSiteMapEvidenceAttachments: sections.includes('evidence') ? (request.targetSiteMapEvidenceAttachments ?? []).filter((item) => item.reportReady) : [],
      proxyHistoryEvidenceAttachments: sections.includes('evidence') ? (request.proxyHistoryEvidenceAttachments ?? []).filter((item) => item.reportReady) : [],
      scannerActiveScanEvidencePackages: sections.includes('evidence') ? (request.scannerActiveScanEvidencePackages ?? []).filter((item) => item.reportReady) : [],
    }, null, 2);
  }

  if (request.format === 'bundle') {
    const evidence = request.exchanges.map(redactReportExchange);
    const bundle: Record<string, unknown> = {
      manifest: {
        version: 1,
        kind: 'proxyforge-evidence-bundle',
        generatedAt: generatedAt.toISOString(),
        projectName: request.projectName,
        brandName,
        preparedFor,
        engagementId,
        templateId,
        templateName,
        sections,
        scopeAllowlist: request.scopeAllowlist,
        summary,
        redactionPolicy: ['authorization bearer', 'cookie', 'session', 'api key'],
        governanceAttestation,
      },
      governanceAttestation,
      findings: request.issues.map((issue) => ({
        id: issue.id,
        title: issue.title,
        severity: issue.severity,
        host: issue.host,
        path: issue.path,
        confidence: issue.confidence,
        status: issue.status,
        remediation: issue.remediation,
        evidenceIds: evidence
          .filter((exchange) => exchange.host === issue.host || exchange.path === issue.path)
          .slice(0, 5)
          .map((exchange) => exchange.id),
      })),
      evidence: evidence.map((exchange) => ({
        id: exchange.id,
        request: {
          method: exchange.method,
          url: exchange.url,
          raw: exchange.requestRaw,
        },
        response: {
          status: exchange.status,
          mime: exchange.mime,
          length: exchange.length,
          raw: exchange.responseRaw,
        },
        metadata: {
          host: exchange.host,
          path: exchange.path,
          risk: exchange.risk,
          source: exchange.source,
          tags: exchange.tags,
          notes: exchange.notes,
        },
      })),
      remediationPlan: sections.includes('remediation') ? buildBrowserReportRemediationPlan(request) : [],
      loggerImportJobs: sections.includes('evidence') ? request.loggerImportJobs ?? [] : [],
      comparerDiffPackages: sections.includes('evidence') ? (request.comparerDiffPackages ?? []).filter((item) => item.reportReady) : [],
      comparerEvidenceAttachments: sections.includes('evidence') ? (request.comparerEvidenceAttachments ?? []).filter((item) => item.reportReady) : [],
      targetSiteMapEvidenceAttachments: sections.includes('evidence') ? (request.targetSiteMapEvidenceAttachments ?? []).filter((item) => item.reportReady) : [],
      proxyHistoryEvidenceAttachments: sections.includes('evidence') ? (request.proxyHistoryEvidenceAttachments ?? []).filter((item) => item.reportReady) : [],
      scannerActiveScanEvidencePackages: sections.includes('evidence') ? (request.scannerActiveScanEvidencePackages ?? []).filter((item) => item.reportReady) : [],
      reportMarkdown: renderBrowserReport({ ...request, format: 'markdown', templateId, brandName, preparedFor, engagementId, customTemplateName, customTemplateBody }, generatedAt),
    };
    if (request.signEvidenceBundle) {
      bundle.signature = previewBrowserEvidenceBundleSignature(bundle, request, generatedAt);
    }
    return JSON.stringify(bundle, null, 2);
  }

  if (request.format === 'pdf') {
    return [
      'PDF report package',
      '',
      `Project: ${request.projectName}`,
      `Prepared for: ${preparedFor}`,
      `Brand: ${brandName}`,
      `Engagement: ${engagementId}`,
      `Template: ${templateName}`,
      `Generated: ${generatedAt.toISOString()}`,
      `Sections: ${sections.join(', ')}`,
      '',
      `Findings: ${summary.totalIssues}`,
      `High/Critical: ${summary.highOrCritical}`,
      `Remediation items: ${sections.includes('remediation') ? request.issues.length : 0}`,
      `Evidence items: ${summary.evidenceItems}`,
      `Logger import jobs: ${summary.loggerImportJobs}`,
      `Comparer diff packages: ${summary.comparerDiffPackages}`,
      `Comparer advanced evidence: ${summary.comparerEvidenceAttachments}`,
      `Target site-map evidence: ${summary.targetSiteMapEvidence}`,
      `Proxy history evidence: ${summary.proxyHistoryEvidence}`,
      `Scanner active scan evidence packages: ${summary.scannerActiveScanEvidencePackages}`,
      `Governance attestation: ${governanceAttestation.status} ${governanceAttestation.signature.digestPreview}`,
      '',
      'Browser preview shows this PDF manifest. Desktop exports render a real paginated PDF through Electron printToPDF with redacted evidence.',
    ].join('\n');
  }

  if (templateId === 'custom') {
    const markdown = renderCustomBrowserReportTemplate({
      ...request,
      brandName,
      preparedFor,
      engagementId,
      customTemplateName,
      customTemplateBody,
      sections,
    }, generatedAt);
    if (request.format === 'html') {
      return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeBrowserHtml(request.projectName)}</title><style>body{font-family:Inter,system-ui,sans-serif;margin:40px;line-height:1.5;color:#17211b}.brand{padding:14px 18px;background:#f4f1ec;border-left:5px solid #ff9b3e;margin-bottom:22px}</style></head><body><div class="brand"><strong>${escapeBrowserHtml(brandName)}</strong><br>${escapeBrowserHtml(preparedFor)} · ${escapeBrowserHtml(engagementId)}</div><pre>${escapeBrowserHtml(markdown)}</pre></body></html>\n`;
    }
    return markdown;
  }

  const lines = [
    `# ${request.projectName} Security Assessment`,
    '',
    `Prepared for: ${preparedFor}`,
    `Brand: ${brandName}`,
    `Engagement: ${engagementId}`,
    `Template: ${templateName}`,
    `Generated: ${generatedAt.toISOString()}`,
    `Governance: ${governanceAttestation.status} ${governanceAttestation.teamName} ${governanceAttestation.signature.digestPreview}`,
    `Scope: ${request.scopeAllowlist.join(', ')}`,
    '',
  ];

  if (sections.includes('executive')) {
    lines.push('## Executive Summary', '');
    lines.push(`${brandName} identified ${request.issues.length} issues from ${request.exchanges.length} evidence items.`);
    if (templateId === 'executive-board') {
      lines.push('', 'Board Focus:');
      lines.push(`- Exposure: ${summary.affectedHosts} affected host(s) in authorized scope.`);
      lines.push(`- Priority: ${summary.highOrCritical} high-or-critical item(s) need owner review.`);
      lines.push(`- Evidence: ${summary.evidenceItems} redacted request/response artifact(s) retained for audit.`);
    }
    lines.push('');
  }

  if (sections.includes('technical')) {
    lines.push('## Technical Findings', '');
    for (const issue of request.issues) {
      lines.push(`### ${issue.severity.toUpperCase()}: ${issue.title}`, '');
      lines.push(`Host: ${issue.host}`);
      lines.push(`Path: ${issue.path}`);
      lines.push(`Confidence: ${issue.confidence}`, '');
      lines.push(issue.detail, '');
      lines.push(`Remediation: ${issue.remediation}`, '');
      if (templateId === 'technical-remediation') {
        lines.push('Validation plan:', 'Replay the linked evidence under authorization, compare status/body deltas, and attach remediation proof before closure.', '');
      }
    }
  }

  if (sections.includes('remediation')) {
    lines.push(renderBrowserRemediationMarkdown({ ...request, sections }), '');
  }

  if (sections.includes('evidence')) {
    lines.push('## Evidence', '');
    lines.push(...request.exchanges.slice(0, 20).map((exchange) => `- ${exchange.method} ${exchange.host}${exchange.path} ${exchange.status} ${exchange.notes}`));
    const loggerImportJobsMarkdown = renderBrowserLoggerImportJobsMarkdown(request);
    if (loggerImportJobsMarkdown) lines.push('', loggerImportJobsMarkdown);
    const comparerPackagesMarkdown = renderBrowserComparerDiffPackagesMarkdown(request);
    if (comparerPackagesMarkdown) lines.push('', comparerPackagesMarkdown);
    const comparerEvidenceMarkdown = renderBrowserComparerEvidenceAttachmentsMarkdown(request);
    if (comparerEvidenceMarkdown) lines.push('', comparerEvidenceMarkdown);
    const targetSiteMapEvidenceMarkdown = renderBrowserTargetSiteMapEvidenceMarkdown(request);
    if (targetSiteMapEvidenceMarkdown) lines.push('', targetSiteMapEvidenceMarkdown);
    const proxyHistoryEvidenceMarkdown = renderBrowserProxyHistoryEvidenceMarkdown(request);
    if (proxyHistoryEvidenceMarkdown) lines.push('', proxyHistoryEvidenceMarkdown);
    const scannerActiveScanEvidenceMarkdown = renderBrowserScannerActiveScanEvidencePackagesMarkdown(request);
    if (scannerActiveScanEvidenceMarkdown) lines.push('', scannerActiveScanEvidenceMarkdown);
    lines.push('');
  }

  if (sections.includes('appendix')) {
    lines.push('## Appendix', '');
    lines.push(`- Generated by ${brandName}`);
    lines.push(`- Prepared for ${preparedFor}`);
    lines.push(`- Engagement ID: ${engagementId}`);
    lines.push('- Active traffic remains gated to project scope.');
  }
  const markdown = `${lines.join('\n')}\n`;
  if (request.format === 'html') {
    return `<!doctype html><html><head><meta charset="utf-8"><title>${request.projectName}</title><style>body{font-family:Inter,system-ui,sans-serif;margin:40px;line-height:1.5;color:#17211b}.brand{padding:14px 18px;background:#f4f1ec;border-left:5px solid #ff9b3e;margin-bottom:22px}</style></head><body><div class="brand"><strong>${escapeBrowserHtml(brandName)}</strong><br>${escapeBrowserHtml(preparedFor)} · ${escapeBrowserHtml(engagementId)}</div><pre>${escapeBrowserHtml(markdown)}</pre></body></html>\n`;
  }
  return markdown;
}

function renderCustomBrowserReportTemplate(request: ReportExportRequest, generatedAt: Date) {
  const sections: ReportExportRequest['sections'] = request.sections.length ? request.sections : ['executive', 'technical', 'remediation', 'evidence', 'appendix'];
  const brandName = request.brandName?.trim() || 'ProxyForge';
  const preparedFor = request.preparedFor?.trim() || 'Authorized Security Team';
  const engagementId = request.engagementId?.trim() || `PF-${generatedAt.getFullYear()}`;
  const summary = {
    totalIssues: request.issues.length,
    openIssues: request.issues.filter((issue) => issue.status === 'open').length,
    highOrCritical: request.issues.filter((issue) => ['high', 'critical'].includes(issue.severity)).length,
    affectedHosts: Array.from(new Set(request.issues.map((issue) => issue.host))).length,
    evidenceItems: request.exchanges.length,
    loggerImportJobs: request.loggerImportJobs?.length ?? 0,
    comparerDiffPackages: (request.comparerDiffPackages ?? []).filter((item) => item.reportReady).length,
    comparerEvidenceAttachments: (request.comparerEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    targetSiteMapEvidence: (request.targetSiteMapEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    proxyHistoryEvidence: (request.proxyHistoryEvidenceAttachments ?? []).filter((item) => item.reportReady).length,
    scannerActiveScanEvidencePackages: (request.scannerActiveScanEvidencePackages ?? []).filter((item) => item.reportReady).length,
  };
  const replacements: Record<string, string | number> = {
    projectName: request.projectName,
    brandName,
    preparedFor,
    engagementId,
    generatedAt: generatedAt.toISOString(),
    scope: request.scopeAllowlist.join(', ') || 'Not specified',
    sections: sections.join(', '),
    templateName: request.customTemplateName?.trim() || 'Custom operator template',
    'summary.totalIssues': summary.totalIssues,
    'summary.openIssues': summary.openIssues,
    'summary.highOrCritical': summary.highOrCritical,
    'summary.affectedHosts': summary.affectedHosts,
    'summary.evidenceItems': summary.evidenceItems,
    'summary.loggerImportJobs': summary.loggerImportJobs,
    'summary.comparerDiffPackages': summary.comparerDiffPackages,
    'summary.comparerEvidenceAttachments': summary.comparerEvidenceAttachments,
    'summary.targetSiteMapEvidence': summary.targetSiteMapEvidence,
    'summary.proxyHistoryEvidence': summary.proxyHistoryEvidence,
    'summary.scannerActiveScanEvidencePackages': summary.scannerActiveScanEvidencePackages,
    executiveMarkdown: sections.includes('executive')
      ? [
          '## Executive Summary',
          '',
          `${brandName} identified ${summary.totalIssues} issue(s) from ${summary.evidenceItems} evidence item(s) across ${summary.affectedHosts} host(s).`,
          `${summary.highOrCritical} issue(s) are high or critical priority.`,
        ].join('\n')
      : '',
    findingsMarkdown: sections.includes('technical')
      ? [
          '## Technical Findings',
          '',
          ...request.issues.map((issue) => [
            `### ${issue.severity.toUpperCase()}: ${issue.title}`,
            '',
            `- Host: ${issue.host}`,
            `- Path: ${issue.path}`,
            `- Confidence: ${issue.confidence}`,
            `- Status: ${issue.status}`,
            '',
            issue.detail,
            '',
            `Remediation: ${issue.remediation}`,
          ].join('\n')),
        ].join('\n\n').trim()
      : '',
    remediationMarkdown: sections.includes('remediation') ? renderBrowserRemediationMarkdown({ ...request, sections }) : '',
    evidenceMarkdown: sections.includes('evidence')
      ? [
          '## Evidence',
          '',
          ...request.exchanges.slice(0, 50).map((exchange) => `- ${exchange.method} ${exchange.host}${exchange.path} ${exchange.status} ${exchange.source} ${exchange.notes}`),
          '',
          renderBrowserLoggerImportJobsMarkdown(request),
          '',
          renderBrowserTargetSiteMapEvidenceMarkdown(request),
          '',
          renderBrowserProxyHistoryEvidenceMarkdown(request),
          '',
          renderBrowserScannerActiveScanEvidencePackagesMarkdown(request),
        ].join('\n').trim()
      : '',
    loggerImportJobsMarkdown: renderBrowserLoggerImportJobsMarkdown(request),
    comparerDiffPackagesMarkdown: renderBrowserComparerDiffPackagesMarkdown(request),
    comparerEvidenceMarkdown: renderBrowserComparerEvidenceAttachmentsMarkdown(request),
    targetSiteMapEvidenceMarkdown: renderBrowserTargetSiteMapEvidenceMarkdown(request),
    proxyHistoryEvidenceMarkdown: renderBrowserProxyHistoryEvidenceMarkdown(request),
    scannerActiveScanEvidencePackagesMarkdown: renderBrowserScannerActiveScanEvidencePackagesMarkdown(request),
    appendixMarkdown: sections.includes('appendix')
      ? [
          '## Appendix',
          '',
          `- Generated by ${brandName}`,
          `- Prepared for ${preparedFor}`,
          `- Engagement ID: ${engagementId}`,
          `- Generated at ${generatedAt.toISOString()}`,
          '- Active traffic remains gated to project scope.',
        ].join('\n')
      : '',
  };

  return `${(request.customTemplateBody?.trim() || defaultCustomReportTemplate).replace(/{{\s*([a-zA-Z0-9_.]+)\s*}}/g, (_match, key: string) => String(replacements[key] ?? ''))}\n`;
}

function reportExtension(format: ReportExportRequest['format']) {
  if (format === 'markdown') return 'md';
  if (format === 'bundle') return 'evidence-bundle.json';
  if (format === 'pdf') return 'pdf';
  return format;
}

function browserTemplateLabel(templateId: ReportExportRequest['templateId'], customTemplateName?: string) {
  if (templateId === 'custom') return customTemplateName?.trim() || 'Custom operator template';
  return {
    'executive-board': 'Executive board brief',
    'technical-remediation': 'Technical remediation plan',
    'evidence-bundle': 'Branded evidence bundle',
  }[templateId ?? 'technical-remediation'];
}

function redactReportExchange(exchange: ReportExportRequest['exchanges'][number]) {
  return {
    ...exchange,
    requestRaw: redactReportSecrets(exchange.requestRaw),
    responseRaw: redactReportSecrets(exchange.responseRaw),
  };
}

function redactReportSecrets(value: string) {
  return value
    .replace(/(authorization:\s*)[^\n]+/gi, '$1[redacted]')
    .replace(/(proxy-authorization:\s*)[^\n]+/gi, '$1[redacted]')
    .replace(/(cookie:\s*)[^\n]+/gi, '$1[redacted]')
    .replace(/(set-cookie:\s*)[^\n]+/gi, '$1[redacted]')
    .replace(/((?:x-api-key|api-key|x-auth-token|x-session-token):\s*)[^\n]+/gi, '$1[redacted]')
    .replace(/((?:access_token|refresh_token|session|token|secret|password|api[_-]?key)=)[^;&\s]+/gi, '$1[redacted]')
    .replace(/(api[_-]?key["']?\s*[:=]\s*["']?)[^"',\s]+/gi, '$1[redacted]')
    .replace(/\b[A-Za-z0-9][A-Za-z0-9._-]*(?:[_-](?:token|secret|session|api[_-]?key))[A-Za-z0-9._-]*\b/g, '[redacted]');
}

function escapeBrowserHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function browserReportGovernanceAttestation(request: ReportExportRequest): NonNullable<ReportExportRequest['governanceAttestation']> {
  if (request.governanceAttestation) return request.governanceAttestation;
  return {
    packageId: 'no-active-governance-package',
    title: 'No active governance policy package',
    teamName: 'Local project policy',
    activeOperator: 'unassigned',
    operatorRole: 'operator',
    status: 'missing',
    signature: {
      algorithm: 'HMAC-SHA256',
      signerName: 'ProxyForge Governance',
      keyId: 'missing-governance-key',
      status: 'missing',
      digestPreview: 'missing',
    },
    runnerBindingCount: 0,
    approvalRequiredCount: 0,
    scopeGateSummary: `Report scope ${request.scopeAllowlist.join(', ') || 'not specified'} has no active governance package attestation.`,
    rateGateSummary: 'No active governance rate gate attested for this export.',
    approvalGateSummary: 'No active governance approval gate attested for this export.',
    ciHeadlessSummary: 'No active CI/headless governance binding attested for this export.',
  };
}

async function signBrowserEvidenceBundle(bundle: Record<string, unknown>, request: ReportExportRequest, generatedAt: Date) {
  const canonical = canonicalizeBrowserBundle(bundle);
  const encoder = new TextEncoder();
  const digest = await browserSha256Hex(canonical);
  const secret = request.signingSecret?.trim();
  if (!secret || !globalThis.crypto?.subtle) {
    return {
      ...previewBrowserEvidenceBundleSignature(bundle, request, generatedAt),
      bundleDigestSha256: digest,
      status: secret ? 'preview-signed' : 'missing-secret',
    };
  }
  const key = await globalThis.crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const signature = await globalThis.crypto.subtle.sign('HMAC', key, encoder.encode(canonical));
  return {
    version: 1,
    algorithm: 'HMAC-SHA256',
    canonicalization: 'proxyforge-evidence-bundle-v1',
    signedAt: generatedAt.toISOString(),
    signerName: request.signerName?.trim() || request.brandName?.trim() || 'ProxyForge',
    keyId: request.signingKeyId?.trim() || 'proxyforge-local',
    bundleDigestSha256: digest,
    signature: bufferToHex(signature),
    status: 'signed',
    covers: ['manifest', 'governanceAttestation', 'findings', 'evidence', 'loggerImportJobs', 'comparerDiffPackages', 'comparerEvidenceAttachments', 'targetSiteMapEvidenceAttachments', 'proxyHistoryEvidenceAttachments', 'scannerActiveScanEvidencePackages', 'remediationPlan', 'reportMarkdown'],
  };
}

function previewBrowserEvidenceBundleSignature(bundle: Record<string, unknown>, request: ReportExportRequest, generatedAt: Date) {
  return {
    version: 1,
    algorithm: 'HMAC-SHA256',
    canonicalization: 'proxyforge-evidence-bundle-v1',
    signedAt: generatedAt.toISOString(),
    signerName: request.signerName?.trim() || request.brandName?.trim() || 'ProxyForge',
    keyId: request.signingKeyId?.trim() || 'proxyforge-local',
    bundleDigestSha256: previewDigest(canonicalizeBrowserBundle(bundle)),
    signature: '[computed on export]',
    status: request.signingSecret?.trim() ? 'ready-on-export' : 'missing-secret',
    covers: ['manifest', 'governanceAttestation', 'findings', 'evidence', 'loggerImportJobs', 'comparerDiffPackages', 'comparerEvidenceAttachments', 'targetSiteMapEvidenceAttachments', 'proxyHistoryEvidenceAttachments', 'scannerActiveScanEvidencePackages', 'remediationPlan', 'reportMarkdown'],
  };
}

async function browserSha256Hex(value: string) {
  if (!globalThis.crypto?.subtle) return previewDigest(value);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return bufferToHex(digest);
}

function bufferToHex(value: ArrayBuffer) {
  return Array.from(new Uint8Array(value)).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function previewDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash.toString(16).padStart(8, '0');
}

function canonicalizeBrowserBundle(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalizeBrowserBundle).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value as Record<string, unknown>).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalizeBrowserBundle((value as Record<string, unknown>)[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function simulateReplay(request: ReplayRequest): HttpExchange {
  const now = new Date();
  const target = new URL(request.targetUrl);
  const settings = request.settings ?? { redirectMode: 'manual', maxRedirects: 3, connectionMode: 'default', timeoutMs: 15000 };
  const oastTags = replayOastPayloadTags(request.rawRequest, request.oastPayloads);
  const identity = request.rawRequest.match(/^X-ProxyForge-Role:\s*([^\r\n]+)/im)?.[1]?.trim() ?? 'current';
  const refundReplay = request.rawRequest.includes('/api/refunds');
  const allowedRefundRole = /support_admin|finance_admin/i.test(identity);
  const status = refundReplay ? allowedRefundRole ? 200 : 403 : 200;
  const body = refundReplay
    ? JSON.stringify({ identity, allowed: allowedRefundRole, required: allowedRefundRole ? null : 'refunds.write' })
    : request.rawRequest.includes('"orderId"')
      ? '{"error":"missing_permission","required":"refunds.write"}'
      : '{"ok":true}';

  return {
    id: `replay-${now.getTime()}`,
    method: request.rawRequest.split(/\s+/)[0] || 'GET',
    host: target.host,
    path: `${target.pathname}${target.search}`,
    url: target.toString(),
    status,
    length: body.length,
    mime: 'application/json',
    risk: status >= 400 ? 'high' : 'info',
    timing: 64,
    notes: `Browser preview replay; redirects ${settings.redirectMode}; connection ${settings.connectionMode}; Electron sends real HTTP requests${oastTags.length ? `; OAST ${oastTags.filter((tag) => tag.startsWith('callback-payload:')).length} payload(s)` : ''}`,
    source: 'repeater',
    time: now.toLocaleTimeString([], { hour12: false }),
    requestRaw: request.rawRequest,
    responseRaw: `HTTP/2 ${status} ${status >= 400 ? 'Forbidden' : 'OK'}\nContent-Type: application/json\nX-ProxyForge-Preview: true\nX-ProxyForge-Redirect-Mode: ${settings.redirectMode}\nX-ProxyForge-Connection-Mode: ${settings.connectionMode}\nX-ProxyForge-Timeout: ${settings.timeoutMs}\n\n${body}`,
    tags: ['replayed', 'preview', `redirect:${settings.redirectMode}`, `connection:${settings.connectionMode}`, ...oastTags],
  };
}

function replayOastPayloadTags(rawRequest: string, payloads: ReplayRequest['oastPayloads'] = []) {
  const tags = new Set<string>();
  for (const payload of payloads ?? []) {
    if (
      rawRequest.includes(payload.id)
      || rawRequest.includes(payload.token)
      || rawRequest.includes(payload.endpoint)
      || rawRequest.includes(encodeURIComponent(payload.endpoint))
    ) {
      tags.add('oast-payload');
      tags.add(`callback-payload:${payload.id}`);
      tags.add(`callback-protocol:${payload.protocol}`);
    }
  }
  return Array.from(tags);
}

function simulateRepeaterDesyncRuntime(
  request: RepeaterDesyncRuntimeRequest,
  transport: RepeaterDesyncRuntimeResult['transport'],
): RepeaterDesyncRuntimeResult {
  const createdAt = new Date().toISOString();
  const syncTechnique = transport === 'single-connection'
    ? 'single-connection'
    : request.syncTechnique === 'single-packet' ? 'single-packet' : 'last-byte';
  const responses = request.requests.map((entry, index) => ({
    requestId: entry.id,
    role: entry.role,
    name: entry.name,
    targetUrl: entry.targetUrl,
    status: 200,
    statusLine: 'HTTP/1.1 200 OK',
    bytes: 128 + index,
    startedAt: createdAt,
    completedAt: createdAt,
    timingMs: 20 + (index * 3),
    headers: {
      'content-type': 'application/json',
      'x-proxyforge-preview': 'true',
    },
    bodyPreview: JSON.stringify({ preview: true, requestId: entry.id, role: entry.role }),
    rawRequest: entry.rawRequest,
    rawResponse: `HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-ProxyForge-Preview: true\r\n\r\n{"preview":true,"requestId":"${entry.id}","role":"${entry.role}"}`,
  }));
  const responseOrder = responses.map((response, index) => `${index + 1}/${responses.length} ${response.role}:${response.name} ${response.status}`);
  const releaseSkewMs = transport === 'single-connection' ? 6 : 2;
  const jitterMs = responses.length > 1 ? responses[responses.length - 1].timingMs - responses[0].timingMs : 0;
  return {
    id: `browser-preview-desync-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    planId: request.planId,
    createdAt,
    targetUrl: request.targetUrl,
    protocol: 'HTTP/1.1',
    transport,
    syncTechnique,
    status: 'proof',
    requestCount: request.requests.length,
    responseOrder,
    jitterMs,
    raceWindowMs: releaseSkewMs,
    releaseSkewMs,
    connectionStrategy: window.proxyForge
      ? 'Electron socket-backed runtime'
      : 'Browser preview simulated transport; Electron uses raw sockets for this workflow.',
    timingNotes: `Preview response order and timing generated for ${request.requests.length} request(s).`,
    responses,
    rawTranscript: responses.map((response) => `>>> ${response.requestId}\n${response.rawRequest}\n<<< ${response.requestId}\n${response.rawResponse}`).join('\n'),
    summary: `${transport} preview proof with ${request.requests.length} request(s), ${releaseSkewMs}ms release window, and ${jitterMs}ms response jitter.`,
  };
}

function simulateIntruderAttack(request: IntruderAttackRequest): IntruderAttackSummary {
  const startedAt = new Date();
  const target = new URL(request.targetUrl);
  const attackMode = sanitizeIntruderAttackMode(request.attackMode);
  const payloadRules = sanitizeIntruderPayloadRules(request.payloadRules);
  const payloadPlans = buildIntruderPayloadPlans(request.rawRequest, { ...request, payloadRules }, attackMode);
  const startOffset = clampIntruderOffset(request.startOffset, payloadPlans.length);
  const maxPayloadRequests = request.maxPayloadRequests === undefined
    ? payloadPlans.length
    : Math.min(Math.max(Math.round(request.maxPayloadRequests), 1), INTRUDER_MAX_PAYLOAD_REQUESTS);
  const selectedPayloadPlans = payloadPlans.slice(startOffset, startOffset + maxPayloadRequests);
  const nextOffset = Math.min(payloadPlans.length, startOffset + selectedPayloadPlans.length);
  const hasMore = nextOffset < payloadPlans.length;
  const payloadPositions = countIntruderMarkers(request.rawRequest);
  const extractRegexes = request.extractRegexes?.map((term) => term.trim()).filter(Boolean).slice(0, 12) ?? [];
  const resourcePoolMaxConcurrent = Math.min(Math.max(Math.round(request.resourcePoolMaxConcurrent ?? 1), 1), 10);
  const resourcePoolName = request.resourcePoolName?.trim() || 'Default sequential pool';
  const streamChunkSize = sanitizeIntruderStreamChunkSize(request.streamChunkSize, selectedPayloadPlans.length);
  const resultWindowSize = sanitizeIntruderResultWindowSize(request.resultWindowSize, selectedPayloadPlans.length);
  const memoryBudgetBytes = sanitizeIntruderMemoryBudgetBytes(request.memoryBudgetBytes);
  const scopeBlocked = !request.scopeAllowlist.some((pattern) => pattern === '*' || target.hostname.endsWith(pattern.replace(/^\*\./, '.')) || target.hostname === pattern);
  const blocked = scopeBlocked || payloadPlans.length === 0;
  const results: IntruderAttackSummary['results'] = [];
  let completedChunks = 0;
  let droppedResultCount = 0;
  let retainedMemoryBytes = 0;
  let sentRequestCount = 0;
  const runStartedAt = Date.now();

  if (!blocked) {
    for (let chunkStart = 0; chunkStart < selectedPayloadPlans.length; chunkStart += Math.max(streamChunkSize, 1)) {
      const chunk = selectedPayloadPlans.slice(chunkStart, chunkStart + Math.max(streamChunkSize, 1));
      for (const [chunkIndex, plan] of chunk.entries()) {
        const index = chunkStart + chunkIndex;
        const status = /admin|support|finance|forbidden/i.test(plan.label) ? 403 : 200 + (index % 3);
        const body = JSON.stringify({ payload: plan.label, payloads: plan.payloads, attackMode, allowed: status < 400, index, required: status >= 400 ? 'refunds.write' : null });
        const responseRaw = `HTTP/2 ${status} ${status >= 400 ? 'Forbidden' : 'OK'}\nContent-Type: application/json\nX-ProxyForge-Intruder-Preview: true\n\n${body}`;
        const haystack = `${plan.rawRequest}\n${body}`.toLowerCase();
        const grepMatches = request.grepTerms.filter((term) => haystack.includes(term.toLowerCase()));
        const extractMatches = extractIntruderMatches(`${responseRaw}\n${plan.rawRequest}`, extractRegexes);
        const result = {
          id: `intruder-preview-${startedAt.getTime()}-${index}`,
          payload: plan.label,
          payloads: plan.payloads,
          attackMode,
          status,
          length: body.length,
          mime: 'application/json',
          timing: 70 + index * 19,
          grepMatches,
          extractMatches,
          notes: `Browser preview Intruder ${attackMode} result; resource pool ${resourcePoolName} (${resourcePoolMaxConcurrent} slot${resourcePoolMaxConcurrent === 1 ? '' : 's'}); payload offset ${startOffset + index + 1}/${payloadPlans.length}`,
          requestRaw: plan.rawRequest,
          responseRaw,
          tags: ['intruder', attackMode, 'preview', `pool:${resourcePoolName}`, ...payloadRules.map((rule) => `payload-rule:${rule}`), grepMatches.length > 0 ? 'grep-match' : 'sample', extractMatches.length > 0 ? 'extract-match' : 'no-extract-match']
            .filter((tag) => tag !== 'no-extract-match'),
        };

        sentRequestCount += 1;
        if (resultWindowSize > 0) {
          results.push(result);
          retainedMemoryBytes += estimateIntruderResultBytes(result);
          while (results.length > resultWindowSize) {
            const removed = results.shift();
            if (!removed) break;
            retainedMemoryBytes = Math.max(0, retainedMemoryBytes - estimateIntruderResultBytes(removed));
            droppedResultCount += 1;
          }
        } else {
          droppedResultCount += 1;
        }
      }
      completedChunks += 1;
    }
  }

  return {
    id: `intruder-preview-${startedAt.getTime()}`,
    targetUrl: target.toString(),
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    attackMode,
    payloadPositions,
    totalRequests: sentRequestCount,
    blocked,
    message: scopeBlocked
      ? `Intruder attack blocked by project scope: ${target.hostname}`
      : payloadPlans.length === 0
        ? 'Intruder attack blocked: no payloads supplied'
        : hasMore
          ? `Intruder ${attackMode} checkpoint paused: ${sentRequestCount} of ${payloadPlans.length} payload request${payloadPlans.length === 1 ? '' : 's'} sent in browser preview; resume at offset ${nextOffset}`
          : `Intruder ${attackMode} complete: ${sentRequestCount} payload request${sentRequestCount === 1 ? '' : 's'} sent in browser preview`,
    results,
    startOffset,
    nextOffset,
    hasMore,
    payloadPlanCount: payloadPlans.length,
    payloadRuleCount: payloadRules.length,
    resourcePoolName,
    resourcePoolMaxConcurrent,
    streaming: buildIntruderStreamingSummary({
      selectedRequestCount: blocked ? 0 : selectedPayloadPlans.length,
      streamChunkSize,
      completedChunks,
      maxConcurrency: resourcePoolMaxConcurrent,
      maxInFlight: blocked ? 0 : Math.min(resourcePoolMaxConcurrent, selectedPayloadPlans.length),
      durationMs: Math.max(1, Date.now() - runStartedAt),
      resultWindowSize,
      retainedResultCount: results.length,
      droppedResultCount,
      startOffset,
      sentRequestCount,
      estimatedMemoryBytes: retainedMemoryBytes,
      memoryBudgetBytes,
    }),
  };
}

interface IntruderPayloadPlan {
  label: string;
  payloads: string[];
  rawRequest: string;
}

function sanitizeIntruderAttackMode(mode?: IntruderAttackMode): IntruderAttackMode {
  return mode && ['sniper', 'battering-ram', 'pitchfork', 'cluster-bomb'].includes(mode) ? mode : 'sniper';
}

function countIntruderMarkers(rawRequest: string) {
  return Array.from(rawRequest.matchAll(/§[^§]*§/g)).length;
}

function sanitizePayloadSet(payloads: string[] | undefined, processors: IntruderPayloadProcessor[]) {
  return (payloads ?? [])
    .map((payload) => payload.trim())
    .filter(Boolean)
    .slice(0, INTRUDER_MAX_PAYLOAD_VALUES)
    .map((payload) => applyIntruderProcessors(payload, processors));
}

function sanitizeIntruderPayloadRules(rules: IntruderPayloadRuleId[] | undefined) {
  const allowed = new Set<IntruderPayloadRuleId>(['case-variants', 'url-recursive', 'path-depth']);
  return Array.from(new Set((rules ?? []).filter((rule) => allowed.has(rule))));
}

function expandIntruderPayloadRules(payloads: string[], rules: IntruderPayloadRuleId[]) {
  if (rules.length === 0) return payloads;
  const values = new Set<string>();
  for (const payload of payloads) {
    values.add(payload);
    if (rules.includes('case-variants')) {
      values.add(payload.toLowerCase());
      values.add(payload.toUpperCase());
      values.add(payload.slice(0, 1).toUpperCase() + payload.slice(1).toLowerCase());
    }
    if (rules.includes('url-recursive')) {
      const encoded = encodeURIComponent(payload);
      values.add(encoded);
      values.add(encodeURIComponent(encoded));
    }
    if (rules.includes('path-depth')) {
      const normalized = payload.replace(/^\/+/, '');
      values.add(`../${normalized}`);
      values.add(`../../${normalized}`);
    }
  }
  return Array.from(values).filter(Boolean).slice(0, INTRUDER_MAX_PAYLOAD_VALUES);
}

function normalizeIntruderPayloadSets(request: IntruderAttackRequest) {
  const processors = request.payloadProcessors ?? [];
  const payloadRules = sanitizeIntruderPayloadRules(request.payloadRules);
  const explicitSets = request.payloadSets?.length ? request.payloadSets : [request.payloads];
  return explicitSets
    .map((payloadSet) => expandIntruderPayloadRules(sanitizePayloadSet(payloadSet, processors), payloadRules))
    .filter((payloadSet) => payloadSet.length > 0);
}

function applyIntruderProcessors(payload: string, processors: IntruderPayloadProcessor[]) {
  return processors.reduce((next, processor) => {
    if (processor === 'url-encode') return encodeURIComponent(next);
    if (processor === 'base64') return btoa(unescape(encodeURIComponent(next)));
    if (processor === 'uppercase') return next.toUpperCase();
    if (processor === 'lowercase') return next.toLowerCase();
    return next;
  }, payload);
}

function buildIntruderPayloadPlans(rawRequest: string, request: IntruderAttackRequest, attackMode: IntruderAttackMode): IntruderPayloadPlan[] {
  const markerCount = countIntruderMarkers(rawRequest);
  const payloadSets = normalizeIntruderPayloadSets(request);
  if (payloadSets.length === 0) return [];
  const positions = Math.max(markerCount, 1);
  const setForPosition = (index: number) => payloadSets[Math.min(index, payloadSets.length - 1)] ?? payloadSets[0];
  const plans: IntruderPayloadPlan[] = [];

  if (markerCount === 0) {
    return payloadSets[0].slice(0, INTRUDER_MAX_PAYLOAD_PLANS).map((payload) => ({
      label: payload,
      payloads: [payload],
      rawRequest,
    }));
  }

  if (attackMode === 'battering-ram') {
    for (const payload of payloadSets[0]) {
      plans.push(payloadPlan(rawRequest, Array.from({ length: markerCount }, () => payload)));
    }
    return plans.slice(0, INTRUDER_MAX_PAYLOAD_PLANS);
  }

  if (attackMode === 'pitchfork') {
    const limit = Math.min(...Array.from({ length: positions }, (_unused, index) => setForPosition(index).length));
    for (let index = 0; index < limit; index += 1) {
      plans.push(payloadPlan(rawRequest, Array.from({ length: markerCount }, (_unused, position) => setForPosition(position)[index])));
    }
    return plans.slice(0, INTRUDER_MAX_PAYLOAD_PLANS);
  }

  if (attackMode === 'cluster-bomb') {
    return limitedCartesianProduct(Array.from({ length: markerCount }, (_unused, index) => setForPosition(index)), INTRUDER_MAX_PAYLOAD_PLANS)
      .map((payloads) => payloadPlan(rawRequest, payloads));
  }

  for (let position = 0; position < markerCount; position += 1) {
    for (const payload of payloadSets[0]) {
      plans.push(payloadPlan(rawRequest, Array.from({ length: markerCount }, (_unused, index) => (index === position ? payload : markerDefault(rawRequest, index)))));
    }
  }
  return plans.slice(0, INTRUDER_MAX_PAYLOAD_PLANS);
}

function payloadPlan(rawRequest: string, payloads: string[]): IntruderPayloadPlan {
  return {
    label: payloads.join(' | '),
    payloads,
    rawRequest: replaceIntruderMarkersByPosition(rawRequest, payloads),
  };
}

function replaceIntruderMarkersByPosition(rawRequest: string, payloads: string[]) {
  let index = 0;
  return rawRequest.replace(/§([^§]*)§/g, (_match, label: string) => payloads[index++] ?? label ?? '');
}

function markerDefault(rawRequest: string, targetIndex: number) {
  let index = 0;
  let value = 'baseline';
  rawRequest.replace(/§([^§]*)§/g, (match, label: string) => {
    if (index === targetIndex) value = label || 'baseline';
    index += 1;
    return match;
  });
  return value;
}

function limitedCartesianProduct(sets: string[][], limit: number): string[][] {
  const results: string[][] = [];
  if (limit <= 0 || sets.length === 0 || sets.some((set) => set.length === 0)) return results;

  const visit = (index: number, prefix: string[]) => {
    if (results.length >= limit) return;
    if (index === sets.length) {
      results.push(prefix);
      return;
    }
    for (const value of sets[index]) {
      if (results.length >= limit) break;
      visit(index + 1, [...prefix, value]);
    }
  };

  visit(0, []);
  return results;
}

function clampIntruderOffset(value: number | undefined, planCount: number) {
  if (!Number.isFinite(value ?? 0)) return 0;
  return Math.min(Math.max(Math.round(value ?? 0), 0), Math.max(planCount, 0));
}

function sanitizeIntruderStreamChunkSize(value: number | undefined, selectedRequestCount: number) {
  if (selectedRequestCount <= 0) return 0;
  const fallback = Math.min(INTRUDER_DEFAULT_STREAM_CHUNK_SIZE, selectedRequestCount);
  if (!Number.isFinite(value ?? fallback)) return fallback;
  return Math.min(Math.max(Math.round(value ?? fallback), 1), selectedRequestCount);
}

function sanitizeIntruderResultWindowSize(value: number | undefined, selectedRequestCount: number) {
  if (selectedRequestCount <= 0) return 0;
  if (!Number.isFinite(value ?? selectedRequestCount)) return selectedRequestCount;
  return Math.min(Math.max(Math.round(value ?? selectedRequestCount), 0), INTRUDER_MAX_PAYLOAD_REQUESTS);
}

function sanitizeIntruderMemoryBudgetBytes(value: number | undefined) {
  if (value === undefined) return undefined;
  if (!Number.isFinite(value)) return undefined;
  return Math.min(Math.max(Math.round(value), 1), INTRUDER_MAX_MEMORY_BUDGET_BYTES);
}

function estimateIntruderResultBytes(result: IntruderAttackSummary['results'][number]) {
  return 512
    + textByteLength(result.payload)
    + textByteLength(result.payloads.join('\n'))
    + textByteLength(result.notes)
    + textByteLength(result.requestRaw)
    + textByteLength(result.responseRaw)
    + textByteLength(result.tags.join('\n'));
}

function textByteLength(value: string) {
  return new TextEncoder().encode(value).length;
}

function buildIntruderStreamingSummary(input: {
  selectedRequestCount: number;
  streamChunkSize: number;
  completedChunks: number;
  maxConcurrency?: number;
  maxInFlight?: number;
  durationMs?: number;
  resultWindowSize: number;
  retainedResultCount: number;
  droppedResultCount: number;
  startOffset: number;
  sentRequestCount: number;
  estimatedMemoryBytes: number;
  memoryBudgetBytes?: number;
}): NonNullable<IntruderAttackSummary['streaming']> {
  const chunkCount = input.selectedRequestCount > 0 && input.streamChunkSize > 0
    ? Math.ceil(input.selectedRequestCount / input.streamChunkSize)
    : 0;
  const firstRetainedOffset = input.retainedResultCount > 0
    ? input.startOffset + input.sentRequestCount - input.retainedResultCount
    : input.startOffset;
  const lastRetainedOffset = input.retainedResultCount > 0
    ? input.startOffset + input.sentRequestCount - 1
    : input.startOffset;
  const memoryPressure = input.memoryBudgetBytes
    ? input.estimatedMemoryBytes >= input.memoryBudgetBytes
      ? 'high'
      : input.estimatedMemoryBytes >= Math.round(input.memoryBudgetBytes * 0.7)
        ? 'medium'
        : 'low'
    : input.estimatedMemoryBytes >= 64 * 1024 * 1024
      ? 'high'
      : input.estimatedMemoryBytes >= 16 * 1024 * 1024
        ? 'medium'
        : 'low';

  return {
    chunkSize: input.streamChunkSize,
    chunkCount,
    completedChunks: Math.min(input.completedChunks, chunkCount),
    maxConcurrency: Math.max(1, Math.round(input.maxConcurrency ?? 1)),
    maxInFlight: Math.max(0, Math.round(input.maxInFlight ?? 0)),
    durationMs: Math.max(0, Math.round(input.durationMs ?? 0)),
    requestRatePerSecond: input.durationMs && input.durationMs > 0
      ? Number((input.sentRequestCount / (input.durationMs / 1000)).toFixed(2))
      : 0,
    resultWindowSize: input.resultWindowSize,
    retainedResultCount: input.retainedResultCount,
    droppedResultCount: input.droppedResultCount,
    firstRetainedOffset,
    lastRetainedOffset,
    estimatedMemoryBytes: input.estimatedMemoryBytes,
    memoryBudgetBytes: input.memoryBudgetBytes,
    memoryPressure,
  };
}

function extractIntruderMatches(haystack: string, patterns: string[]) {
  return patterns.flatMap((pattern) => {
    try {
      const match = haystack.match(new RegExp(pattern, 'i'));
      if (!match) return [];
      return [`${pattern}: ${(match[1] ?? match[0]).slice(0, 120)}`];
    } catch {
      return [`${pattern}: invalid regex`];
    }
  });
}

function simulateCrawl(request: CrawlRequest): CrawlSummary {
  const startedAt = new Date();
  let target: URL;

  try {
    target = new URL(request.startUrl);
  } catch {
    return {
      id: `crawl-preview-${startedAt.getTime()}`,
      startUrl: request.startUrl,
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      totalRequests: 0,
      blocked: true,
      message: 'Crawler blocked: start URL is invalid',
      routes: [],
      insertionPoints: [],
      exchanges: [],
    };
  }

  const allowed = request.scopeAllowlist.some((pattern) => pattern === '*' || target.hostname.endsWith(pattern.replace(/^\*\./, '.')) || target.hostname === pattern);
  if (!allowed) {
    return {
      id: `crawl-preview-${startedAt.getTime()}`,
      startUrl: target.toString(),
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      totalRequests: 0,
      blocked: true,
      message: `Crawler blocked by project scope: ${target.hostname}`,
      routes: [],
      insertionPoints: [],
      exchanges: [],
    };
  }

  const base = `${target.protocol}//${target.host}`;
  const routeSeeds: Array<Pick<CrawlRoute, 'method' | 'url' | 'status' | 'mime' | 'depth' | 'source' | 'title'>> = [
    { method: 'GET', url: target.toString(), status: 200, mime: 'text/html', depth: 0, source: 'seed', title: 'Account landing' },
    { method: 'GET', url: `${base}/admin/orders?status=open`, status: 200, mime: 'text/html', depth: 1, source: 'link', title: 'Admin orders' },
    { method: 'GET', url: `${base}/assets/app.8e31.js`, status: 200, mime: 'application/javascript', depth: 1, source: 'script', title: 'Application bundle' },
    { method: 'POST', url: `${base}/api/refunds`, status: 0, mime: 'form', depth: 1, source: 'form', title: 'Refund request form' },
  ];
  const routes = routeSeeds.slice(0, Math.max(1, Math.min(routeSeeds.length, request.maxPages + 1))).map((seed) => {
    const url = new URL(seed.url);
    return {
      id: `preview-route-${seed.method.toLowerCase()}-${url.pathname.replace(/[^a-z0-9]+/gi, '-') || 'root'}`,
      method: seed.method,
      url: seed.url,
      host: url.host,
      path: `${url.pathname}${url.search}`,
      status: seed.status,
      mime: seed.mime,
      depth: seed.depth,
      source: seed.source,
      parentUrl: seed.depth > 0 ? target.toString() : undefined,
      title: seed.title,
      discoveredAt: startedAt.toISOString(),
      insertionPoints: [],
    } satisfies CrawlRoute;
  });

  const insertionPoints: CrawlInsertionPoint[] = [];
  const addPoint = (route: CrawlRoute, type: CrawlInsertionPoint['type'], name: string, evidence: string) => {
    const point = {
      id: `preview-ip-${route.id}-${type}-${name}`.replace(/[^a-z0-9_-]+/gi, '-'),
      routeId: route.id,
      type,
      name,
      method: route.method,
      url: route.url,
      evidence,
    } satisfies CrawlInsertionPoint;
    route.insertionPoints.push(point.id);
    insertionPoints.push(point);
  };

  for (const route of routes) {
    const url = new URL(route.url);
    for (const [name] of url.searchParams) addPoint(route, 'query', name, `URL query parameter "${name}"`);
    if (route.method === 'POST') {
      for (const field of ['orderId', 'amount', 'reason']) addPoint(route, 'form', field, `HTML form field "${field}"`);
    }
    if (route.path.includes('/admin/')) addPoint(route, 'path', 'segment-1', 'Path segment "admin"');
  }

  const exchanges = routes
    .filter((route) => route.method === 'GET')
    .slice(0, request.maxPages)
    .map((route) => exchangeFromCrawlRoute(route, startedAt, request.headers));

  return {
    id: `crawl-preview-${startedAt.getTime()}`,
    startUrl: target.toString(),
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    totalRequests: exchanges.length,
    blocked: false,
    message: `Crawler discovered ${routes.length} routes, ${insertionPoints.length} insertion points, and fetched ${exchanges.length} pages in browser preview`,
    routes,
    insertionPoints,
    exchanges,
  };
}

function exchangeFromCrawlRoute(route: CrawlRoute, startedAt: Date, headers: Record<string, string> = {}): HttpExchange {
  const body = route.mime.includes('javascript')
    ? 'const routes=["/admin/orders","/api/refunds","/internal/export"];'
    : '<html><title>ProxyForge crawler preview</title><a href="/admin/orders?status=open">Orders</a><form method="post" action="/api/refunds"><input name="orderId"><input name="amount"><textarea name="reason"></textarea></form></html>';
  const sessionHeaderLines = renderSessionHeaderLines(headers);

  return {
    id: `crawl-preview-exchange-${startedAt.getTime()}-${route.id}`,
    method: route.method,
    host: route.host,
    path: route.path,
    url: route.url,
    status: route.status,
    length: body.length,
    mime: route.mime,
    risk: 'info',
    timing: 48 + route.depth * 12,
    notes: `Browser preview crawler ${route.source} discovery`,
    source: 'crawler',
    time: startedAt.toLocaleTimeString([], { hour12: false }),
    requestRaw: `${route.method} ${route.path} HTTP/2\nHost: ${route.host}\nUser-Agent: ProxyForge Crawler${sessionHeaderLines ? `\n${sessionHeaderLines}` : ''}\n\n`,
    responseRaw: `HTTP/2 ${route.status} OK\nContent-Type: ${route.mime}\nX-ProxyForge-Crawler: preview\n\n${body}`,
    tags: ['crawler', 'content-discovery', route.source],
  };
}

function renderSessionHeaderLines(headers: Record<string, string> | undefined) {
  return Object.entries(headers ?? {})
    .filter(([name, value]) => name && value && !/^(host|content-length|transfer-encoding|connection)$/i.test(name))
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n');
}

function simulateActiveScan(request: ActiveScanRequest): ActiveScanSummary {
  const startedAt = new Date();
  const target = new URL(request.targetUrl);
  const blocked = !request.scopeAllowlist.some((pattern) => pattern === '*' || target.hostname.endsWith(pattern.replace(/^\*\./, '.')) || target.hostname === pattern);
  if (blocked) {
    return {
      id: `scan-preview-${startedAt.getTime()}`,
      targetUrl: target.toString(),
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      totalRequests: 0,
      blocked: true,
      message: `Active scan blocked by project scope: ${target.hostname}`,
      findings: [],
      suppressedFindings: [],
      tuning: {
        profile: 'browser-app-calibration',
        falsePositiveControls: ['scope-gated-live-probes', 'browser-preview-no-traffic'],
        suppressedFindingCount: 0,
        dedupedFindingCount: 0,
        findingDedupeKeys: [],
        calibrationNotes: ['Browser preview blocked the active scan before sending traffic.'],
      },
      exchanges: [],
    };
  }

  const checks = request.checks.slice(0, request.maxRequests || request.checks.length);
  const exchanges = checks.map((check, index) => {
    const status = check === 'method-options' ? 204 : check === 'open-redirect' ? 302 : 200;
    const response = activeScanPreviewResponse(check, request.oastPayloadUrl);

    return {
      id: `scan-preview-exchange-${startedAt.getTime()}-${index}`,
      method: check === 'method-options' ? 'OPTIONS' : request.rawRequest.split(/\s+/)[0] || 'GET',
      host: target.host,
      path: `${target.pathname}${target.search}`,
      url: target.toString(),
      status,
      length: response.length,
      mime: activeScanPreviewMime(check),
      risk: activeScanPreviewSeverity(check),
      timing: 80 + index * 17,
      notes: `Browser preview active scanner ${check} probe`,
      source: 'scanner',
      time: new Date().toLocaleTimeString([], { hour12: false }),
      requestRaw: `${request.rawRequest}\nX-ProxyForge-Active-Scan: ${check}`,
      responseRaw: response,
      tags: ['active-scan', `check:${check}`, 'preview'],
    } satisfies HttpExchange;
  });

  const findings = checks.map((check, index) => ({
    id: `scan-preview-finding-${startedAt.getTime()}-${index}`,
    checkId: check,
    title: activeScanPreviewTitle(check),
    severity: activeScanPreviewSeverity(check),
    confidence: check === 'method-options' ? 'tentative' : 'firm',
    host: target.host,
    path: `${target.pathname}${target.search}`,
    detail: `Browser preview generated a ${check} active-scan finding for the selected request.`,
    remediation: 'Validate the finding against the live target, keep evidence attached, and tune server-side policy.',
    evidenceExchangeId: exchanges[index]?.id,
    dedupeKey: `${check}:${target.host}:${target.pathname}${target.search}`.toLowerCase(),
    confidenceReason: `firm confidence from browser-preview ${check} evidence attached to ${exchanges[index]?.id ?? 'preview exchange'}.`,
  })) satisfies ActiveScanSummary['findings'];

  return {
    id: `scan-preview-${startedAt.getTime()}`,
    targetUrl: target.toString(),
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    totalRequests: exchanges.length,
    blocked: false,
    message: `Active scan complete: ${exchanges.length} preview probes, ${findings.length} findings`,
    findings,
    suppressedFindings: [],
    tuning: {
      profile: 'browser-app-calibration',
      falsePositiveControls: [
        'scope-gated-preview-probes',
        'dedupe-by-check-host-path-title',
        'preserve-confidence-reason-per-finding',
      ],
      suppressedFindingCount: 0,
      dedupedFindingCount: 0,
      findingDedupeKeys: Array.from(new Set(findings.map((finding) => finding.dedupeKey).filter(Boolean) as string[])),
      calibrationNotes: [`${findings.length} browser-preview finding${findings.length === 1 ? '' : 's'} retained for review.`],
    },
    exchanges,
  };
}

function simulateCrawlAudit(request: CrawlAuditRequest): CrawlAuditSummary {
  const startedAt = new Date();
  const checks: ActiveScanCheckId[] = request.checks.length ? request.checks : ['security-headers'];
  const scopedPoints = request.insertionPoints
    .filter((point) => {
      try {
        const target = new URL(point.url);
        return request.scopeAllowlist.some((pattern) => pattern === '*' || target.hostname.endsWith(pattern.replace(/^\*\./, '.')) || target.hostname === pattern);
      } catch {
        return false;
      }
    })
    .slice(0, Math.max(1, request.maxInsertionPoints));

  if (scopedPoints.length === 0) {
    return {
      id: `crawl-audit-preview-${startedAt.getTime()}`,
      targetUrl: 'crawl-insertion-points',
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      totalRequests: 0,
      blocked: true,
      message: 'Crawl insertion audit blocked: no in-scope insertion points',
      findings: [],
      exchanges: [],
      auditedInsertionPoints: 0,
    };
  }

  const exchanges: HttpExchange[] = [];
  const findings: CrawlAuditSummary['findings'] = [];
  let index = 0;

  for (const point of scopedPoints) {
    const target = new URL(point.url);
    for (const check of checks) {
      const status = check === 'method-options' ? 204 : check === 'open-redirect' ? 302 : 200;
      const response = activeScanPreviewResponse(check);
      const sessionHeaderLines = renderSessionHeaderLines(request.sessionHeaders);
      const exchange = {
        id: `crawl-audit-preview-exchange-${startedAt.getTime()}-${index}`,
        method: check === 'method-options' ? 'OPTIONS' : point.method,
        host: target.host,
        path: `${target.pathname}${target.search}`,
        url: target.toString(),
        status,
        length: response.length,
        mime: activeScanPreviewMime(check),
        risk: activeScanPreviewSeverity(check),
        timing: 90 + index * 11,
        notes: `Browser preview crawl-audit ${point.type}:${point.name} ${check} probe`,
        source: 'scanner',
        time: new Date().toLocaleTimeString([], { hour12: false }),
        requestRaw: `${point.method} ${target.pathname}${target.search} HTTP/2\nHost: ${target.host}${sessionHeaderLines ? `\n${sessionHeaderLines}` : ''}\nX-ProxyForge-Insertion-Point: ${point.type}:${point.name}\nX-ProxyForge-Active-Scan: ${check}\n\n`,
        responseRaw: response,
        tags: ['active-scan', 'crawl-audit', `check:${check}`, `insertion:${point.type}`, `insertion-name:${point.name}`, 'preview'],
      } satisfies HttpExchange;
      exchanges.push(exchange);
      findings.push({
        id: `crawl-audit-preview-finding-${startedAt.getTime()}-${index}`,
        checkId: check,
        title: activeScanPreviewTitle(check),
        severity: activeScanPreviewSeverity(check),
        confidence: check === 'method-options' ? 'tentative' : 'firm',
        host: target.host,
        path: `${target.pathname}${target.search}`,
        detail: `Browser preview generated a ${check} finding from crawler insertion point ${point.type}:${point.name}.`,
        remediation: 'Validate the finding against the live target, then prioritize confirmed issues by affected workflow and privilege boundary.',
        evidenceExchangeId: exchange.id,
        dedupeKey: `${check}:${target.host}:${target.pathname}${target.search}:${point.type}:${point.name}`.toLowerCase(),
        confidenceReason: `firm confidence from crawler insertion point ${point.type}:${point.name} preview evidence.`,
      });
      index += 1;
    }
  }

  return {
    id: `crawl-audit-preview-${startedAt.getTime()}`,
    targetUrl: 'crawl-insertion-points',
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    totalRequests: exchanges.length,
    blocked: false,
    message: `Crawl insertion audit complete: ${scopedPoints.length} insertion points, ${exchanges.length} preview probes, ${findings.length} findings`,
    findings,
    exchanges,
    auditedInsertionPoints: scopedPoints.length,
  };
}

function activeScanPreviewTitle(check: ActiveScanRequest['checks'][number]) {
  const titles = {
    'security-headers': 'HTML response missing Content-Security-Policy',
    'cors-origin': 'CORS policy trusts scanner-controlled origin',
    'cache-key': 'Untrusted cache-routing header reflected',
    'method-options': 'OPTIONS response advertises state-changing methods',
    'authz-diff': 'Authenticated state comparison preserved privileged response',
    'jwt-claims': 'Token or privileged claim material exposed',
    'graphql-introspection': 'GraphQL introspection data exposed',
    'oast-ssrf': 'Out-of-band callback was triggered',
    'reflected-xss': 'Reflected script payload returned unencoded',
    'sql-injection': 'SQL injection probe exposed database error evidence',
    'path-traversal': 'Path traversal probe reached file-like content',
    'open-redirect': 'Open redirect accepts scanner-controlled destination',
    'command-injection': 'Command injection probe produced execution-like output',
  };
  return titles[check];
}

function activeScanPreviewResponse(check: ActiveScanRequest['checks'][number], oastPayloadUrl?: string) {
  const responses: Record<ActiveScanRequest['checks'][number], string> = {
    'security-headers': 'HTTP/2 200 OK\nContent-Type: text/html\n\n<html>missing security headers</html>',
    'cors-origin': 'HTTP/2 200 OK\nContent-Type: application/json\nAccess-Control-Allow-Origin: https://proxyforge.invalid\nAccess-Control-Allow-Credentials: true\n\n{"ok":true}',
    'cache-key': 'HTTP/2 200 OK\nContent-Type: text/html\n\n<html>proxyforge.invalid</html>',
    'method-options': 'HTTP/2 204 No Content\nAllow: GET, POST, DELETE\nAccess-Control-Allow-Methods: GET, POST, DELETE\n\n',
    'authz-diff': 'HTTP/2 200 OK\nContent-Type: application/json\n\n{"role":"support_admin","featureFlags":["refunds.write"],"comparison":"low-privilege"}',
    'jwt-claims': 'HTTP/2 200 OK\nContent-Type: application/json\n\n{"token":"eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic3VwcG9ydF9hZG1pbiJ9.signature","scope":"refunds.write"}',
    'graphql-introspection': 'HTTP/2 200 OK\nContent-Type: application/json\n\n{"data":{"__schema":{"queryType":{"name":"Query"},"mutationType":{"name":"Mutation"}}}}',
    'oast-ssrf': `HTTP/2 200 OK\nContent-Type: application/json\nX-Fixture-Vulnerability: ssrf-local-callback\n\n{"ok":true,"callbackUrl":"${oastPayloadUrl ?? 'http://127.0.0.1:1/proxyforge-oast-missing'}","callbackStatus":204}`,
    'reflected-xss': 'HTTP/2 200 OK\nContent-Type: text/html\n\n<html><script>proxyforge_xss_probe</script></html>',
    'sql-injection': 'HTTP/2 500 Internal Server Error\nContent-Type: text/plain\n\nSQL syntax error near proxyforge_sql_probe',
    'path-traversal': 'HTTP/2 200 OK\nContent-Type: text/plain\n\nroot:x:0:0:root:/root:/bin/bash',
    'open-redirect': 'HTTP/2 302 Found\nLocation: https://proxyforge.invalid/redirect-proof\nContent-Type: text/html\n\nredirecting',
    'command-injection': 'HTTP/2 200 OK\nContent-Type: text/plain\n\nuid=1000(proxyforge) gid=1000(proxyforge) proxyforge_command_probe',
  };
  return responses[check];
}

function activeScanPreviewSeverity(check: ActiveScanRequest['checks'][number]): ActiveScanSummary['findings'][number]['severity'] {
  if (check === 'command-injection') return 'critical';
  if (['cors-origin', 'authz-diff', 'oast-ssrf', 'reflected-xss', 'sql-injection', 'path-traversal'].includes(check)) return 'high';
  if (['cache-key', 'jwt-claims', 'graphql-introspection', 'open-redirect'].includes(check)) return 'medium';
  return 'low';
}

function activeScanPreviewMime(check: ActiveScanRequest['checks'][number]) {
  if (['cors-origin', 'authz-diff', 'jwt-claims', 'graphql-introspection', 'oast-ssrf'].includes(check)) return 'application/json';
  if (['sql-injection', 'path-traversal', 'command-injection'].includes(check)) return 'text/plain';
  return 'text/html';
}

function analyzeBrowserSequencerSamples(request: SequencerSampleRequest): SequencerAnalysisResult {
  const generatedAt = new Date();
  const samples = request.samples.map((sample) => sample.trim()).filter(Boolean).slice(0, 20000);
  const sampleCount = samples.length;
  const uniqueCount = new Set(samples).size;
  const duplicateCount = Math.max(0, sampleCount - uniqueCount);
  const lengths = samples.map((sample) => Array.from(sample).length);
  const minLength = lengths.length ? Math.min(...lengths) : 0;
  const maxLength = lengths.length ? Math.max(...lengths) : 0;
  const averageLength = lengths.length ? lengths.reduce((sum, value) => sum + value, 0) / lengths.length : 0;
  const characters = samples.flatMap((sample) => Array.from(sample));
  const shannonBitsPerChar = browserShannonEntropy(characters);
  const estimatedEntropyBits = shannonBitsPerChar * averageLength;
  const collisionRate = sampleCount ? duplicateCount / sampleCount : 0;
  const serialCorrelation = Math.abs(browserSerialCorrelation(characters.map((char) => char.charCodeAt(0))));
  const monobitRatio = browserMonobitRatio(samples);
  const repeatedPrefixLength = browserCommonPrefixLength(samples);
  const characterSets = browserCharacterSets(characters);
  const reliability = browserSequencerReliability(sampleCount);
  const positionStats = browserSequencerPositionStats(samples);
  const bitStats = browserSequencerBitStats(samples);
  const entropyBySignificance = browserSequencerEntropyBySignificance(estimatedEntropyBits, sampleCount, bitStats);
  const statisticalTests = browserSequencerStatisticalTests({
    sampleCount,
    collisionRate,
    estimatedEntropyBits,
    repeatedPrefixLength,
    serialCorrelation,
    monobitRatio,
    positionStats,
    bitStats,
  });
  const findings = browserSequencerFindings({
    sampleCount,
    duplicateCount,
    collisionRate,
    minLength,
    estimatedEntropyBits,
    repeatedPrefixLength,
    serialCorrelation,
    monobitRatio,
    uniqueCharacters: new Set(characters).size,
  });

  return {
    id: `sequencer-preview-${generatedAt.getTime()}`,
    label: request.label.trim() || 'Token sample',
    source: request.source,
    generatedAt: generatedAt.toISOString(),
    sampleCount,
    uniqueCount,
    duplicateCount,
    minLength,
    maxLength,
    averageLength: browserRound(averageLength),
    shannonBitsPerChar: browserRound(shannonBitsPerChar),
    estimatedEntropyBits: browserRound(estimatedEntropyBits),
    collisionRate: browserRound(collisionRate),
    serialCorrelation: browserRound(serialCorrelation),
    monobitRatio: browserRound(monobitRatio),
    repeatedPrefixLength,
    characterSets,
    reliability,
    entropyBySignificance,
    positionStats,
    bitStats,
    statisticalTests,
    verdict: browserSequencerVerdict(findings, sampleCount, estimatedEntropyBits),
    findings,
  };
}

function browserShannonEntropy(characters: string[]) {
  if (characters.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const char of characters) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / characters.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function browserSerialCorrelation(values: number[]) {
  if (values.length < 3) return 0;
  const xs = values.slice(0, -1);
  const ys = values.slice(1);
  const meanX = xs.reduce((sum, value) => sum + value, 0) / xs.length;
  const meanY = ys.reduce((sum, value) => sum + value, 0) / ys.length;
  let covariance = 0;
  let varianceX = 0;
  let varianceY = 0;

  for (let index = 0; index < xs.length; index += 1) {
    const dx = xs[index] - meanX;
    const dy = ys[index] - meanY;
    covariance += dx * dy;
    varianceX += dx * dx;
    varianceY += dy * dy;
  }

  if (varianceX === 0 || varianceY === 0) return 0;
  return covariance / Math.sqrt(varianceX * varianceY);
}

function browserMonobitRatio(samples: string[]) {
  const bytes = new TextEncoder().encode(samples.join('\n'));
  if (bytes.length === 0) return 0;
  let ones = 0;
  for (const byte of bytes) {
    let value = byte;
    for (let bit = 0; bit < 8; bit += 1) {
      ones += value & 1;
      value >>= 1;
    }
  }
  return ones / (bytes.length * 8);
}

function browserCommonPrefixLength(samples: string[]) {
  if (samples.length < 2) return 0;
  const first = Array.from(samples[0]);
  let prefixLength = 0;
  for (let index = 0; index < first.length; index += 1) {
    if (samples.every((sample) => Array.from(sample)[index] === first[index])) {
      prefixLength += 1;
      continue;
    }
    break;
  }
  return prefixLength;
}

function browserCharacterSets(characters: string[]): SequencerCharacterSet[] {
  const uniqueCharacters = Array.from(new Set(characters));
  const definitions = [
    { name: 'Lowercase', size: 26, matcher: (char: string) => /[a-z]/.test(char) },
    { name: 'Uppercase', size: 26, matcher: (char: string) => /[A-Z]/.test(char) },
    { name: 'Digits', size: 10, matcher: (char: string) => /[0-9]/.test(char) },
    { name: 'Hex alphabet', size: 16, matcher: (char: string) => /[a-fA-F0-9]/.test(char) },
    { name: 'Base64url alphabet', size: 64, matcher: (char: string) => /[A-Za-z0-9_-]/.test(char) },
    { name: 'Symbols', size: 32, matcher: (char: string) => /[^A-Za-z0-9]/.test(char) },
  ];
  return definitions.map((definition) => ({
    name: definition.name,
    size: definition.size,
    observed: uniqueCharacters.filter(definition.matcher).length,
  }));
}

function browserSequencerReliability(sampleCount: number): SequencerReliabilitySummary {
  if (sampleCount >= 20000) {
    return {
      level: 'fips-ready',
      sampleTarget: 5000,
      maxSupportedSamples: 20000,
      fipsSampleTarget: 20000,
      message: '20,000 tokens are available, enough for FIPS-style statistical confidence.',
    };
  }
  if (sampleCount >= 5000) {
    return {
      level: 'reliable',
      sampleTarget: 5000,
      maxSupportedSamples: 20000,
      fipsSampleTarget: 20000,
      message: 'Sample size is usually sufficient for reliable Sequencer-style analysis.',
    };
  }
  if (sampleCount >= 100) {
    return {
      level: 'indicative',
      sampleTarget: 5000,
      maxSupportedSamples: 20000,
      fipsSampleTarget: 20000,
      message: 'Sample size can provide an indicative result, but collect closer to 5,000 tokens before relying on it.',
    };
  }
  return {
    level: 'rough',
    sampleTarget: 5000,
    maxSupportedSamples: 20000,
    fipsSampleTarget: 20000,
    message: 'Sample reliability is rough because fewer than 100 tokens were analyzed; treat the result as triage only.',
  };
}

function browserSequencerPositionStats(samples: string[]): SequencerPositionStat[] {
  const maxLength = samples.reduce((max, sample) => Math.max(max, Array.from(sample).length), 0);
  return Array.from({ length: Math.min(maxLength, 64) }, (_item, index) => {
    const chars = samples
      .map((sample) => Array.from(sample)[index])
      .filter((char): char is string => typeof char === 'string');
    const counts = new Map<string, number>();
    for (const char of chars) counts.set(char, (counts.get(char) ?? 0) + 1);
    const ordered = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
    const dominant = ordered[0] ?? ['', 0];
    const transitionPairs = chars.slice(1).map((char, pairIndex) => `${chars[pairIndex]}->${char}`);
    const repeatedTransitions = transitionPairs.filter((pair, pairIndex) => transitionPairs.indexOf(pair) !== pairIndex).length;
    return {
      index,
      samplesObserved: chars.length,
      observedCharacters: counts.size,
      maxEntropyBits: browserRound(counts.size > 1 ? Math.log2(counts.size) : 0),
      shannonBits: browserRound(browserShannonEntropy(chars)),
      dominantCharacter: dominant[0],
      dominantRate: browserRound(chars.length ? dominant[1] / chars.length : 0),
      transitionRepeatRate: browserRound(transitionPairs.length ? repeatedTransitions / transitionPairs.length : 0),
      bitStart: index * 8,
      bitLength: chars.length ? 8 : 0,
    };
  });
}

function browserSequencerBitStats(samples: string[]): SequencerBitStat[] {
  const maxLength = samples.reduce((max, sample) => Math.max(max, Array.from(sample).length), 0);
  return Array.from({ length: Math.min(maxLength * 8, 256) }, (_item, index) => {
    const sourcePosition = Math.floor(index / 8);
    const bitOffset = index % 8;
    const bits = samples.flatMap((sample) => {
      const char = Array.from(sample)[sourcePosition];
      if (!char) return [];
      return [(char.charCodeAt(0) >> (7 - bitOffset)) & 1];
    });
    const ones = bits.filter((bit) => bit === 1).length;
    const zeros = bits.length - ones;
    const skew = bits.length ? Math.abs(ones - zeros) / bits.length : 1;
    const monobitPValue = browserRound(Math.max(0, 1 - skew * 2));
    const runCount = bits.reduce((count, bit, bitIndex) => bitIndex === 0 || bit !== bits[bitIndex - 1] ? count + 1 : count, 0);
    const pokerScore = browserRound(browserSequencerPokerScore(bits));
    return {
      index,
      sourcePosition,
      ones,
      zeros,
      monobitPValue,
      pokerScore,
      runCount,
      passedFips: bits.length >= 20 && monobitPValue >= 0.01 && pokerScore <= 3.84,
    };
  });
}

function browserSequencerPokerScore(bits: number[]) {
  if (bits.length < 16) return 0;
  const groups = new Map<number, number>();
  const groupCount = Math.floor(bits.length / 4);
  for (let groupIndex = 0; groupIndex < groupCount; groupIndex += 1) {
    const offset = groupIndex * 4;
    const value = (bits[offset] << 3) | (bits[offset + 1] << 2) | (bits[offset + 2] << 1) | bits[offset + 3];
    groups.set(value, (groups.get(value) ?? 0) + 1);
  }
  const expected = groupCount / 16;
  if (expected === 0) return 0;
  let chiSquare = 0;
  for (let value = 0; value < 16; value += 1) {
    const observed = groups.get(value) ?? 0;
    chiSquare += ((observed - expected) ** 2) / expected;
  }
  return chiSquare;
}

function browserSequencerEntropyBySignificance(estimatedEntropyBits: number, sampleCount: number, bitStats: SequencerBitStat[]): SequencerEntropySignificancePoint[] {
  const failedBitPenalty = bitStats.filter((bit) => !bit.passedFips).length * 0.35;
  const samplePenalty = sampleCount < 100 ? 0.72 : sampleCount < 5000 ? 0.9 : 1;
  return [
    ['fips 0.001%', 0.92],
    ['reliable 0.01%', 0.95],
    ['reliable 0.1%', 0.97],
    ['indicative 1%', 0.985],
    ['rough 5%', 1],
    ['sample 10%', 1.01],
  ].map(([significance, multiplier]) => ({
    significance: String(significance),
    effectiveEntropyBits: browserRound(Math.max(0, (estimatedEntropyBits - failedBitPenalty) * Number(multiplier) * samplePenalty)),
  }));
}

function browserSequencerStatisticalTests(metrics: {
  sampleCount: number;
  collisionRate: number;
  estimatedEntropyBits: number;
  repeatedPrefixLength: number;
  serialCorrelation: number;
  monobitRatio: number;
  positionStats: SequencerPositionStat[];
  bitStats: SequencerBitStat[];
}): SequencerStatisticalTest[] {
  const biasedPositions = metrics.positionStats.filter((position) => position.dominantRate > 0.65 && position.samplesObserved > 1).map((position) => position.index);
  const weakTransitionPositions = metrics.positionStats.filter((position) => position.transitionRepeatRate > 0.35).map((position) => position.index);
  const failedBits = metrics.bitStats.filter((bit) => !bit.passedFips && bit.ones + bit.zeros >= 20).map((bit) => bit.index);
  return [
    {
      id: 'sample-reliability',
      name: 'Sample reliability',
      level: 'summary',
      significance: 'size',
      passed: metrics.sampleCount >= 100,
      score: metrics.sampleCount,
      detail: `${metrics.sampleCount} samples available; 100 is the minimum rough analysis threshold and 5,000 is the usual reliability target.`,
      failedPositions: [],
    },
    {
      id: 'effective-entropy',
      name: 'Effective entropy',
      level: 'summary',
      significance: '1%',
      passed: metrics.estimatedEntropyBits >= 64,
      score: browserRound(metrics.estimatedEntropyBits),
      detail: `${browserRound(metrics.estimatedEntropyBits)} estimated bits after character distribution and bit-level penalties.`,
      failedPositions: [],
    },
    {
      id: 'character-count',
      name: 'Character count analysis',
      level: 'character',
      significance: '1%',
      passed: biasedPositions.length === 0,
      score: browserRound(1 - (biasedPositions.length / Math.max(metrics.positionStats.length, 1))),
      detail: 'Looks for dominant characters at each token position that would be unlikely under a uniform generator.',
      failedPositions: biasedPositions.slice(0, 24),
    },
    {
      id: 'character-transition',
      name: 'Character transition analysis',
      level: 'character',
      significance: '1%',
      passed: weakTransitionPositions.length === 0 && metrics.serialCorrelation <= 0.45,
      score: browserRound(1 - (weakTransitionPositions.length / Math.max(metrics.positionStats.length, 1))),
      detail: `Transition repeat rate and serial correlation (${browserRound(metrics.serialCorrelation)}) are checked across adjacent tokens.`,
      failedPositions: weakTransitionPositions.slice(0, 24),
    },
    {
      id: 'fips-monobit',
      name: 'FIPS monobit test',
      level: 'fips',
      significance: '0.01%',
      passed: metrics.monobitRatio >= 0.4 && metrics.monobitRatio <= 0.6,
      score: browserRound(metrics.monobitRatio),
      detail: `Overall one-bit ratio is ${browserRound(metrics.monobitRatio)}; larger samples should sit close to 0.50.`,
      failedPositions: failedBits.slice(0, 24),
    },
    {
      id: 'fips-poker',
      name: 'FIPS poker test',
      level: 'fips',
      significance: '0.01%',
      passed: failedBits.length === 0,
      score: browserRound(failedBits.length / Math.max(metrics.bitStats.length, 1)),
      detail: 'Four-bit group distributions are checked per bit position for strong skew.',
      failedPositions: failedBits.slice(0, 24),
    },
    {
      id: 'collision',
      name: 'Collision analysis',
      level: 'summary',
      significance: 'observed',
      passed: metrics.collisionRate === 0,
      score: browserRound(metrics.collisionRate),
      detail: `${browserRound(metrics.collisionRate * 100)}% of samples collided.`,
      failedPositions: [],
    },
    {
      id: 'prefix',
      name: 'Static prefix analysis',
      level: 'character',
      significance: 'observed',
      passed: metrics.repeatedPrefixLength < 8,
      score: metrics.repeatedPrefixLength,
      detail: `${metrics.repeatedPrefixLength} shared leading characters should be excluded from entropy assumptions.`,
      failedPositions: Array.from({ length: Math.min(metrics.repeatedPrefixLength, 24) }, (_item, index) => index),
    },
  ];
}

function browserSequencerFindings(metrics: {
  sampleCount: number;
  duplicateCount: number;
  collisionRate: number;
  minLength: number;
  estimatedEntropyBits: number;
  repeatedPrefixLength: number;
  serialCorrelation: number;
  monobitRatio: number;
  uniqueCharacters: number;
}): SequencerFinding[] {
  const findings: SequencerFinding[] = [];

  if (metrics.sampleCount === 0) {
    return [{
      title: 'No token samples supplied',
      severity: 'high',
      detail: 'Sequencer needs at least one observed token before entropy and predictability checks can run.',
    }];
  }

  if (metrics.sampleCount < 8) {
    findings.push({
      title: 'Low sample size',
      severity: 'low',
      detail: `${metrics.sampleCount} samples were analyzed. Collect 20 or more live tokens before relying on statistical confidence.`,
    });
  }
  if (metrics.duplicateCount > 0) {
    findings.push({
      title: 'Token collisions observed',
      severity: metrics.collisionRate >= 0.1 ? 'high' : 'medium',
      detail: `${metrics.duplicateCount} duplicate sample${metrics.duplicateCount === 1 ? '' : 's'} appeared in the corpus, a collision rate of ${(metrics.collisionRate * 100).toFixed(1)}%.`,
    });
  }
  if (metrics.minLength > 0 && metrics.minLength < 16) {
    findings.push({
      title: 'Short token length',
      severity: 'medium',
      detail: `The shortest token is ${metrics.minLength} characters. Short bearer/session tokens can be easier to brute force or enumerate.`,
    });
  }
  if (metrics.estimatedEntropyBits < 64) {
    findings.push({
      title: 'Estimated entropy below session-token baseline',
      severity: 'high',
      detail: `Estimated entropy is ${browserRound(metrics.estimatedEntropyBits)} bits. Session-grade tokens should generally exceed 64 bits and preferably 96 bits or more.`,
    });
  } else if (metrics.estimatedEntropyBits < 96) {
    findings.push({
      title: 'Estimated entropy needs review',
      severity: 'medium',
      detail: `Estimated entropy is ${browserRound(metrics.estimatedEntropyBits)} bits. Validate that server-side generation is cryptographically random.`,
    });
  }
  if (metrics.repeatedPrefixLength >= 8) {
    findings.push({
      title: 'Long repeated prefix',
      severity: 'medium',
      detail: `All samples share a ${metrics.repeatedPrefixLength}-character prefix. Confirm the variable portion alone carries sufficient entropy.`,
    });
  } else if (metrics.repeatedPrefixLength >= 4) {
    findings.push({
      title: 'Repeated prefix detected',
      severity: 'low',
      detail: `Samples share a ${metrics.repeatedPrefixLength}-character prefix. This can be normal for versioned tokens but should be excluded from entropy assumptions.`,
    });
  }
  if (metrics.serialCorrelation > 0.45) {
    findings.push({
      title: 'High serial correlation',
      severity: 'medium',
      detail: `Adjacent character correlation is ${browserRound(metrics.serialCorrelation)}. Predictable counters, timestamps, or encoders can create this pattern.`,
    });
  }
  if (metrics.monobitRatio > 0 && (metrics.monobitRatio < 0.4 || metrics.monobitRatio > 0.6)) {
    findings.push({
      title: 'Bit distribution is skewed',
      severity: 'low',
      detail: `The monobit ratio is ${browserRound(metrics.monobitRatio)}. Strong random data usually lands close to 0.50 over larger samples.`,
    });
  }
  if (metrics.uniqueCharacters <= 4 && metrics.sampleCount > 1) {
    findings.push({
      title: 'Very small observed alphabet',
      severity: 'high',
      detail: `Only ${metrics.uniqueCharacters} unique character${metrics.uniqueCharacters === 1 ? '' : 's'} appeared across the sample corpus.`,
    });
  }

  if (findings.length === 0) {
    findings.push({
      title: 'No obvious predictability signals',
      severity: 'info',
      detail: 'The current corpus shows no duplicate, prefix, entropy, bit-balance, or correlation signal that warrants immediate concern.',
    });
  }

  return findings;
}

function browserSequencerVerdict(findings: SequencerFinding[], sampleCount: number, estimatedEntropyBits: number) {
  if (findings.some((finding) => ['critical', 'high'].includes(finding.severity))) return 'weak';
  if (sampleCount < 16 || estimatedEntropyBits < 96 || findings.some((finding) => finding.severity === 'medium' || finding.severity === 'low')) return 'watch';
  return 'strong';
}

function browserRound(value: number) {
  return Number.isFinite(value) ? Number(value.toFixed(3)) : 0;
}
