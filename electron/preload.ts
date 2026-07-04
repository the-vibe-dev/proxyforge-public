import { contextBridge, ipcRenderer } from 'electron';

interface HttpExchange {
  id: string;
  method: string;
  host: string;
  path: string;
  url: string;
  status: number;
  length: number;
  mime: string;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
  timing: number;
  notes: string;
  source: 'proxy' | 'repeater' | 'scanner' | 'crawler' | 'demo';
  time: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
}

type CallbackProtocol = 'dns' | 'http' | 'smtp';
type CallbackPayloadStatus = 'waiting' | 'observed' | 'archived';
type CallbackListenerMode = 'browser-preview' | 'local-http' | 'local-dns' | 'local-smtp' | 'hybrid-local';
type CallbackListenerStatus = 'planned' | 'running' | 'stopped' | 'blocked';

interface CallbackPayload {
  id: string;
  token: string;
  label: string;
  protocol: CallbackProtocol;
  endpoint: string;
  createdAt: string;
  status: CallbackPayloadStatus;
  sourceExchangeId?: string;
  sourceHost?: string;
  sourcePath?: string;
  lastInteractionAt?: string;
  notes: string;
}

interface CallbackInteraction {
  id: string;
  payloadId: string;
  protocol: CallbackProtocol;
  observedAt: string;
  sourceIp: string;
  sourceHost: string;
  requestLine: string;
  userAgent: string;
  raw: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  tags: string[];
}

interface CallbackListenerProfile {
  id: string;
  name: string;
  createdAt: string;
  mode: CallbackListenerMode;
  status: CallbackListenerStatus;
  host: string;
  publicBaseUrl: string;
  protocols: CallbackProtocol[];
  httpPort: number;
  dnsPort: number;
  smtpPort: number;
  pollIntervalSeconds: number;
  retentionHours: number;
  signingKeyId: string;
  ciCommand: string;
  healthChecks: string[];
  summary: string;
  content: string;
}

interface CallbackListenerRuntimeStatus {
  profileId: string;
  running: boolean;
  mode: CallbackListenerMode;
  host: string;
  protocols: CallbackProtocol[];
  ports: Partial<Record<CallbackProtocol, number>>;
  interactionCount: number;
  startedAt?: string;
  stoppedAt?: string;
  healthChecks: string[];
  message: string;
}

interface CallbackListenerPollResult {
  status: CallbackListenerRuntimeStatus;
  interactions: CallbackInteraction[];
  newInteractionIds: string[];
}

type ExtensionPermission = 'read-traffic' | 'modify-traffic' | 'create-issues' | 'run-automations' | 'callback-access';
type ExtensionHook = 'passive-scan' | 'request-editor' | 'traffic-enrichment' | 'report-transform';
type ExtensionTrustLevel = 'built-in' | 'verified' | 'local';

interface InstalledExtension {
  id: string;
  catalogId?: string;
  name: string;
  author: string;
  version: string;
  description: string;
  enabled: boolean;
  hooks: ExtensionHook[];
  permissions: ExtensionPermission[];
  trustLevel: ExtensionTrustLevel;
  installedAt: string;
}

interface ExtensionRun {
  id: string;
  extensionId: string;
  extensionName: string;
  hook: ExtensionHook;
  status: 'complete' | 'blocked' | 'error';
  target: string;
  startedAt: string;
  completedAt: string;
  summary: string;
  logs: string[];
  issue?: {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    host: string;
    path: string;
    confidence: 'certain' | 'firm' | 'tentative';
    status: 'open' | 'triaged' | 'false-positive' | 'fixed';
    detail: string;
    remediation: string;
  };
  exchange?: HttpExchange;
}

type AutomationWorkflowStatus = 'ready' | 'running' | 'blocked' | 'complete';
type AutomationTrigger = 'manual' | 'scheduled' | 'on-tag' | 'ci';
type AutomationStepType = 'replay' | 'crawl' | 'active-scan' | 'callback-poll' | 'report-export' | 'delay';
type AutomationCiProvider = 'github-actions' | 'gitlab-ci' | 'azure-pipelines' | 'jenkins';

interface AutomationWorkflowStep {
  id: string;
  type: AutomationStepType;
  label: string;
  target: string;
  throttleMs: number;
  maxRequests: number;
  requiresApproval: boolean;
}

interface AutomationWorkflow {
  id: string;
  name: string;
  status: AutomationWorkflowStatus;
  trigger: AutomationTrigger;
  scope: string;
  scheduleEnabled: boolean;
  scheduleIntervalMinutes: number;
  nextRunAt: string;
  lastRun: string;
  steps: AutomationWorkflowStep[];
}

interface AutomationExecution {
  id: string;
  workflowId: string;
  workflowName: string;
  status: AutomationWorkflowStatus;
  trigger: AutomationTrigger;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  totalRequests: number;
  logs: string[];
  exchange?: HttpExchange;
  issue?: {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    host: string;
    path: string;
    confidence: 'certain' | 'firm' | 'tentative';
    status: 'open' | 'triaged' | 'false-positive' | 'fixed';
    detail: string;
    remediation: string;
  };
  operationalRawMaterial?: {
    sourceExchangeId: string;
    requestRaw: string;
    responseRaw: string;
    secretHandling: 'execution-full-fidelity-secrets-preserved';
    reportRedactionBoundary: 'redact-only-during-report-export';
  };
  ciProvider?: AutomationCiProvider;
  ciConfig: string;
}

interface ProjectRunStatePersistResult {
  kind: 'proxyforge-project-run-state-persist-result';
  runType: 'automation' | 'ai' | 'extension';
  id: string;
  stats: Record<string, unknown>;
}

interface EnterpriseRemotePolicyTransport {
  endpoint: string;
  authHeaderName: string;
  credentialLabel: string;
  lastPulledAt?: string;
  lastPushedAt?: string;
  pullCount: number;
  pushCount: number;
  lastPackageDigestSha256?: string;
  status: 'not-configured' | 'ready' | 'pulled' | 'pushed' | 'error';
  message: string;
}

interface EnterprisePolicyTransportRuntimeRequest {
  transport: EnterpriseRemotePolicyTransport;
  policyPackage?: Record<string, unknown>;
  timeoutMs?: number;
  authHeaderValue?: string;
}

interface EnterprisePolicyTransportRuntimeResult {
  endpoint: string;
  method: 'GET' | 'POST';
  statusCode: number;
  completedAt: string;
  digestSha256: string;
  receiptId?: string;
  responseBody: string;
  message: string;
  policyPackage?: Record<string, unknown>;
}

type ExploitMode = 'dry-run' | 'approved';
type ExploitRunStatus = 'complete' | 'blocked' | 'error';

interface ExploitRun {
  id: string;
  templateId: string;
  templateTitle: string;
  mode: ExploitMode;
  status: ExploitRunStatus;
  target: string;
  startedAt: string;
  completedAt: string;
  approvalRequired: boolean;
  approvalSatisfied: boolean;
  scopePassed: boolean;
  stopReason: string;
  payloadPreview: string;
  logs: string[];
  exchange?: HttpExchange;
  issue?: {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    host: string;
    path: string;
    confidence: 'certain' | 'firm' | 'tentative';
    status: 'open' | 'triaged' | 'false-positive' | 'fixed';
    detail: string;
    remediation: string;
  };
}

interface ReplayMatrixResult {
  id: string;
  identity: string;
  headerName: string;
  status: number;
  length: number;
  timing: number;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
  delta: string;
  notes: string;
  exchange: HttpExchange;
}

interface ReplayMatrixRun {
  id: string;
  targetUrl: string;
  headerName: string;
  startedAt: string;
  completedAt: string;
  baselineStatus: number;
  baselineLength: number;
  totalRequests: number;
  blocked: boolean;
  message: string;
  results: ReplayMatrixResult[];
}

interface ProjectSafetyPolicy {
  requireScopeMatch: boolean;
  auditLogging: boolean;
  redactAuditSecrets: boolean;
  minThrottleMs: number;
  maxRequestsPerRun: number;
}

interface PolicyOverride {
  id: string;
  operator: string;
  role: string;
  enabled: boolean;
  createdAt: string;
  expiresAt: string;
  scopeAdditions: string[];
  minThrottleMs?: number;
  maxRequestsPerRun?: number;
  reason: string;
}

interface HttpsInspectionSettings {
  upstreamTlsMode: 'strict' | 'relaxed';
}

interface AuditEvent {
  id: string;
  at: string;
  operator?: string;
  tool: string;
  action: string;
  target: string;
  decision: 'allowed' | 'blocked' | 'completed' | 'updated';
  detail: string;
  requestCount: number;
  scope: string[];
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

interface ApprovalRecord {
  id: string;
  at: string;
  operator: string;
  tool: string;
  action: string;
  target: string;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
  status: 'approved' | 'used' | 'revoked';
  expiresAt: string;
  detail: string;
  scope: string[];
  evidenceIds: string[];
}

interface SignedAuditExport {
  id: string;
  fileName: string;
  path: string;
  exportedAt: string;
  projectName: string;
  signerName: string;
  keyId: string;
  digestSha256: string;
  signature: string;
  status: 'signed' | 'missing-secret';
  eventCount: number;
  approvalCount: number;
  overrideCount: number;
  sizeBytes: number;
  content?: string;
}

type IssueStatus = 'open' | 'triaged' | 'false-positive' | 'fixed';

interface IssueTriageOverride {
  issueId: string;
  status: IssueStatus;
  assignee: string;
  triageNote: string;
  updatedAt: string;
}

interface ScannerAuditQueueItem {
  id: string;
  kind: 'passive' | 'active-scan' | 'crawl-audit' | 'authz-replay' | 'manual-review';
  label: string;
  target: string;
  status: 'queued' | 'running' | 'complete' | 'blocked';
  priority: 'critical' | 'high' | 'medium' | 'low' | 'info';
  requestCount: number;
  detail: string;
  createdAt: string;
  updatedAt: string;
}

interface ProxyStatus {
  running: boolean;
  port: number;
  mode: 'electron' | 'browser';
  message: string;
}

interface ProjectSnapshot {
  version: 1;
  savedAt: string;
  projectName: string;
  scopeAllowlist: string[];
  exchanges: HttpExchange[];
  sessionProfiles?: SessionProfile[];
  selectedSessionProfileId?: string;
  browserLaunches?: BrowserLaunchResult[];
  httpsInspectionSettings?: HttpsInspectionSettings;
  safetyPolicy?: ProjectSafetyPolicy;
  auditEvents?: AuditEvent[];
  approvalRecords?: ApprovalRecord[];
  policyOverrides?: PolicyOverride[];
  signedAuditExports?: SignedAuditExport[];
  enterpriseTeamSync?: unknown;
  enterpriseOperatorIdentities?: unknown[];
  selectedEnterpriseOperatorId?: string;
  remoteAuditRetention?: unknown;
  organizerCollections?: unknown[];
  selectedOrganizerCollectionId?: string;
  selectedOrganizerItemId?: string;
  loggerCustomColumns?: unknown[];
  selectedLoggerCustomColumnId?: string;
  loggerCaptureControls?: unknown[];
  loggerCapturePresets?: unknown[];
  selectedLoggerCapturePresetId?: string;
  loggerArchiveMappingPresets?: unknown[];
  selectedLoggerArchiveMappingPresetId?: string;
  loggerArchiveMergeStrategy?: string;
  loggerArchiveImportHistory?: unknown[];
  selectedLoggerArchiveReviewId?: string;
  selectedLoggerArchiveConflictId?: string;
  matchReplaceRules?: MatchReplaceRule[];
  callbackPayloads?: CallbackPayload[];
  callbackInteractions?: CallbackInteraction[];
  callbackWorkspaces?: unknown[];
  selectedCallbackWorkspaceId?: string;
  callbackEvidencePackages?: unknown[];
  selectedCallbackEvidencePackageId?: string;
  callbackListenerProfiles?: unknown[];
  selectedCallbackListenerProfileId?: string;
  callbackSignedPollBatches?: unknown[];
  selectedCallbackSignedPollBatchId?: string;
  callbackCorrelationReplays?: unknown[];
  selectedCallbackCorrelationReplayId?: string;
  callbackReplayExecutionBatches?: unknown[];
  selectedCallbackReplayExecutionBatchId?: string;
  callbackLifecycleReviews?: unknown[];
  selectedCallbackLifecycleReviewId?: string;
  callbackCiHandoffPackages?: unknown[];
  selectedCallbackCiHandoffPackageId?: string;
  installedExtensions?: InstalledExtension[];
  extensionRuns?: ExtensionRun[];
  automationWorkflows?: AutomationWorkflow[];
  automationExecutions?: AutomationExecution[];
  exploitRuns?: ExploitRun[];
  exploitChainPlans?: unknown[];
  savedIntruderAttacks?: IntruderSavedAttack[];
  intruderPayloadGenerators?: IntruderPayloadGenerator[];
  intruderAttackQueue?: IntruderAttackQueueItem[];
  intruderComparisons?: unknown[];
  intruderPositionDiffs?: unknown[];
  intruderPromotedIssues?: unknown[];
  replayMatrixRuns?: ReplayMatrixRun[];
  pinnedRepeaterExchangeIds?: string[];
  savedRepeaterRequests?: RepeaterSavedRequest[];
  repeaterTabs?: RepeaterWorkspaceTab[];
  selectedRepeaterTabId?: string;
  repeaterBatchRuns?: RepeaterBatchRun[];
  replayTransportSettings?: ReplayTransportSettings;
  savedWebSocketReplays?: WebSocketSavedReplay[];
  webSocketFrameRewriteRules?: unknown[];
  webSocketConnectionNotebooks?: unknown[];
  webSocketPromotedIssues?: unknown[];
  webSocketFuzzRuns?: unknown[];
  webSocketTranscriptExports?: unknown[];
  aiRunHistory?: AiRunResult[];
  aiPromptTemplates?: AiPromptTemplate[];
  aiEvaluationBaselines?: unknown[];
  aiPromptComparisons?: unknown[];
  aiBenchmarkRuns?: unknown[];
  reportCustomTemplateName?: string;
  reportCustomTemplateBody?: string;
  reportLoggerArchiveReviewIds?: string[];
  issueTriageOverrides?: IssueTriageOverride[];
  scannerAuditQueue?: ScannerAuditQueueItem[];
}

interface SessionProfile {
  id: string;
  name: string;
  role: string;
  targetUrl: string;
  source: 'manual' | 'browser' | 'traffic' | 'ci';
  status: 'ready' | 'stale' | 'needs-refresh';
  headerText: string;
  cookieText: string;
  createdAt: string;
  updatedAt: string;
  lastUsedAt?: string;
  headerCount: number;
  cookieCount: number;
  notes: string;
  refreshUrl?: string;
  expiresAt?: string;
  lastRefreshAt?: string;
  refreshStatus?: 'never' | 'refreshed' | 'unchanged' | 'failed';
  refreshCookieCount?: number;
  refreshMessage?: string;
}

interface SessionProfileRefreshRequest {
  profile: SessionProfile;
  timeoutMs?: number;
}

interface SessionProfileRefreshResult {
  profile: SessionProfile;
  status: 'refreshed' | 'unchanged' | 'failed';
  statusCode?: number;
  setCookieCount: number;
  headerCount: number;
  cookieCount: number;
  message: string;
  rawResponseHead: string;
}

type ManagedBrowserFamily = 'auto' | 'chromium' | 'chrome' | 'edge' | 'firefox';

interface BrowserLaunchRequest {
  targetUrl: string;
  browser: ManagedBrowserFamily;
  proxyHost?: string;
  proxyPort: number;
  profileName?: string;
  ignoreCertificateErrors?: boolean;
}

interface BrowserLaunchResult {
  id: string;
  status: 'launched' | 'preview' | 'not-found' | 'error';
  browser: ManagedBrowserFamily | 'unknown';
  browserName: string;
  targetUrl: string;
  proxyHost: string;
  proxyPort: number;
  profilePath: string;
  command: string;
  args: string[];
  pid?: number;
  startedAt: string;
  message: string;
}

interface BrowserCookieExtractionRequest {
  targetUrl: string;
  browser: ManagedBrowserFamily;
  profilePath: string;
}

interface BrowserCookieEntry {
  name: string;
  value: string;
  domain: string;
  path: string;
  expiresAt?: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite?: string;
  source: 'chromium' | 'firefox';
}

interface BrowserCookieExtractionResult {
  id: string;
  status: 'complete' | 'partial' | 'empty' | 'unsupported' | 'error';
  targetUrl: string;
  browser: ManagedBrowserFamily | 'unknown';
  profilePath: string;
  cookieHeader: string;
  cookieCount: number;
  decryptedCount: number;
  encryptedCount: number;
  skippedCount: number;
  extractedAt: string;
  cookies: BrowserCookieEntry[];
  message: string;
}

interface ProjectFileArtifact {
  id: string;
  fileName: string;
  path: string;
  exportedAt: string;
  projectName: string;
  exchangeCount: number;
  scopeCount: number;
  sizeBytes: number;
  content?: string;
}

interface ProjectStoreStats {
  projectName: string;
  schemaVersion: 2;
  exchangeCount: number;
  scopeRuleCount: number;
  auditEventCount: number;
  projectSettingCount: number;
  sessionCookieCount: number;
  targetHostCount: number;
  targetRouteCount: number;
  parameterCount: number;
  callbackPayloadCount: number;
  callbackInteractionCount: number;
  repeaterTabCount: number;
  repeaterSendCount: number;
  webSocketConnectionCount: number;
  webSocketFrameCount: number;
  intruderAttackCount: number;
  intruderResultCount: number;
  scannerTaskCount: number;
  scannerFindingCount: number;
  scannerSuppressedFindingCount: number;
  issueCount: number;
  reportExportCount: number;
  automationRunCount: number;
  aiRunCount: number;
  extensionRunCount: number;
  blobCount: number;
  requestBytes: number;
  responseBytes: number;
  callbackBytes: number;
  repeaterRequestBytes: number;
  repeaterResponseBytes: number;
  webSocketPayloadBytes: number;
  intruderRequestBytes: number;
  intruderResponseBytes: number;
  reportBytes: number;
  aiPromptBytes: number;
  aiOutputBytes: number;
}

interface ProjectLifecycleAuditEvent {
  id: string;
  actor: string;
  action: string;
  targetRef: string;
  decision: 'allowed' | 'blocked' | 'completed' | 'updated';
  detail: string;
  createdAt: string;
  previousHash?: string;
  hash: string;
}

interface ProjectLifecycleCreateRequest {
  projectName?: string;
  projectId?: string;
  rootDir?: string;
  operator?: string;
  allowExternalRoot?: boolean;
}

interface ProjectLifecycleOpenRequest {
  rootDir: string;
  operator?: string;
  recover?: boolean;
  allowExternalRoot?: boolean;
}

interface ProjectLifecycleCloseRequest {
  operator?: string;
}

interface ProjectLifecycleBackupRequest {
  backupRootDir?: string;
  label?: string;
  operator?: string;
  allowExternalRoot?: boolean;
}

interface ProjectLifecycleState {
  kind: 'proxyforge-project-lifecycle-state';
  status: 'open' | 'closed';
  projectsRootDir: string;
  backupsRootDir: string;
  activeProject?: {
    projectId: string;
    projectName: string;
    rootDir: string;
    snapshotPath: string;
    manifest: {
      kind: 'proxyforge-project-store';
      schemaVersion: 2;
      projectId: string;
      projectName: string;
      createdAt: string;
      updatedAt: string;
    };
    stats: ProjectStoreStats;
    auditEvents: ProjectLifecycleAuditEvent[];
  };
  recentProjects: Array<{
    projectId: string;
    projectName: string;
    rootDir: string;
    openedAt: string;
  }>;
  requirements: {
    typedIpcContract: boolean;
    projectStoreBackbone: boolean;
    activeProjectRebindsRecorders: boolean;
    lifecycleAuditLedger: boolean;
    pathTraversalRejected: boolean;
    rawOperationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
}

interface ProjectLifecycleBackupResponse {
  kind: 'proxyforge-project-lifecycle-backup-response';
  backup: {
    kind: 'proxyforge-project-store-backup';
    schemaVersion: 1;
    projectId: string;
    projectName: string;
    sourceRootDir: string;
    backupRootDir: string;
    backupDir: string;
    label: string;
    createdAt: string;
    manifestPath: string;
    stats: ProjectStoreStats;
    content: string;
    requirements: {
      manifestCopied: boolean;
      databaseCopied: boolean;
      blobsCopied: boolean;
      recoveryJournalCopied: boolean;
      rawOperationalSecretsPreserved: boolean;
      reportPhaseOnlyRedaction: boolean;
    };
    secretHandling: string;
    reportRedactionBoundary: string;
  };
  state: ProjectLifecycleState;
}

type SessionInjectionMode = 'merge' | 'replace';
type SessionInjectionTarget = 'headers' | 'cookies' | 'headers-and-cookies';

interface RuntimeSessionProfile {
  id?: string;
  name?: string;
  headerText?: string;
  cookieText?: string;
}

interface SessionApplyOptions {
  mode?: SessionInjectionMode;
  target?: SessionInjectionTarget;
}

interface ReplayRequest {
  rawRequest: string;
  targetUrl: string;
  scopeAllowlist: string[];
  settings?: ReplayTransportSettings;
  sessionProfile?: RuntimeSessionProfile;
  sessionOptions?: SessionApplyOptions;
  oastPayloads?: CallbackPayload[];
  repeaterTabId?: string;
  repeaterTabName?: string;
  repeaterTabGroup?: string;
  repeaterSendId?: string;
  sourceExchangeId?: string;
  operator?: string;
  tags?: string[];
  notes?: string;
}

type ReplayRedirectMode = 'manual' | 'follow';
type ReplayConnectionMode = 'default' | 'close' | 'keep-alive';

interface ReplayTransportSettings {
  redirectMode: ReplayRedirectMode;
  maxRedirects: number;
  connectionMode: ReplayConnectionMode;
  timeoutMs: number;
}

type RepeaterSyncTechnique = 'single-connection' | 'last-byte' | 'single-packet' | 'pause-window';
type DesyncProbeRole = 'baseline' | 'poison' | 'victim' | 'warmup';

interface RepeaterDesyncProbeRequest {
  id: string;
  name: string;
  targetUrl: string;
  rawRequest: string;
  role: DesyncProbeRole;
}

interface RepeaterDesyncRuntimeRequest {
  planId?: string;
  targetUrl: string;
  requests: RepeaterDesyncProbeRequest[];
  scopeAllowlist: string[];
  timeoutMs?: number;
  syncTechnique?: RepeaterSyncTechnique;
  pauseMs?: number;
}

interface RepeaterDesyncRuntimeResponse {
  requestId: string;
  role: DesyncProbeRole;
  name: string;
  targetUrl: string;
  status?: number;
  statusLine?: string;
  bytes: number;
  startedAt: string;
  completedAt?: string;
  timingMs: number;
  headers: Record<string, string>;
  bodyPreview: string;
  rawRequest: string;
  rawResponse: string;
  error?: string;
}

interface RepeaterDesyncRuntimeResult {
  id: string;
  planId?: string;
  createdAt: string;
  targetUrl: string;
  protocol: 'HTTP/1.1';
  transport: 'single-connection' | 'parallel-last-byte' | 'parallel-single-packet';
  syncTechnique: RepeaterSyncTechnique;
  status: 'proof' | 'blocked' | 'error';
  requestCount: number;
  responseOrder: string[];
  jitterMs: number;
  raceWindowMs: number;
  releaseSkewMs?: number;
  connectionStrategy: string;
  timingNotes: string;
  responses: RepeaterDesyncRuntimeResponse[];
  rawTranscript: string;
  summary: string;
}

interface RepeaterSavedRequest {
  id: string;
  name: string;
  folder: string;
  targetUrl: string;
  rawRequest: string;
  createdAt: string;
  updatedAt: string;
  tags: string[];
}

interface RepeaterRequestSnapshot {
  id: string;
  tabId: string;
  label: string;
  targetUrl: string;
  rawRequest: string;
  createdAt: string;
  changedLines: number;
}

interface RepeaterRequestDiff {
  id: string;
  tabId: string;
  label: string;
  fromLabel: string;
  toLabel: string;
  targetUrl: string;
  createdAt: string;
  changedLines: number;
  addedLines: number;
  removedLines: number;
  preview: string[];
}

interface RepeaterWorkspaceTab {
  id: string;
  name: string;
  group: string;
  targetUrl: string;
  rawRequest: string;
  createdAt: string;
  updatedAt: string;
  dirty: boolean;
  sourceExchangeId?: string;
  lastStatus?: number;
  lastReplayId?: string;
  snapshots: RepeaterRequestSnapshot[];
  diffs: RepeaterRequestDiff[];
}

interface RepeaterBatchResult {
  tabId: string;
  tabName: string;
  targetUrl: string;
  status: number;
  length: number;
  timing: number;
  risk: 'critical' | 'high' | 'medium' | 'low' | 'info';
  notes: string;
  blocked: boolean;
  exchangeId?: string;
}

interface RepeaterBatchRun {
  id: string;
  startedAt: string;
  completedAt: string;
  totalRequests: number;
  blocked: boolean;
  message: string;
  results: RepeaterBatchResult[];
}

type IntruderAttackMode = 'sniper' | 'battering-ram' | 'pitchfork' | 'cluster-bomb';
type IntruderPayloadProcessor = 'url-encode' | 'base64' | 'uppercase' | 'lowercase';
type IntruderPayloadRuleId = 'case-variants' | 'url-recursive' | 'path-depth';

interface IntruderOastPayloadReference {
  id: string;
  token: string;
  endpoint: string;
  label?: string;
  protocol?: 'http' | 'dns' | 'smtp';
}

interface IntruderOastCorrelationSummary {
  payloadCount: number;
  interactionCount: number;
  correlatedResultCount: number;
  correlatedInteractionCount: number;
  pendingPayloadIds: string[];
}

interface IntruderAttackRequest {
  rawRequest: string;
  targetUrl: string;
  payloads: string[];
  payloadSets?: string[][];
  attackMode?: IntruderAttackMode;
  payloadProcessors?: IntruderPayloadProcessor[];
  payloadRules?: IntruderPayloadRuleId[];
  scopeAllowlist: string[];
  throttleMs: number;
  grepTerms: string[];
  extractRegexes?: string[];
  startOffset?: number;
  maxPayloadRequests?: number;
  resourcePoolName?: string;
  resourcePoolMaxConcurrent?: number;
  streamChunkSize?: number;
  resultWindowSize?: number;
  memoryBudgetBytes?: number;
  sessionProfile?: RuntimeSessionProfile;
  sessionOptions?: SessionApplyOptions;
  oastPayloads?: IntruderOastPayloadReference[];
}

interface IntruderAttackResult {
  id: string;
  payload: string;
  payloads: string[];
  attackMode: IntruderAttackMode;
  status: number;
  length: number;
  mime: string;
  timing: number;
  grepMatches: string[];
  extractMatches: string[];
  notes: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
  oastPayloadIds?: string[];
  callbackInteractionIds?: string[];
}

interface IntruderAttackSummary {
  id: string;
  targetUrl: string;
  startedAt: string;
  completedAt: string;
  attackMode: IntruderAttackMode;
  payloadPositions: number;
  totalRequests: number;
  blocked: boolean;
  message: string;
  results: IntruderAttackResult[];
  startOffset?: number;
  nextOffset?: number;
  hasMore?: boolean;
  payloadPlanCount?: number;
  payloadRuleCount?: number;
  resourcePoolName?: string;
  resourcePoolMaxConcurrent?: number;
  streaming?: IntruderStreamingSummary;
  oast?: IntruderOastCorrelationSummary;
}

interface IntruderStreamingSummary {
  chunkSize: number;
  chunkCount: number;
  completedChunks: number;
  resultWindowSize: number;
  retainedResultCount: number;
  droppedResultCount: number;
  firstRetainedOffset: number;
  lastRetainedOffset: number;
  estimatedMemoryBytes: number;
  memoryBudgetBytes?: number;
  memoryPressure: 'low' | 'medium' | 'high';
}

interface IntruderSavedAttack {
  id: string;
  name: string;
  targetUrl: string;
  rawRequest: string;
  attackMode: IntruderAttackMode;
  payloads: string;
  payloadSetTwo: string;
  payloadProcessors: IntruderPayloadProcessor[];
  payloadRules?: IntruderPayloadRuleId[];
  grepTerms: string;
  extractRegexes: string;
  throttleMs: number;
  createdAt: string;
  updatedAt: string;
}

interface IntruderPayloadGenerator {
  id: string;
  name: string;
  kind: 'wordlist' | 'number-range' | 'role-matrix' | 'case-mutation';
  description: string;
  payloads: string[];
  updatedAt: string;
}

interface IntruderAttackQueueItem {
  id: string;
  attackName: string;
  targetUrl: string;
  attackMode: IntruderAttackMode;
  status: 'queued' | 'running' | 'complete' | 'blocked' | 'paused';
  totalRequests: number;
  completedRequests: number;
  message: string;
  createdAt: string;
  updatedAt: string;
  latestSummaryId?: string;
  checkpointOffset?: number;
  resourcePoolName?: string;
  payloadRules?: IntruderPayloadRuleId[];
}

type ActiveScanCheckId =
  | 'security-headers'
  | 'cors-origin'
  | 'cache-key'
  | 'method-options'
  | 'authz-diff'
  | 'jwt-claims'
  | 'graphql-introspection'
  | 'oast-ssrf'
  | 'reflected-xss'
  | 'sql-injection'
  | 'path-traversal'
  | 'open-redirect'
  | 'command-injection';

interface ActiveScanRequest {
  rawRequest: string;
  targetUrl: string;
  scopeAllowlist: string[];
  checks: ActiveScanCheckId[];
  throttleMs: number;
  maxRequests: number;
  sessionProfile?: RuntimeSessionProfile;
  sessionOptions?: SessionApplyOptions;
  oastPayloadUrl?: string;
  oastPayloadToken?: string;
  oastPayloadId?: string;
}

interface ActiveScanFinding {
  id: string;
  checkId: ActiveScanCheckId;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'certain' | 'firm' | 'tentative';
  host: string;
  path: string;
  detail: string;
  remediation: string;
  evidenceExchangeId?: string;
  dedupeKey?: string;
  confidenceReason?: string;
}

interface ActiveScanSuppressedFinding {
  id: string;
  checkId: ActiveScanCheckId;
  title: string;
  host: string;
  path: string;
  evidenceExchangeId?: string;
  dedupeKey?: string;
  reason: string;
}

interface ActiveScanTuningMetadata {
  profile: 'browser-app-calibration';
  falsePositiveControls: string[];
  suppressedFindingCount: number;
  dedupedFindingCount: number;
  findingDedupeKeys: string[];
  calibrationNotes: string[];
}

interface ActiveScanSummary {
  id: string;
  targetUrl: string;
  startedAt: string;
  completedAt: string;
  totalRequests: number;
  blocked: boolean;
  message: string;
  findings: ActiveScanFinding[];
  suppressedFindings?: ActiveScanSuppressedFinding[];
  tuning?: ActiveScanTuningMetadata;
  exchanges: HttpExchange[];
}

type CrawlRouteSource = 'seed' | 'link' | 'script' | 'form' | 'redirect';
type CrawlInsertionPointType = 'query' | 'form' | 'path' | 'cookie' | 'header' | 'body' | 'json' | 'xml' | 'multipart' | 'graphql';

interface CrawlRequest {
  startUrl: string;
  scopeAllowlist: string[];
  maxDepth: number;
  maxPages: number;
  throttleMs: number;
  userAgent: string;
  includeForms: boolean;
  headers?: Record<string, string>;
}

interface CrawlInsertionPoint {
  id: string;
  routeId: string;
  type: CrawlInsertionPointType;
  name: string;
  method: string;
  url: string;
  evidence: string;
}

interface CrawlRoute {
  id: string;
  method: string;
  url: string;
  host: string;
  path: string;
  status: number;
  mime: string;
  depth: number;
  source: CrawlRouteSource;
  parentUrl?: string;
  title: string;
  discoveredAt: string;
  insertionPoints: string[];
}

interface CrawlSummary {
  id: string;
  startUrl: string;
  startedAt: string;
  completedAt: string;
  totalRequests: number;
  blocked: boolean;
  message: string;
  routes: CrawlRoute[];
  insertionPoints: CrawlInsertionPoint[];
  exchanges: HttpExchange[];
}

interface CrawlAuditRequest {
  scopeAllowlist: string[];
  checks: ActiveScanCheckId[];
  insertionPoints: CrawlInsertionPoint[];
  sessionHeaders?: Record<string, string>;
  throttleMs: number;
  maxInsertionPoints: number;
}

interface CrawlAuditSummary extends ActiveScanSummary {
  auditedInsertionPoints: number;
}

interface InterceptedRequest {
  id: string;
  direction: 'request' | 'response';
  method: string;
  host: string;
  path: string;
  url: string;
  status?: number;
  time: string;
  rawRequest: string;
  source: 'http' | 'https';
  tags: string[];
}

interface InterceptDecision {
  id: string;
  action: 'forward' | 'drop';
  rawRequest?: string;
}

interface InterceptStatus {
  enabled: boolean;
  responseEnabled: boolean;
  pendingCount: number;
  message: string;
}

interface MatchReplaceRule {
  id: string;
  name: string;
  enabled: boolean;
  direction: 'request' | 'response' | 'both';
  match: string;
  replace: string;
  isRegex: boolean;
  caseSensitive: boolean;
}

interface WebSocketMessage {
  id: string;
  connectionId: string;
  time: string;
  direction: 'client' | 'server';
  host: string;
  path: string;
  url: string;
  opcode: number;
  type: 'text' | 'binary' | 'close' | 'ping' | 'pong' | 'other';
  payload: string;
  payloadEncoding?: 'text' | 'hex' | 'base64';
  length: number;
  tags: string[];
}

interface WebSocketInterceptStatus {
  enabled: boolean;
  clientEnabled?: boolean;
  serverEnabled?: boolean;
  pendingCount: number;
  message: string;
}

interface WebSocketInterceptSettings {
  enabled: boolean;
  clientEnabled: boolean;
  serverEnabled: boolean;
}

interface WebSocketFrameDecision {
  id: string;
  action: 'forward' | 'drop';
  payload?: string;
  payloadEncoding?: 'text' | 'hex' | 'base64';
  opcode?: number;
}

interface WebSocketReplayRequest {
  connectionId: string;
  direction: 'client' | 'server';
  payload: string;
  payloadEncoding?: 'text' | 'hex' | 'base64';
  opcode?: number;
}

interface WebSocketSavedReplay {
  id: string;
  name: string;
  connectionId: string;
  direction: 'client' | 'server';
  host: string;
  path: string;
  url: string;
  opcode: number;
  type: WebSocketMessage['type'];
  payload: string;
  payloadEncoding?: 'text' | 'hex' | 'base64';
  createdAt: string;
  updatedAt: string;
  tags: string[];
}

interface WebSocketFrameRewriteRule {
  id: string;
  name: string;
  enabled: boolean;
  direction: 'client' | 'server' | 'both';
  frameType: WebSocketMessage['type'] | 'both';
  match: string;
  replace: string;
  isRegex: boolean;
  caseSensitive: boolean;
}

interface WebSocketTranscriptExport {
  id: string;
  title: string;
  fileName: string;
  filePath: string;
  createdAt: string;
  connectionId: string;
  host: string;
  path: string;
  format: 'markdown' | 'json';
  frameCount: number;
  fuzzRunIds: string[];
  stateDiffIds: string[];
  closeCodeCount: number;
  sizeBytes: number;
  content: string;
}

interface CertificateAuthorityStatus {
  ready: boolean;
  rootCertificatePath: string;
  projectId: string;
  projectLabel: string;
  projectCertificateDir: string;
  fingerprintSha256?: string;
  validUntil?: string;
  hostCertificateCount: number;
  lastRotatedAt?: string;
  revokedAt?: string;
  message: string;
}

interface CertificateAuthorityExport {
  pem: string;
  path: string;
  fingerprintSha256?: string;
}

interface HttpsInspectionStatus {
  enabled: boolean;
  upstreamTlsMode: 'strict' | 'relaxed';
  message: string;
}

type AiProviderId = 'codex' | 'claude' | 'local';
type AiTaskKind = 'triage' | 'replay-plan' | 'exploit-review' | 'report-draft';

interface AiContextExchange {
  method: string;
  host: string;
  path: string;
  status: number;
  risk: string;
  notes: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
}

interface AiContextIssue {
  title: string;
  severity: string;
  host: string;
  path: string;
  detail: string;
  remediation: string;
}

interface AiContextBundle {
  projectName: string;
  scopeAllowlist: string[];
  taskHint: string;
  exchanges: AiContextExchange[];
  issues: AiContextIssue[];
}

interface AiProviderConfig {
  id: AiProviderId;
  label: string;
  mode: 'cli' | 'http';
  enabled: boolean;
  model: string;
  command?: string;
  args?: string[];
  endpoint?: string;
  apiKeyEnv?: string;
  timeoutMs: number;
  inputCostPerMillionTokens?: number;
  outputCostPerMillionTokens?: number;
}

interface AiProviderRuntime extends AiProviderConfig {
  available: boolean;
  secretPresent: boolean;
  status: 'configured' | 'needs-key' | 'offline';
  message: string;
}

interface AiRunRequest {
  providerId: AiProviderId;
  task: AiTaskKind;
  prompt: string;
  context: AiContextBundle;
}

interface AiRunUsage {
  promptTokens: number;
  completionTokens: number;
  totalTokens: number;
  estimatedCostUsd: number;
  latencyMs: number;
  source?: 'provider' | 'estimated' | 'browser-preview';
}

interface AiRunStreamEvent {
  id: string;
  at: string;
  source: 'prompt' | 'stdout' | 'stderr' | 'http' | 'fallback' | 'complete';
  text: string;
}

interface AiPromptEvaluationCheck {
  label: string;
  status: 'ready' | 'warning' | 'blocked';
  detail: string;
}

interface AiPromptEvaluation {
  score: number;
  providerId: AiProviderId;
  model: string;
  checks: AiPromptEvaluationCheck[];
  recommendations: string[];
}

type AiSuggestedActionKind =
  | 'stage-repeater'
  | 'stage-replay-matrix'
  | 'queue-active-scan'
  | 'open-exploit-review'
  | 'record-automation'
  | 'draft-report';

interface AiSuggestedAction {
  id: string;
  kind: AiSuggestedActionKind;
  label: string;
  detail: string;
  target: string;
  priority: 'critical' | 'high' | 'medium' | 'low' | 'info';
}

interface AiRunResult {
  id: string;
  providerId: AiProviderId;
  task: AiTaskKind;
  status: 'complete' | 'unavailable' | 'error';
  model: string;
  startedAt: string;
  completedAt: string;
  summary: string;
  output: string;
  evidenceCount: number;
  command?: string;
  providerLabel?: string;
  prompt?: string;
  contextDigest?: string;
  usage?: AiRunUsage;
  streamEvents?: AiRunStreamEvent[];
  promptEvaluation?: AiPromptEvaluation;
  suggestedActions?: AiSuggestedAction[];
}

interface AiPromptTemplate {
  id: string;
  task: AiTaskKind;
  title: string;
  prompt: string;
  updatedAt: string;
}

type ReportFormat = 'markdown' | 'html' | 'json' | 'bundle' | 'pdf';
type ReportSection = 'executive' | 'technical' | 'remediation' | 'evidence' | 'appendix';
type ReportTemplateId = 'executive-board' | 'technical-remediation' | 'evidence-bundle' | 'custom';

interface ReportExportRequest {
  projectName: string;
  scopeAllowlist: string[];
  issues: Array<{
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    host: string;
    path: string;
    confidence: 'certain' | 'firm' | 'tentative';
    status: 'open' | 'triaged' | 'false-positive' | 'fixed';
    detail: string;
    remediation: string;
    assignee?: string;
    triageNote?: string;
    lastTriagedAt?: string;
  }>;
  exchanges: HttpExchange[];
  format: ReportFormat;
  sections: ReportSection[];
  templateId?: ReportTemplateId;
  customTemplateName?: string;
  customTemplateBody?: string;
  brandName?: string;
  preparedFor?: string;
  engagementId?: string;
  signEvidenceBundle?: boolean;
  signingKeyId?: string;
  signingSecret?: string;
  signerName?: string;
  loggerImportJobs?: unknown[];
  targetSiteMapEvidenceAttachments?: unknown[];
  proxyHistoryEvidenceAttachments?: unknown[];
  scannerActiveScanEvidencePackages?: unknown[];
  governanceAttestation?: unknown;
}

interface ReportArtifact {
  id: string;
  format: ReportFormat;
  fileName: string;
  path: string;
  generatedAt: string;
  issueCount: number;
  exchangeCount: number;
  content: string;
}

type SequencerSampleSource = 'manual' | 'traffic' | 'browser-preview';
type SequencerVerdict = 'strong' | 'watch' | 'weak';
type SequencerReliability = 'rough' | 'indicative' | 'reliable' | 'fips-ready';

interface SequencerSampleRequest {
  label: string;
  samples: string[];
  source: SequencerSampleSource;
}

interface SequencerCharacterSet {
  name: string;
  size: number;
  observed: number;
}

interface SequencerFinding {
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  detail: string;
}

interface SequencerReliabilitySummary {
  level: SequencerReliability;
  sampleTarget: number;
  maxSupportedSamples: number;
  fipsSampleTarget: number;
  message: string;
}

interface SequencerEntropySignificancePoint {
  significance: string;
  effectiveEntropyBits: number;
}

interface SequencerPositionStat {
  index: number;
  samplesObserved: number;
  observedCharacters: number;
  maxEntropyBits: number;
  shannonBits: number;
  dominantCharacter: string;
  dominantRate: number;
  transitionRepeatRate: number;
  bitStart: number;
  bitLength: number;
}

interface SequencerBitStat {
  index: number;
  sourcePosition: number;
  ones: number;
  zeros: number;
  monobitPValue: number;
  pokerScore: number;
  runCount: number;
  passedFips: boolean;
}

interface SequencerStatisticalTest {
  id: string;
  name: string;
  level: 'summary' | 'character' | 'bit' | 'fips';
  significance: string;
  passed: boolean;
  score: number;
  detail: string;
  failedPositions: number[];
}

interface SequencerAnalysisResult {
  id: string;
  label: string;
  source: SequencerSampleSource;
  generatedAt: string;
  sampleCount: number;
  uniqueCount: number;
  duplicateCount: number;
  minLength: number;
  maxLength: number;
  averageLength: number;
  shannonBitsPerChar: number;
  estimatedEntropyBits: number;
  collisionRate: number;
  serialCorrelation: number;
  monobitRatio: number;
  repeatedPrefixLength: number;
  characterSets: SequencerCharacterSet[];
  reliability: SequencerReliabilitySummary;
  entropyBySignificance: SequencerEntropySignificancePoint[];
  positionStats: SequencerPositionStat[];
  bitStats: SequencerBitStat[];
  statisticalTests: SequencerStatisticalTest[];
  verdict: SequencerVerdict;
  findings: SequencerFinding[];
}

contextBridge.exposeInMainWorld('proxyForge', {
  startProxy: (port: number): Promise<ProxyStatus> => ipcRenderer.invoke('proxy:start', port),
  stopProxy: (): Promise<ProxyStatus> => ipcRenderer.invoke('proxy:stop'),
  getProxyStatus: (): Promise<ProxyStatus> => ipcRenderer.invoke('proxy:status'),
  launchBrowser: (request: BrowserLaunchRequest): Promise<BrowserLaunchResult> => ipcRenderer.invoke('browser:launch', request),
  extractBrowserCookies: (request: BrowserCookieExtractionRequest): Promise<BrowserCookieExtractionResult> => ipcRenderer.invoke('browser:cookies', request),
  refreshSessionProfile: (request: SessionProfileRefreshRequest): Promise<SessionProfileRefreshResult> => ipcRenderer.invoke('session-profile:refresh', request),
  createProject: (request: ProjectLifecycleCreateRequest): Promise<ProjectLifecycleState> => ipcRenderer.invoke('project:create', request),
  openProject: (request: ProjectLifecycleOpenRequest): Promise<ProjectLifecycleState> => ipcRenderer.invoke('project:open', request),
  closeProject: (request?: ProjectLifecycleCloseRequest): Promise<ProjectLifecycleState> => ipcRenderer.invoke('project:close', request),
  getProjectLifecycle: (): Promise<ProjectLifecycleState> => ipcRenderer.invoke('project:stats'),
  backupProject: (request?: ProjectLifecycleBackupRequest): Promise<ProjectLifecycleBackupResponse> => ipcRenderer.invoke('project:backup', request),
  loadProject: (): Promise<ProjectSnapshot | null> => ipcRenderer.invoke('project:load'),
  saveProject: (snapshot: ProjectSnapshot): Promise<ProjectSnapshot> => ipcRenderer.invoke('project:save', snapshot),
  resetProject: (): Promise<void> => ipcRenderer.invoke('project:reset'),
  exportProjectFile: (snapshot: ProjectSnapshot): Promise<ProjectFileArtifact | null> => ipcRenderer.invoke('project:export-file', snapshot),
  importProjectFile: (content?: string): Promise<ProjectSnapshot | null> => ipcRenderer.invoke('project:import-file', content),
  exportSignedAuditPackage: (artifact: SignedAuditExport): Promise<SignedAuditExport | null> => ipcRenderer.invoke('audit:export-file', artifact),
  exportWebSocketTranscript: (artifact: WebSocketTranscriptExport): Promise<WebSocketTranscriptExport | null> => ipcRenderer.invoke('websocket-transcript:export-file', artifact),
  importWebSocketTranscript: (content?: string): Promise<WebSocketTranscriptExport | null> => ipcRenderer.invoke('websocket-transcript:import-file', content),
  pushEnterprisePolicy: (request: EnterprisePolicyTransportRuntimeRequest): Promise<EnterprisePolicyTransportRuntimeResult> => ipcRenderer.invoke('enterprise-policy:push', request),
  pullEnterprisePolicy: (request: EnterprisePolicyTransportRuntimeRequest): Promise<EnterprisePolicyTransportRuntimeResult> => ipcRenderer.invoke('enterprise-policy:pull', request),
  replayRequest: (request: ReplayRequest): Promise<HttpExchange> => ipcRenderer.invoke('repeater:send', request),
  runRepeaterDesyncProbe: (request: RepeaterDesyncRuntimeRequest): Promise<RepeaterDesyncRuntimeResult> => ipcRenderer.invoke('repeater:desync-probe', request),
  runRepeaterParallelRace: (request: RepeaterDesyncRuntimeRequest): Promise<RepeaterDesyncRuntimeResult> => ipcRenderer.invoke('repeater:parallel-race', request),
  runIntruderAttack: (request: IntruderAttackRequest): Promise<IntruderAttackSummary> => ipcRenderer.invoke('intruder:run', request),
  runCrawl: (request: CrawlRequest): Promise<CrawlSummary> => ipcRenderer.invoke('crawler:run', request),
  runCrawlAudit: (request: CrawlAuditRequest): Promise<CrawlAuditSummary> => ipcRenderer.invoke('scanner:run-crawl-audit', request),
  runActiveScan: (request: ActiveScanRequest): Promise<ActiveScanSummary> => ipcRenderer.invoke('scanner:run-active', request),
  getInterceptStatus: (): Promise<InterceptStatus> => ipcRenderer.invoke('intercept:status'),
  setIntercept: (enabled: boolean): Promise<InterceptStatus> => ipcRenderer.invoke('intercept:set', enabled),
  setResponseIntercept: (enabled: boolean): Promise<InterceptStatus> => ipcRenderer.invoke('intercept:set-response', enabled),
  listIntercepts: (): Promise<InterceptedRequest[]> => ipcRenderer.invoke('intercept:list'),
  resolveIntercept: (decision: InterceptDecision): Promise<InterceptStatus> => ipcRenderer.invoke('intercept:resolve', decision),
  getWebSocketInterceptStatus: (): Promise<WebSocketInterceptStatus> => ipcRenderer.invoke('websocket-intercept:status'),
  setWebSocketIntercept: (settings: boolean | WebSocketInterceptSettings): Promise<WebSocketInterceptStatus> => ipcRenderer.invoke('websocket-intercept:set', settings),
  listWebSocketIntercepts: (): Promise<WebSocketMessage[]> => ipcRenderer.invoke('websocket-intercept:list'),
  resolveWebSocketIntercept: (decision: WebSocketFrameDecision): Promise<WebSocketInterceptStatus> => ipcRenderer.invoke('websocket-intercept:resolve', decision),
  replayWebSocketFrame: (request: WebSocketReplayRequest): Promise<WebSocketMessage> => ipcRenderer.invoke('websocket:replay', request),
  getMatchReplaceRules: (): Promise<MatchReplaceRule[]> => ipcRenderer.invoke('match-replace:list'),
  setMatchReplaceRules: (rules: MatchReplaceRule[]): Promise<MatchReplaceRule[]> => ipcRenderer.invoke('match-replace:set', rules),
  getWebSocketFrameRewriteRules: (): Promise<WebSocketFrameRewriteRule[]> => ipcRenderer.invoke('websocket-rewrite:list'),
  setWebSocketFrameRewriteRules: (rules: WebSocketFrameRewriteRule[]): Promise<WebSocketFrameRewriteRule[]> => ipcRenderer.invoke('websocket-rewrite:set', rules),
  setCertificateProject: (projectName: string): Promise<CertificateAuthorityStatus> => ipcRenderer.invoke('cert:set-project', projectName),
  getCertificateStatus: (): Promise<CertificateAuthorityStatus> => ipcRenderer.invoke('cert:status'),
  ensureRootCertificate: (): Promise<CertificateAuthorityStatus> => ipcRenderer.invoke('cert:ensure-root'),
  exportRootCertificate: (): Promise<CertificateAuthorityExport> => ipcRenderer.invoke('cert:export-root'),
  rotateRootCertificate: (): Promise<CertificateAuthorityStatus> => ipcRenderer.invoke('cert:rotate-root'),
  revokeRootCertificate: (): Promise<CertificateAuthorityStatus> => ipcRenderer.invoke('cert:revoke-root'),
  getHttpsInspectionStatus: (): Promise<HttpsInspectionStatus> => ipcRenderer.invoke('https-inspection:status'),
  setHttpsInspection: (enabled: boolean): Promise<HttpsInspectionStatus> => ipcRenderer.invoke('https-inspection:set', enabled),
  setUpstreamTlsValidation: (mode: 'strict' | 'relaxed'): Promise<HttpsInspectionStatus> => ipcRenderer.invoke('https-inspection:set-upstream-tls', mode),
  startCallbackListener: (profile: CallbackListenerProfile, payloads: CallbackPayload[]): Promise<CallbackListenerRuntimeStatus> => ipcRenderer.invoke('callback-listener:start', { profile, payloads }),
  stopCallbackListener: (profileId: string): Promise<CallbackListenerRuntimeStatus> => ipcRenderer.invoke('callback-listener:stop', profileId),
  pollCallbackListener: (profileId: string, payloads: CallbackPayload[]): Promise<CallbackListenerPollResult> => ipcRenderer.invoke('callback-listener:poll', { profileId, payloads }),
  getCallbackListenerStatus: (profileId: string): Promise<CallbackListenerRuntimeStatus> => ipcRenderer.invoke('callback-listener:status', profileId),
  getAiProviders: (): Promise<AiProviderRuntime[]> => ipcRenderer.invoke('ai:providers'),
  setAiProviders: (configs: AiProviderConfig[]): Promise<AiProviderRuntime[]> => ipcRenderer.invoke('ai:providers:set', configs),
  runAiTask: (request: AiRunRequest): Promise<AiRunResult> => ipcRenderer.invoke('ai:run', request),
  recordAutomationRun: (execution: AutomationExecution): Promise<ProjectRunStatePersistResult> => ipcRenderer.invoke('run-state:automation', execution),
  recordExtensionRun: (run: ExtensionRun): Promise<ProjectRunStatePersistResult> => ipcRenderer.invoke('run-state:extension', run),
  exportReport: (request: ReportExportRequest): Promise<ReportArtifact> => ipcRenderer.invoke('report:export', request),
  analyzeSequencerSamples: (request: SequencerSampleRequest): Promise<SequencerAnalysisResult> => ipcRenderer.invoke('sequencer:analyze', request),
  onInterceptQueue: (handler: (pending: InterceptedRequest[]) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, pending: InterceptedRequest[]) => handler(pending);
    ipcRenderer.on('proxy:intercepts', listener);
    return () => ipcRenderer.removeListener('proxy:intercepts', listener);
  },
  onExchange: (handler: (exchange: HttpExchange) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, exchange: HttpExchange) => handler(exchange);
    ipcRenderer.on('proxy:exchange', listener);
    return () => ipcRenderer.removeListener('proxy:exchange', listener);
  },
  onWebSocketMessage: (handler: (message: WebSocketMessage) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, message: WebSocketMessage) => handler(message);
    ipcRenderer.on('proxy:websocket-message', listener);
    return () => ipcRenderer.removeListener('proxy:websocket-message', listener);
  },
  onWebSocketInterceptQueue: (handler: (pending: WebSocketMessage[]) => void) => {
    const listener = (_event: Electron.IpcRendererEvent, pending: WebSocketMessage[]) => handler(pending);
    ipcRenderer.on('proxy:websocket-intercepts', listener);
    return () => ipcRenderer.removeListener('proxy:websocket-intercepts', listener);
  },
});
