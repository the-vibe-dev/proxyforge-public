import { app, BrowserWindow, dialog, ipcMain, protocol, session, type IpcMainInvokeEvent, type OpenDialogOptions, type SaveDialogOptions } from 'electron';
import fs from 'node:fs/promises';
import path from 'node:path';
import { AiEngine, type AiProviderConfig, type AiRunRequest, type AiRunResult, type AiTaskKind } from './aiEngine';
import { launchManagedBrowser, type BrowserLaunchRequest, type BrowserLaunchResult } from './browserLauncher';
import { extractBrowserCookies, type BrowserCookieExtractionRequest } from './browserCookies';
import { CertificateAuthorityManager } from './certManager';
import { CallbackListenerService, type CallbackListenerProfile as RuntimeCallbackListenerProfile, type CallbackPayload as RuntimeCallbackPayload } from './callbackListenerService';
import { CrawlEngine, type CrawlRequest } from './crawlEngine';
import {
  EnterprisePolicyTransportService,
  type EnterprisePolicyPullRequest,
  type EnterprisePolicyPushRequest,
} from './enterprisePolicyTransport';
import {
  ProxyEngine,
  type ActiveScanRequest,
  type CrawlAuditRequest,
  type InterceptDecision,
  type IntruderAttackRequest,
  type MatchReplaceRule,
  type ReplayRequest,
  type WebSocketFrameDecision,
  type WebSocketFrameRewriteRule,
  type WebSocketMessage,
  type WebSocketInterceptSettings,
  type WebSocketReplayRequest,
} from './proxyEngine';
import {
  RepeaterDesyncRaceEngine,
  type RepeaterDesyncRaceRuntimeRequest,
} from './repeaterDesyncRaceEngine';
import { parseProjectSnapshotContent as parseProjectSnapshotContentShared } from './projectSnapshotEngine';
import { ProjectStoreCallbackRecorder, ProjectStoreIntruderRecorder, ProjectStoreProxyRecorder, ProjectStoreRepeaterRecorder, ProjectStoreReportRecorder, ProjectStoreScannerRecorder, ProjectStoreWebSocketRecorder } from './projectStore';
import {
  ProjectStoreRunStateRecorder,
  type RuntimeAutomationExecution,
  type RuntimeExtensionRun,
} from './runStatePersistence';
import {
  guardedIpcHandler,
  ipcContracts,
  type IpcGuardAuditEvent,
} from './ipcContracts';
import {
  ProjectLifecycleService,
  projectSnapshotPath,
  type ActiveProjectReference,
  type ProjectLifecycleBackupRequest,
  type ProjectLifecycleCreateRequest,
  type ProjectLifecycleOpenRequest,
  type ProjectLifecycleCloseRequest,
} from './services/projectLifecycleService';
import { ReportEngine, type ReportExportRequest } from './reportEngine';
import { SequencerEngine, type SequencerSampleRequest } from './sequencerEngine';
import { refreshSessionProfile, type SessionProfileRefreshRequest } from './sessionProfileRefresh';

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
  ciProvider?: AutomationCiProvider;
  ciConfig: string;
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

type ReplayRedirectMode = 'manual' | 'follow';
type ReplayConnectionMode = 'default' | 'close' | 'keep-alive';

interface ReplayTransportSettings {
  redirectMode: ReplayRedirectMode;
  maxRedirects: number;
  connectionMode: ReplayConnectionMode;
  timeoutMs: number;
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

interface IntruderSavedAttack {
  id: string;
  name: string;
  targetUrl: string;
  rawRequest: string;
  attackMode: IntruderAttackMode;
  payloads: string;
  payloadSetTwo: string;
  payloadProcessors: IntruderPayloadProcessor[];
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

interface AiPromptTemplate {
  id: string;
  task: AiTaskKind;
  title: string;
  prompt: string;
  updatedAt: string;
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
  savedWebSocketReplays?: unknown[];
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

let mainWindow: BrowserWindow | null = null;
let certificateAuthority: CertificateAuthorityManager | null = null;
let proxyEngine: ProxyEngine | null = null;
let aiEngine: AiEngine | null = null;
let reportEngine: ReportEngine | null = null;
let crawlEngine: CrawlEngine | null = null;
let sequencerEngine: SequencerEngine | null = null;
let callbackListenerService: CallbackListenerService | null = null;
let repeaterDesyncRaceEngine: RepeaterDesyncRaceEngine | null = null;
let enterprisePolicyTransportService: EnterprisePolicyTransportService | null = null;
let projectStoreProxyRecorder: ProjectStoreProxyRecorder | null = null;
let projectStoreCallbackRecorder: ProjectStoreCallbackRecorder | null = null;
let projectStoreRepeaterRecorder: ProjectStoreRepeaterRecorder | null = null;
let projectStoreIntruderRecorder: ProjectStoreIntruderRecorder | null = null;
let projectStoreScannerRecorder: ProjectStoreScannerRecorder | null = null;
let projectStoreReportRecorder: ProjectStoreReportRecorder | null = null;
let projectStoreWebSocketRecorder: ProjectStoreWebSocketRecorder | null = null;
let projectStoreRunStateRecorder: ProjectStoreRunStateRecorder | null = null;
let projectLifecycleService: ProjectLifecycleService | null = null;
let authorizedRendererUrl: string | null = null;

const PACKAGED_RENDERER_PROTOCOL = 'proxyforge';
const PACKAGED_RENDERER_HOST = 'app';
const PACKAGED_RENDERER_URL = `${PACKAGED_RENDERER_PROTOCOL}://${PACKAGED_RENDERER_HOST}/index.html`;

protocol.registerSchemesAsPrivileged([
  {
    scheme: PACKAGED_RENDERER_PROTOCOL,
    privileges: {
      standard: true,
      secure: true,
      supportFetchAPI: true,
    },
  },
]);

const DEFAULT_PROJECT_NAME = 'Default ProxyForge Project';
const DEFAULT_PROJECT_ID = 'default-proxyforge-project';
const SECURE_DIR_MODE = 0o700;
const SECURE_FILE_MODE = 0o600;
const MAX_PROJECT_IMPORT_BYTES = 25 * 1024 * 1024;

function services() {
  if (!certificateAuthority) certificateAuthority = certificateAuthorityManager();
  if (!projectStoreProxyRecorder) {
    const project = currentProjectRuntime();
    projectStoreProxyRecorder = new ProjectStoreProxyRecorder(project.rootDir, {
      projectName: project.projectName,
      projectId: project.projectId,
    });
  }
  if (!projectStoreCallbackRecorder) {
    const project = currentProjectRuntime();
    projectStoreCallbackRecorder = new ProjectStoreCallbackRecorder(project.rootDir, {
      projectName: project.projectName,
      projectId: project.projectId,
    });
  }
  if (!projectStoreRepeaterRecorder) {
    const project = currentProjectRuntime();
    projectStoreRepeaterRecorder = new ProjectStoreRepeaterRecorder(project.rootDir, {
      projectName: project.projectName,
      projectId: project.projectId,
    });
  }
  if (!projectStoreReportRecorder) {
    const project = currentProjectRuntime();
    projectStoreReportRecorder = new ProjectStoreReportRecorder(project.rootDir, {
      projectName: project.projectName,
      projectId: project.projectId,
    });
  }
  if (!projectStoreIntruderRecorder) {
    const project = currentProjectRuntime();
    projectStoreIntruderRecorder = new ProjectStoreIntruderRecorder(project.rootDir, {
      projectName: project.projectName,
      projectId: project.projectId,
    });
  }
  if (!projectStoreScannerRecorder) {
    const project = currentProjectRuntime();
    projectStoreScannerRecorder = new ProjectStoreScannerRecorder(project.rootDir, {
      projectName: project.projectName,
      projectId: project.projectId,
    });
  }
  if (!projectStoreWebSocketRecorder) {
    const project = currentProjectRuntime();
    projectStoreWebSocketRecorder = new ProjectStoreWebSocketRecorder(project.rootDir, {
      projectName: project.projectName,
      projectId: project.projectId,
    });
  }
  if (!projectStoreRunStateRecorder) {
    const project = currentProjectRuntime();
    projectStoreRunStateRecorder = new ProjectStoreRunStateRecorder(project.rootDir, {
      projectName: project.projectName,
      projectId: project.projectId,
    });
  }
  if (!proxyEngine) {
    proxyEngine = new ProxyEngine((exchange) => {
      projectStoreProxyRecorder?.capture(exchange);
      mainWindow?.webContents.send('proxy:exchange', exchange);
    }, certificateAuthority, (pending) => {
      mainWindow?.webContents.send('proxy:intercepts', pending);
    }, (message: WebSocketMessage) => {
      projectStoreWebSocketRecorder?.capture(message);
      mainWindow?.webContents.send('proxy:websocket-message', message);
    }, (pending: WebSocketMessage[]) => {
      mainWindow?.webContents.send('proxy:websocket-intercepts', pending);
    });
  }
  if (!aiEngine) {
    aiEngine = new AiEngine(path.join(app.getPath('userData'), 'ai', 'providers.json'));
  }
  if (!reportEngine) {
    reportEngine = new ReportEngine(path.join(app.getPath('userData'), 'reports'), renderReportPdf);
  }
  if (!crawlEngine) {
    crawlEngine = new CrawlEngine({ upstreamTlsMode: () => proxyEngine?.getUpstreamTlsValidation() ?? 'strict' });
  }
  if (!sequencerEngine) {
    sequencerEngine = new SequencerEngine();
  }
  if (!callbackListenerService) {
    callbackListenerService = new CallbackListenerService({
      payloads: (_profile, payloads) => projectStoreCallbackRecorder?.capturePayloads(payloads),
      interaction: (_profile, interaction) => projectStoreCallbackRecorder?.captureInteraction(interaction),
    });
  }
  if (!repeaterDesyncRaceEngine) {
    repeaterDesyncRaceEngine = new RepeaterDesyncRaceEngine({ upstreamTlsMode: () => proxyEngine?.getUpstreamTlsValidation() ?? 'strict' });
  }
  if (!enterprisePolicyTransportService) {
    enterprisePolicyTransportService = new EnterprisePolicyTransportService();
  }
  return { certificateAuthority, proxyEngine, aiEngine, reportEngine, crawlEngine, sequencerEngine, callbackListenerService, repeaterDesyncRaceEngine, enterprisePolicyTransportService };
}

async function renderReportPdf(html: string) {
  const pdfWindow = new BrowserWindow({
    show: false,
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  try {
    await pdfWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`);
    await pdfWindow.webContents.executeJavaScript('document.fonts ? document.fonts.ready.then(() => true) : true');
    const pdf = await pdfWindow.webContents.printToPDF({
      printBackground: true,
      pageSize: 'A4',
    });
    return Buffer.from(pdf);
  } finally {
    pdfWindow.destroy();
  }
}

function createWindow() {
  const releaseSmoke = process.env.PROXYFORGE_RELEASE_SMOKE === '1';
  const devServerUrl = app.isPackaged ? undefined : process.env.VITE_DEV_SERVER_URL;
  authorizedRendererUrl = devServerUrl || PACKAGED_RENDERER_URL;
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 920,
    show: !releaseSmoke,
    minWidth: 1040,
    minHeight: 720,
    backgroundColor: '#101211',
    title: 'ProxyForge',
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, url) => {
    if (!isAuthorizedRendererUrl(url)) {
      event.preventDefault();
    }
  });
  session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));

  let loadPromise: Promise<void>;
  if (devServerUrl) {
    loadPromise = mainWindow.loadURL(devServerUrl);
    if (!releaseSmoke) mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    loadPromise = mainWindow.loadURL(PACKAGED_RENDERER_URL);
  }

  if (releaseSmoke) {
    const smokeStartedAt = Date.now();
    loadPromise.then(() => {
      const result = {
        kind: 'proxyforge-release-smoke',
        status: 'passed',
        appName: app.getName(),
        version: app.getVersion(),
        platform: process.platform,
        arch: process.arch,
        electron: process.versions.electron,
        node: process.versions.node,
        rendererUrl: mainWindow?.webContents.getURL() ?? '',
        userDataPath: app.getPath('userData'),
        durationMs: Date.now() - smokeStartedAt,
      };
      process.stdout.write(`PROXYFORGE_RELEASE_SMOKE ${JSON.stringify(result)}\n`);
      setTimeout(() => app.quit(), 100);
    }).catch((error) => {
      const result = {
        kind: 'proxyforge-release-smoke',
        status: 'failed',
        appName: app.getName(),
        version: app.getVersion(),
        platform: process.platform,
        arch: process.arch,
        error: error instanceof Error ? error.message : String(error),
        durationMs: Date.now() - smokeStartedAt,
      };
      process.stdout.write(`PROXYFORGE_RELEASE_SMOKE ${JSON.stringify(result)}\n`);
      app.exit(1);
    });
  }

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function registerPackagedRendererProtocol() {
  if (!app.isPackaged) return;
  protocol.registerFileProtocol(PACKAGED_RENDERER_PROTOCOL, (request, callback) => {
    const targetPath = resolvePackagedRendererPath(request.url);
    if (!targetPath) {
      callback({ error: -6 });
      return;
    }
    callback({ path: targetPath });
  });
}

function resolvePackagedRendererPath(requestUrl: string): string | null {
  const parsed = parseUrl(requestUrl);
  if (!parsed || parsed.protocol !== `${PACKAGED_RENDERER_PROTOCOL}:` || parsed.hostname !== PACKAGED_RENDERER_HOST) return null;
  const rendererRoot = path.resolve(__dirname, '../dist');
  const rawPathname = parsed.pathname === '/' ? '/index.html' : parsed.pathname;
  let decodedPathname: string;
  try {
    decodedPathname = decodeURIComponent(rawPathname);
  } catch {
    return null;
  }
  const relativePath = path.normalize(decodedPathname.replace(/^\/+/, ''));
  if (!relativePath || relativePath.startsWith('..') || path.isAbsolute(relativePath)) return null;
  const targetPath = path.resolve(rendererRoot, relativePath);
  if (targetPath !== rendererRoot && !targetPath.startsWith(`${rendererRoot}${path.sep}`)) return null;
  return targetPath;
}

function isAuthorizedRendererUrl(value: string): boolean {
  if (!authorizedRendererUrl) return false;
  if (!app.isPackaged && process.env.VITE_DEV_SERVER_URL) {
    const expected = parseUrl(authorizedRendererUrl);
    const candidate = parseUrl(value);
    return Boolean(expected && candidate && candidate.origin === expected.origin && isLoopbackHost(candidate.hostname));
  }
  return value === authorizedRendererUrl;
}

function parseUrl(value: string): URL | null {
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function safeOrigin(value: string): string | null {
  return parseUrl(value)?.origin ?? null;
}

function isLoopbackHost(hostname: string) {
  return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '[::1]';
}

function assertAuthorizedIpcSender(channel: string, event: IpcMainInvokeEvent) {
  if (!mainWindow || event.sender !== mainWindow.webContents) {
    throw new Error(`Unauthorized IPC sender for ${channel}`);
  }
  if (!event.senderFrame || event.senderFrame !== event.sender.mainFrame) {
    throw new Error(`Unauthorized IPC frame for ${channel}`);
  }
  if (!isAuthorizedRendererUrl(event.senderFrame.url)) {
    throw new Error(`Unauthorized IPC origin for ${channel}`);
  }
}

function secureIpcHandle<T extends unknown[], R>(
  channel: string,
  handler: (event: IpcMainInvokeEvent, ...args: T) => R | Promise<R>,
) {
  ipcMain.handle(channel, async (event, ...args: T) => {
    assertAuthorizedIpcSender(channel, event);
    return handler(event, ...args);
  });
}

async function writeAppPrivateFile(filePath: string, content: string | Buffer, encoding?: BufferEncoding) {
  await ensureSensitiveParentDir(filePath, { hardenExisting: true });
  await fs.writeFile(filePath, content, encoding ? { encoding, mode: SECURE_FILE_MODE } : { mode: SECURE_FILE_MODE });
  await chmodIfPossible(filePath, SECURE_FILE_MODE);
}

async function writeUserExportFile(filePath: string, content: string | Buffer, encoding?: BufferEncoding) {
  await ensureSensitiveParentDir(filePath, { hardenExisting: false });
  await fs.writeFile(filePath, content, encoding ? { encoding, mode: SECURE_FILE_MODE } : { mode: SECURE_FILE_MODE });
  await chmodIfPossible(filePath, SECURE_FILE_MODE);
}

async function ensureSensitiveParentDir(filePath: string, options: { hardenExisting: boolean }) {
  const parentDir = path.dirname(filePath);
  const createdRoot = await fs.mkdir(parentDir, { recursive: true, mode: SECURE_DIR_MODE });
  if (createdRoot) {
    await chmodCreatedDirectoryTree(createdRoot, parentDir, SECURE_DIR_MODE);
  } else if (options.hardenExisting) {
    await chmodIfPossible(parentDir, SECURE_DIR_MODE);
  }
}

async function chmodCreatedDirectoryTree(createdRoot: string, targetDir: string, mode: number) {
  if (process.platform === 'win32') return;
  const resolvedCreatedRoot = path.resolve(createdRoot);
  const resolvedTarget = path.resolve(targetDir);
  await chmodIfPossible(resolvedCreatedRoot, mode);
  const relativeParts = path.relative(resolvedCreatedRoot, resolvedTarget).split(path.sep).filter(Boolean);
  let current = resolvedCreatedRoot;
  for (const part of relativeParts) {
    current = path.join(current, part);
    await chmodIfPossible(current, mode);
  }
}

async function chmodIfPossible(filePath: string, mode: number) {
  if (process.platform === 'win32') return;
  try {
    await fs.chmod(filePath, mode);
  } catch (error) {
    if (!['ENOENT', 'EPERM', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
  }
}

secureIpcHandle('proxy:start', async (_event, port: number) => services().proxyEngine.start(port));
secureIpcHandle('proxy:stop', async () => services().proxyEngine.stop());
secureIpcHandle('proxy:status', async () => services().proxyEngine.status());
secureIpcHandle('browser:launch', async (_event, request: BrowserLaunchRequest) => launchManagedBrowser({
  ...request,
  profileBaseDir: path.join(app.getPath('userData'), 'browser-profiles'),
}));
secureIpcHandle('browser:cookies', async (_event, request: BrowserCookieExtractionRequest) => extractBrowserCookies(request));
secureIpcHandle('session-profile:refresh', async (_event, request: SessionProfileRefreshRequest) => refreshSessionProfile(request));
secureIpcHandle('project:create', guardedIpcHandler(ipcContracts.projectCreate, async (request: ProjectLifecycleCreateRequest) => {
  const state = await projectLifecycle().createProject(request);
  await bindProjectRecorders(state.activeProject);
  if (state.activeProject) await certificateAuthorityManager().setProject(state.activeProject.projectName);
  return state;
}, auditIpcGuardEvent));
secureIpcHandle('project:open', guardedIpcHandler(ipcContracts.projectOpen, async (request: ProjectLifecycleOpenRequest) => {
  const state = await projectLifecycle().openProject(request);
  await bindProjectRecorders(state.activeProject);
  if (state.activeProject) await certificateAuthorityManager().setProject(state.activeProject.projectName);
  return state;
}, auditIpcGuardEvent));
secureIpcHandle('project:close', guardedIpcHandler(ipcContracts.projectClose, async (request: ProjectLifecycleCloseRequest) => {
  const state = await projectLifecycle().closeProject(request);
  await bindProjectRecorders(undefined);
  await certificateAuthorityManager().setProject(DEFAULT_PROJECT_NAME);
  return state;
}, auditIpcGuardEvent));
secureIpcHandle('project:stats', async () => projectLifecycle().status());
secureIpcHandle('project:backup', guardedIpcHandler(ipcContracts.projectBackup, async (request: ProjectLifecycleBackupRequest) => projectLifecycle().backupProject(request), auditIpcGuardEvent));
secureIpcHandle('project:load', async () => loadProjectSnapshot());
secureIpcHandle('project:save', async (_event, snapshot: ProjectSnapshot) => saveProjectSnapshot(snapshot));
secureIpcHandle('project:reset', async () => resetProjectSnapshot());
secureIpcHandle('project:export-file', async (_event, snapshot: ProjectSnapshot) => exportProjectSnapshot(snapshot));
secureIpcHandle('project:import-file', async (_event, content?: string) => importProjectSnapshot(content));
secureIpcHandle('audit:export-file', async (_event, artifact: SignedAuditExport) => exportSignedAuditPackage(artifact));
secureIpcHandle('websocket-transcript:export-file', async (_event, artifact: WebSocketTranscriptExport) => exportWebSocketTranscript(artifact));
secureIpcHandle('websocket-transcript:import-file', async (_event, content?: string) => importWebSocketTranscript(content));
secureIpcHandle('enterprise-policy:push', async (_event, request: EnterprisePolicyPushRequest) => services().enterprisePolicyTransportService.push(request));
secureIpcHandle('enterprise-policy:pull', async (_event, request: EnterprisePolicyPullRequest) => services().enterprisePolicyTransportService.pull(request));
secureIpcHandle('repeater:send', guardedIpcHandler<ReplayRequest, Awaited<ReturnType<ProxyEngine['replay']>>>(ipcContracts.repeaterSend, async (request) => {
  const exchange = await services().proxyEngine.replay(request);
  projectStoreRepeaterRecorder?.capture(request, exchange);
  await auditIpcGuardEvent({
    channel: 'repeater:send',
    capability: 'active.repeater',
    dangerLevel: 'active-workflow',
    decision: exchange.tags.includes('blocked-by-scope') ? 'blocked' : 'completed',
    detail: `Repeater sent ${request.targetUrl} with ${request.scopeAllowlist.length} scope rule(s).`,
  });
  return exchange;
}, auditIpcGuardEvent));
secureIpcHandle('repeater:desync-probe', async (_event, request: RepeaterDesyncRaceRuntimeRequest) => services().repeaterDesyncRaceEngine.runSingleConnectionProbe(request));
secureIpcHandle('repeater:parallel-race', async (_event, request: RepeaterDesyncRaceRuntimeRequest) => services().repeaterDesyncRaceEngine.runParallelRace(request));
secureIpcHandle('intruder:run', guardedIpcHandler<IntruderAttackRequest, Awaited<ReturnType<ProxyEngine['runIntruderAttack']>>>(ipcContracts.intruderRun, async (request) => {
  const summary = await services().proxyEngine.runIntruderAttack(request);
  await projectStoreIntruderRecorder?.recordAttack(request, summary);
  await auditIpcGuardEvent({
    channel: 'intruder:run',
    capability: 'active.intruder',
    dangerLevel: 'active-workflow',
    decision: summary.blocked ? 'blocked' : 'completed',
    detail: `Intruder ${summary.attackMode} run for ${request.targetUrl}; ${summary.totalRequests} request(s), ${request.scopeAllowlist.length} scope rule(s).`,
  });
  return summary;
}, auditIpcGuardEvent));
secureIpcHandle('crawler:run', async (_event, request: CrawlRequest) => services().crawlEngine.runCrawl(request));
secureIpcHandle('scanner:run-crawl-audit', guardedIpcHandler<CrawlAuditRequest, Awaited<ReturnType<ProxyEngine['runCrawlAudit']>>>(ipcContracts.scannerRunCrawlAudit, async (request) => {
  const summary = await services().proxyEngine.runCrawlAudit(request);
  await auditIpcGuardEvent({
    channel: 'scanner:run-crawl-audit',
    capability: 'active.scanner',
    dangerLevel: 'active-workflow',
    decision: summary.blocked ? 'blocked' : 'completed',
    detail: `Crawl audit checked ${summary.auditedInsertionPoints} insertion point(s) with ${request.scopeAllowlist.length} scope rule(s).`,
  });
  return summary;
}, auditIpcGuardEvent));
secureIpcHandle('scanner:run-active', guardedIpcHandler<ActiveScanRequest, Awaited<ReturnType<ProxyEngine['runActiveScan']>>>(ipcContracts.scannerRunActive, async (request) => {
  const summary = await services().proxyEngine.runActiveScan(request);
  await projectStoreScannerRecorder?.recordTask(request, summary, 'active');
  await auditIpcGuardEvent({
    channel: 'scanner:run-active',
    capability: 'active.scanner',
    dangerLevel: 'active-workflow',
    decision: summary.blocked ? 'blocked' : 'completed',
    detail: `Active scan ran ${request.checks.length} check(s) against ${request.targetUrl}; ${summary.totalRequests} request(s).`,
  });
  return summary;
}, auditIpcGuardEvent));
secureIpcHandle('intercept:status', async () => services().proxyEngine.interceptStatus());
secureIpcHandle('intercept:set', async (_event, enabled: boolean) => services().proxyEngine.setIntercept(enabled));
secureIpcHandle('intercept:set-response', async (_event, enabled: boolean) => services().proxyEngine.setResponseIntercept(enabled));
secureIpcHandle('intercept:list', async () => services().proxyEngine.listIntercepts());
secureIpcHandle('intercept:resolve', async (_event, decision: InterceptDecision) => services().proxyEngine.resolveIntercept(decision));
secureIpcHandle('websocket-intercept:status', async () => services().proxyEngine.webSocketInterceptStatus());
secureIpcHandle('websocket-intercept:set', async (_event, settings: boolean | WebSocketInterceptSettings) => services().proxyEngine.setWebSocketIntercept(settings));
secureIpcHandle('websocket-intercept:list', async () => services().proxyEngine.listWebSocketIntercepts());
secureIpcHandle('websocket-intercept:resolve', async (_event, decision: WebSocketFrameDecision) => services().proxyEngine.resolveWebSocketIntercept(decision));
secureIpcHandle('websocket:replay', async (_event, request: WebSocketReplayRequest) => services().proxyEngine.replayWebSocketFrame(request));
secureIpcHandle('match-replace:list', async () => services().proxyEngine.getMatchReplaceRules());
secureIpcHandle('match-replace:set', async (_event, rules: MatchReplaceRule[]) => services().proxyEngine.setMatchReplaceRules(rules));
secureIpcHandle('websocket-rewrite:list', async () => services().proxyEngine.getWebSocketFrameRewriteRules());
secureIpcHandle('websocket-rewrite:set', async (_event, rules: WebSocketFrameRewriteRule[]) => services().proxyEngine.setWebSocketFrameRewriteRules(rules));
secureIpcHandle('cert:set-project', async (_event, projectName: string) => services().certificateAuthority.setProject(projectName));
secureIpcHandle('cert:status', async () => services().certificateAuthority.status());
secureIpcHandle('cert:ensure-root', async () => services().certificateAuthority.ensureRoot());
secureIpcHandle('cert:export-root', async () => services().certificateAuthority.exportRootPem());
secureIpcHandle('cert:rotate-root', async () => services().certificateAuthority.rotateRoot());
secureIpcHandle('cert:revoke-root', async () => services().certificateAuthority.revokeRoot());
secureIpcHandle('https-inspection:status', async () => services().proxyEngine.httpsInspectionStatus());
secureIpcHandle('https-inspection:set', async (_event, enabled: boolean) => services().proxyEngine.setHttpsInspection(enabled));
secureIpcHandle('https-inspection:set-upstream-tls', async (_event, mode: 'strict' | 'relaxed') => services().proxyEngine.setUpstreamTlsValidation(mode));
secureIpcHandle('callback-listener:start', guardedIpcHandler<{ profile: RuntimeCallbackListenerProfile; payloads: RuntimeCallbackPayload[] }, Awaited<ReturnType<CallbackListenerService['start']>>>(ipcContracts.callbackListenerStart, async (request) => {
  const status = await services().callbackListenerService.start(request.profile, request.payloads);
  await auditIpcGuardEvent({
    channel: 'callback-listener:start',
    capability: 'oast.listener',
    dangerLevel: 'active-workflow',
    decision: status.running ? 'completed' : 'blocked',
    detail: `Callback listener ${request.profile.id} start requested for ${request.profile.mode} with ${request.payloads.length} payload(s).`,
  });
  return status;
}, auditIpcGuardEvent));
secureIpcHandle('callback-listener:stop', async (_event, profileId: string) => services().callbackListenerService.stop(profileId));
secureIpcHandle('callback-listener:poll', guardedIpcHandler<{ profileId: string; payloads: RuntimeCallbackPayload[] }, ReturnType<CallbackListenerService['poll']>>(ipcContracts.callbackListenerPoll, async (request) => services().callbackListenerService.poll(request.profileId, request.payloads), auditIpcGuardEvent));
secureIpcHandle('callback-listener:status', async (_event, profileId: string) => services().callbackListenerService.status(profileId));
secureIpcHandle('ai:providers', async () => services().aiEngine.loadProviders());
secureIpcHandle('ai:providers:set', guardedIpcHandler(ipcContracts.aiProvidersSet, async (configs: AiProviderConfig[]) => {
  const result = await services().aiEngine.saveProviders(configs);
  await auditIpcGuardEvent({
    channel: 'ai:providers:set',
    capability: 'ai.provider-config',
    dangerLevel: 'credential',
    decision: 'updated',
    detail: `Updated ${result.length} AI provider configuration(s).`,
  });
  return result;
}, auditIpcGuardEvent));
secureIpcHandle('ai:run', guardedIpcHandler(ipcContracts.aiRun, async (request: AiRunRequest) => {
  const result = await services().aiEngine.runTask(request);
  await projectStoreRunStateRecorder?.recordAiRun({
    ...result,
    prompt: result.prompt ?? buildAiRunPersistencePrompt(request),
    contextDigest: result.contextDigest ?? `ai-context-${Buffer.from(JSON.stringify(request.context)).toString('base64url').slice(0, 24)}`,
  });
  return result;
}, auditIpcGuardEvent));
secureIpcHandle('run-state:automation', guardedIpcHandler(ipcContracts.automationRunState, async (execution: RuntimeAutomationExecution) => {
  services();
  if (!projectStoreRunStateRecorder) throw new Error('Project Store run-state recorder unavailable.');
  return projectStoreRunStateRecorder.recordAutomationRun(execution);
}, auditIpcGuardEvent));
secureIpcHandle('run-state:extension', guardedIpcHandler(ipcContracts.extensionRunState, async (run: RuntimeExtensionRun) => {
  services();
  if (!projectStoreRunStateRecorder) throw new Error('Project Store run-state recorder unavailable.');
  return projectStoreRunStateRecorder.recordExtensionRun(run);
}, auditIpcGuardEvent));
secureIpcHandle('report:export', async (_event, request: ReportExportRequest) => {
  const artifact = await services().reportEngine.exportReport(request);
  await projectStoreReportRecorder?.recordExport(request, artifact);
  return artifact;
});
secureIpcHandle('sequencer:analyze', async (_event, request: SequencerSampleRequest) => services().sequencerEngine.analyzeSamples(request));

app.whenReady().then(() => {
  registerPackagedRendererProtocol();
  createWindow();
});

app.on('window-all-closed', () => {
  proxyEngine?.stop();
  void projectStoreProxyRecorder?.close().catch(() => undefined);
  void projectStoreCallbackRecorder?.close().catch(() => undefined);
  void projectStoreRepeaterRecorder?.close().catch(() => undefined);
  void projectStoreIntruderRecorder?.close().catch(() => undefined);
  void projectStoreScannerRecorder?.close().catch(() => undefined);
  void projectStoreReportRecorder?.close().catch(() => undefined);
  void projectStoreWebSocketRecorder?.close().catch(() => undefined);
  void projectStoreRunStateRecorder?.close().catch(() => undefined);
  void projectLifecycleService?.dispose().catch(() => undefined);
  void callbackListenerService?.stopAll();
  if (process.platform !== 'darwin') app.quit();
});

app.on('activate', () => {
  if (BrowserWindow.getAllWindows().length === 0) createWindow();
});

function projectLifecycle() {
  if (!projectLifecycleService) {
    projectLifecycleService = new ProjectLifecycleService({
      projectsRootDir: path.join(app.getPath('userData'), 'projects'),
      backupsRootDir: path.join(app.getPath('userData'), 'project-backups'),
      defaultProjectName: DEFAULT_PROJECT_NAME,
    });
  }
  return projectLifecycleService;
}

function certificateAuthorityManager() {
  if (!certificateAuthority) {
    certificateAuthority = new CertificateAuthorityManager(path.join(app.getPath('userData'), 'certificates'));
  }
  return certificateAuthority;
}

function currentProjectRuntime(): ActiveProjectReference {
  return projectLifecycleService?.activeProjectReference() ?? {
    projectId: DEFAULT_PROJECT_ID,
    projectName: DEFAULT_PROJECT_NAME,
    rootDir: defaultProjectStorePath(),
    snapshotPath: path.join(app.getPath('userData'), 'projects', 'default.proxyforge.json'),
  };
}

function buildAiRunPersistencePrompt(request: AiRunRequest) {
  return JSON.stringify({
    kind: 'proxyforge-ai-run-persistence-prompt',
    providerId: request.providerId,
    task: request.task,
    operatorPrompt: request.prompt,
    context: request.context,
    secretHandling: 'executor-full-fidelity-context-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  }, null, 2);
}

async function auditIpcGuardEvent(event: IpcGuardAuditEvent) {
  await projectLifecycleService?.recordAuditEvent({
    actor: 'ipc-guard',
    action: `ipc.${event.channel}`,
    targetRef: event.capability,
    decision: event.decision,
    detail: `${event.dangerLevel}: ${event.detail}`,
  });
}

async function bindProjectRecorders(project?: ActiveProjectReference) {
  await Promise.all([
    projectStoreProxyRecorder?.close().catch(() => undefined),
    projectStoreCallbackRecorder?.close().catch(() => undefined),
    projectStoreRepeaterRecorder?.close().catch(() => undefined),
    projectStoreIntruderRecorder?.close().catch(() => undefined),
    projectStoreScannerRecorder?.close().catch(() => undefined),
    projectStoreReportRecorder?.close().catch(() => undefined),
    projectStoreWebSocketRecorder?.close().catch(() => undefined),
    projectStoreRunStateRecorder?.close().catch(() => undefined),
  ]);
  projectStoreProxyRecorder = null;
  projectStoreCallbackRecorder = null;
  projectStoreRepeaterRecorder = null;
  projectStoreIntruderRecorder = null;
  projectStoreScannerRecorder = null;
  projectStoreReportRecorder = null;
  projectStoreWebSocketRecorder = null;
  projectStoreRunStateRecorder = null;
  if (!project) return;
  projectStoreProxyRecorder = new ProjectStoreProxyRecorder(project.rootDir, {
    projectName: project.projectName,
    projectId: project.projectId,
  });
  projectStoreCallbackRecorder = new ProjectStoreCallbackRecorder(project.rootDir, {
    projectName: project.projectName,
    projectId: project.projectId,
  });
  projectStoreRepeaterRecorder = new ProjectStoreRepeaterRecorder(project.rootDir, {
    projectName: project.projectName,
    projectId: project.projectId,
  });
  projectStoreIntruderRecorder = new ProjectStoreIntruderRecorder(project.rootDir, {
    projectName: project.projectName,
    projectId: project.projectId,
  });
  projectStoreScannerRecorder = new ProjectStoreScannerRecorder(project.rootDir, {
    projectName: project.projectName,
    projectId: project.projectId,
  });
  projectStoreReportRecorder = new ProjectStoreReportRecorder(project.rootDir, {
    projectName: project.projectName,
    projectId: project.projectId,
  });
  projectStoreWebSocketRecorder = new ProjectStoreWebSocketRecorder(project.rootDir, {
    projectName: project.projectName,
    projectId: project.projectId,
  });
  projectStoreRunStateRecorder = new ProjectStoreRunStateRecorder(project.rootDir, {
    projectName: project.projectName,
    projectId: project.projectId,
  });
}

function projectPath() {
  const active = projectLifecycleService?.activeProjectReference();
  if (active) return projectSnapshotPath(active.rootDir);
  return path.join(app.getPath('userData'), 'projects', 'default.proxyforge.json');
}

function defaultProjectStorePath() {
  return path.join(app.getPath('userData'), 'projects', 'default.proxyforge');
}

async function loadProjectSnapshot(): Promise<ProjectSnapshot | null> {
  try {
    const raw = await fs.readFile(projectPath(), 'utf8');
    return JSON.parse(raw) as ProjectSnapshot;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return null;
    throw error;
  }
}

async function resetProjectSnapshot(): Promise<void> {
  try {
    await fs.unlink(projectPath());
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw error;
  }
}

async function saveProjectSnapshot(snapshot: ProjectSnapshot): Promise<ProjectSnapshot> {
  const filePath = projectPath();
  const next = {
    ...snapshot,
    savedAt: new Date().toISOString(),
  } satisfies ProjectSnapshot;
  await writeAppPrivateFile(filePath, JSON.stringify(next, null, 2), 'utf8');
  return next;
}

async function exportProjectSnapshot(snapshot: ProjectSnapshot): Promise<ProjectFileArtifact | null> {
  const next = {
    ...snapshot,
    savedAt: new Date().toISOString(),
  } satisfies ProjectSnapshot;
  const content = JSON.stringify(next, null, 2);
  const fileName = `${slugifyFileName(next.projectName)}.proxyforge.json`;
  const saveOptions: SaveDialogOptions = {
    title: 'Export ProxyForge project',
    defaultPath: fileName,
    filters: [
      { name: 'ProxyForge Project', extensions: ['json'] },
    ],
  };
  const result = mainWindow ? await dialog.showSaveDialog(mainWindow, saveOptions) : await dialog.showSaveDialog(saveOptions);
  if (result.canceled || !result.filePath) return null;
  await writeUserExportFile(result.filePath, content, 'utf8');
  return projectFileArtifact(next, result.filePath, Buffer.byteLength(content, 'utf8'));
}

async function importProjectSnapshot(content?: string): Promise<ProjectSnapshot | null> {
  let raw = content;
  if (!raw?.trim()) {
    const openOptions: OpenDialogOptions = {
      title: 'Import ProxyForge project',
      properties: ['openFile'],
      filters: [
        { name: 'ProxyForge, HAR, legacy proxy XML, JSONL, raw HTTP', extensions: ['json', 'har', 'xml', 'jsonl', 'txt', 'http'] },
        { name: 'All Files', extensions: ['*'] },
      ],
    };
    const result = mainWindow ? await dialog.showOpenDialog(mainWindow, openOptions) : await dialog.showOpenDialog(openOptions);
    if (result.canceled || !result.filePaths[0]) return null;
    const stat = await fs.stat(result.filePaths[0]);
    if (stat.size > MAX_PROJECT_IMPORT_BYTES) throw new Error(`Project import is limited to ${MAX_PROJECT_IMPORT_BYTES} bytes.`);
    raw = await fs.readFile(result.filePaths[0], 'utf8');
  }
  const snapshot = parseProjectSnapshotContent(raw);
  return saveProjectSnapshot(snapshot);
}

async function exportSignedAuditPackage(artifact: SignedAuditExport): Promise<SignedAuditExport | null> {
  const content = artifact.content ?? '';
  if (!content.trim()) throw new Error('Signed audit export content is empty.');
  const fileName = artifact.fileName || `${slugifyFileName(artifact.projectName)}.proxyforge-audit.json`;
  const saveOptions: SaveDialogOptions = {
    title: 'Export ProxyForge signed audit package',
    defaultPath: fileName,
    filters: [
      { name: 'ProxyForge Audit Package', extensions: ['json'] },
    ],
  };
  const result = mainWindow ? await dialog.showSaveDialog(mainWindow, saveOptions) : await dialog.showSaveDialog(saveOptions);
  if (result.canceled || !result.filePath) return null;
  await writeUserExportFile(result.filePath, content, 'utf8');
  return {
    ...artifact,
    fileName: path.basename(result.filePath),
    path: result.filePath,
    sizeBytes: Buffer.byteLength(content, 'utf8'),
    content,
  };
}

async function exportWebSocketTranscript(artifact: WebSocketTranscriptExport): Promise<WebSocketTranscriptExport | null> {
  const content = artifact.content ?? '';
  if (!content.trim()) throw new Error('WebSocket transcript content is empty.');
  const fileName = artifact.fileName || `${slugifyFileName(`${artifact.host}-${artifact.path}-websocket-transcript`)}.${artifact.format === 'json' ? 'proxyforge-ws.json' : 'md'}`;
  const saveOptions: SaveDialogOptions = {
    title: 'Export ProxyForge WebSocket transcript',
    defaultPath: fileName,
    filters: [
      artifact.format === 'json'
        ? { name: 'ProxyForge WebSocket Transcript', extensions: ['json'] }
        : { name: 'Markdown Transcript', extensions: ['md'] },
    ],
  };
  const result = mainWindow ? await dialog.showSaveDialog(mainWindow, saveOptions) : await dialog.showSaveDialog(saveOptions);
  if (result.canceled || !result.filePath) return null;
  await fs.writeFile(result.filePath, content, 'utf8');
  return {
    ...artifact,
    fileName: path.basename(result.filePath),
    filePath: result.filePath,
    sizeBytes: Buffer.byteLength(content, 'utf8'),
    content,
  };
}

async function importWebSocketTranscript(content?: string): Promise<WebSocketTranscriptExport | null> {
  let raw = content;
  let filePath = 'pasted';
  if (!raw?.trim()) {
    const openOptions: OpenDialogOptions = {
      title: 'Import ProxyForge WebSocket transcript',
      properties: ['openFile'],
      filters: [
        { name: 'ProxyForge WebSocket Transcript', extensions: ['json', 'md'] },
      ],
    };
    const result = mainWindow ? await dialog.showOpenDialog(mainWindow, openOptions) : await dialog.showOpenDialog(openOptions);
    if (result.canceled || !result.filePaths[0]) return null;
    filePath = result.filePaths[0];
    raw = await fs.readFile(filePath, 'utf8');
  }
  return parseWebSocketTranscriptContent(raw, filePath);
}

function parseProjectSnapshotContent(content: string): ProjectSnapshot {
  return parseProjectSnapshotContentShared(content) as ProjectSnapshot;
}

function parseWebSocketTranscriptContent(content: string, filePath: string): WebSocketTranscriptExport {
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
    return {
      id: typeof parsed.id === 'string' ? parsed.id : `ws-transcript-import-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      title: typeof parsed.title === 'string' ? parsed.title : `${parsed.host}${parsed.path} WebSocket transcript`,
      fileName: path.basename(filePath),
      filePath,
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
      sizeBytes: Buffer.byteLength(content, 'utf8'),
      content,
    };
  } catch (error) {
    if (content.trim().startsWith('{')) throw error;
    const title = content.match(/^#\s+(.+)$/m)?.[1]?.trim() || 'Imported WebSocket transcript';
    const connection = content.match(/^Connection:\s*(.+)$/m)?.[1]?.trim() || `imported-${Date.now()}`;
    return {
      id: `ws-transcript-import-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      title,
      fileName: path.basename(filePath),
      filePath,
      createdAt: now,
      connectionId: connection,
      host: 'imported.websocket.local',
      path: '/imported-transcript',
      format: 'markdown',
      frameCount: (content.match(/^###\s+/gm) ?? []).length,
      fuzzRunIds: [],
      stateDiffIds: [],
      closeCodeCount: (content.match(/Close\s+\d{4}/g) ?? []).length,
      sizeBytes: Buffer.byteLength(content, 'utf8'),
      content,
    };
  }
}

function projectFileArtifact(snapshot: ProjectSnapshot, filePath: string, sizeBytes: number): ProjectFileArtifact {
  return {
    id: `project-file-${Date.now()}-${Math.random().toString(16).slice(2)}`,
    fileName: path.basename(filePath),
    path: filePath,
    exportedAt: snapshot.savedAt,
    projectName: snapshot.projectName,
    exchangeCount: snapshot.exchanges.length,
    scopeCount: snapshot.scopeAllowlist.length,
    sizeBytes,
  };
}

function slugifyFileName(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'proxyforge-project';
}
