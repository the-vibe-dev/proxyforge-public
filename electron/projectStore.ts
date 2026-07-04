import { createHash, createHmac, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import fs from 'node:fs/promises';
import path from 'node:path';
import { parseProjectSnapshotContent, type ProjectSnapshot } from './projectSnapshotEngine';
import type { ActiveScanCheckId, ActiveScanFinding, ActiveScanRequest, ActiveScanSummary, ActiveScanSuppressedFinding, HttpExchange, IntruderAttackMode, IntruderAttackRequest, IntruderAttackResult, IntruderAttackSummary, ReplayRequest, WebSocketMessage } from './proxyEngine';
import type { ReportArtifact, ReportExportRequest, ReportFormat, ReportIssue, ReportSection, ReportTemplateId } from './reportEngine';
import type { CallbackInteraction, CallbackPayload } from './callbackListenerService';
import type { SessionCookieRecord } from './sessionEngine';

const CURRENT_SCHEMA_VERSION = 2;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const SECURE_DIR_MODE = 0o700;
const SECURE_FILE_MODE = 0o600;

export interface ProjectStoreManifest {
  kind: 'proxyforge-project-store';
  schemaVersion: 2;
  projectId: string;
  projectName: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectStoreOpenOptions {
  projectName?: string;
  projectId?: string;
  create?: boolean;
  recover?: boolean;
}

export type ProjectStoreSettingCategory =
  | 'scope'
  | 'proxy'
  | 'scanner'
  | 'sessions'
  | 'oast'
  | 'reports'
  | 'network'
  | 'browser'
  | 'repeater'
  | 'intruder'
  | 'automation'
  | 'ai'
  | 'safety';

export interface ProjectStoreSettingInput {
  id?: string;
  category: ProjectStoreSettingCategory;
  key: string;
  value: unknown;
  source?: string;
  enabled?: boolean;
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ProjectStoreSettingRecord {
  id: string;
  category: ProjectStoreSettingCategory;
  key: string;
  value: unknown;
  valueSha256: string;
  source: string;
  enabled: boolean;
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectStoreSettingsQuery {
  category?: ProjectStoreSettingCategory;
  key?: string;
  text?: string;
  enabled?: boolean;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreSessionCookieInput {
  name: string;
  value: string;
  domain: string;
  path?: string;
  secure?: boolean;
  httpOnly?: boolean;
  hostOnly?: boolean;
  sameSite?: string;
  expiresAt?: string;
  source?: string;
  createdAt?: string;
  updatedAt?: string;
  lastSeenAt?: string;
}

export interface ProjectStoreSessionCookieRecord extends SessionCookieRecord {
  valueSha256: string;
}

export interface ProjectStoreSessionCookieQuery {
  domain?: string;
  path?: string;
  name?: string;
  source?: string;
  secure?: boolean;
  hostOnly?: boolean;
  includeExpired?: boolean;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreHttpExchangeInput {
  id?: string;
  method: string;
  url: string;
  status: number;
  mime?: string;
  requestRaw: string | Buffer;
  responseRaw: string | Buffer;
  host?: string;
  path?: string;
  protocol?: string;
  timingMs?: number;
  source?: string;
  tags?: string[];
  notes?: string;
  scopeState?: string;
  createdAt?: string;
}

export interface ProjectStoreHttpExchangeRecord {
  id: string;
  method: string;
  url: string;
  host: string;
  path: string;
  protocol: string;
  status: number;
  mime: string;
  requestHash: string;
  responseHash: string;
  requestSize: number;
  responseSize: number;
  timingMs: number;
  source: string;
  tags: string[];
  notes: string;
  scopeState: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectStoreHttpExchangeFull extends ProjectStoreHttpExchangeRecord {
  requestRaw: Buffer;
  responseRaw: Buffer;
}

export type ProjectStoreTargetInventorySource =
  | 'proxy'
  | 'scanner'
  | 'crawler'
  | 'import'
  | 'repeater'
  | 'intruder'
  | 'manual'
  | 'agent'
  | 'unknown';

export type ProjectStoreParameterLocation =
  | 'query'
  | 'form'
  | 'json'
  | 'graphql'
  | 'xml'
  | 'multipart'
  | 'cookie'
  | 'header'
  | 'body';

export interface ProjectStoreTargetHostInput {
  id?: string;
  host: string;
  scheme?: string;
  port?: number;
  scopeState?: string;
  technologySummary?: Record<string, unknown>;
  source?: string;
  tags?: string[];
  notes?: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
}

export interface ProjectStoreTargetHostRecord {
  id: string;
  host: string;
  scheme: string;
  port: number;
  scopeState: string;
  technologySummary: Record<string, unknown>;
  source: ProjectStoreTargetInventorySource;
  exchangeCount: number;
  routeCount: number;
  tags: string[];
  notes: string;
  firstSeenAt: string;
  lastSeenAt: string;
  updatedAt: string;
}

export interface ProjectStoreTargetHostQuery {
  host?: string;
  scheme?: string;
  scopeState?: string;
  source?: string;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreTargetRouteInput {
  id?: string;
  hostId?: string;
  host: string;
  scheme?: string;
  port?: number;
  method: string;
  path: string;
  normalizedPath?: string;
  contentType?: string;
  status?: number;
  source?: string;
  evidenceExchangeId?: string;
  tags?: string[];
  notes?: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
}

export interface ProjectStoreTargetRouteRecord {
  id: string;
  hostId: string;
  host: string;
  scheme: string;
  port: number;
  method: string;
  path: string;
  normalizedPath: string;
  contentType: string;
  status: number;
  source: ProjectStoreTargetInventorySource;
  evidenceExchangeId?: string;
  parameterCount: number;
  issueCount: number;
  tags: string[];
  notes: string;
  firstSeenAt: string;
  lastSeenAt: string;
  updatedAt: string;
}

export interface ProjectStoreTargetRouteQuery {
  host?: string;
  method?: string;
  pathIncludes?: string;
  normalizedPath?: string;
  source?: string;
  hasParameters?: boolean;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreParameterInput {
  id?: string;
  routeId?: string;
  exchangeId?: string;
  host: string;
  method: string;
  path: string;
  location: ProjectStoreParameterLocation | string;
  name: string;
  value?: string;
  valueHash?: string;
  valueSample?: string;
  inferredType?: string;
  insertionCandidate?: boolean;
  source?: string;
  tags?: string[];
  notes?: string;
  firstSeenAt?: string;
  lastSeenAt?: string;
}

export interface ProjectStoreParameterRecord {
  id: string;
  routeId: string;
  exchangeId?: string;
  host: string;
  method: string;
  path: string;
  location: ProjectStoreParameterLocation;
  name: string;
  valueHash: string;
  valueSample: string;
  inferredType: string;
  insertionCandidate: boolean;
  source: ProjectStoreTargetInventorySource;
  evidenceCount: number;
  tags: string[];
  notes: string;
  firstSeenAt: string;
  lastSeenAt: string;
  updatedAt: string;
}

export interface ProjectStoreParameterQuery {
  routeId?: string;
  exchangeId?: string;
  host?: string;
  method?: string;
  location?: ProjectStoreParameterLocation | string;
  name?: string;
  insertionCandidate?: boolean;
  source?: string;
  text?: string;
  limit?: number;
  offset?: number;
}

export type ProjectStoreCallbackProtocol = 'dns' | 'http' | 'smtp';

export interface ProjectStoreCallbackPayloadInput {
  id?: string;
  token: string;
  label: string;
  protocol: ProjectStoreCallbackProtocol;
  endpoint: string;
  status?: string;
  sourceExchangeId?: string;
  sourceHost?: string;
  sourcePath?: string;
  notes?: string;
  createdAt?: string;
  lastInteractionAt?: string;
}

export interface ProjectStoreCallbackInteractionInput {
  id?: string;
  payloadId: string;
  protocol: ProjectStoreCallbackProtocol;
  observedAt?: string;
  sourceIp?: string;
  sourceHost?: string;
  requestLine?: string;
  userAgent?: string;
  raw: string | Buffer;
  severity?: string;
  tags?: string[];
}

export interface ProjectStoreCallbackPayloadRecord {
  id: string;
  token: string;
  label: string;
  protocol: ProjectStoreCallbackProtocol;
  endpoint: string;
  status: string;
  sourceExchangeId?: string;
  sourceHost: string;
  sourcePath: string;
  notes: string;
  createdAt: string;
  updatedAt: string;
  lastInteractionAt?: string;
  interactionCount: number;
}

export interface ProjectStoreCallbackInteractionRecord {
  id: string;
  payloadId: string;
  protocol: ProjectStoreCallbackProtocol;
  observedAt: string;
  sourceIp: string;
  sourceHost: string;
  requestLine: string;
  userAgent: string;
  rawHash: string;
  rawSize: number;
  severity: string;
  tags: string[];
  createdAt: string;
}

export interface ProjectStoreCallbackInteractionFull extends ProjectStoreCallbackInteractionRecord {
  raw: Buffer;
}

export interface ProjectStoreRepeaterTabInput {
  id?: string;
  name?: string;
  targetUrl: string;
  rawRequest: string | Buffer;
  group?: string;
  sourceExchangeId?: string;
  lastReplayId?: string;
  lastStatus?: number;
  dirty?: boolean;
  tags?: string[];
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ProjectStoreRepeaterTabRecord {
  id: string;
  name: string;
  targetUrl: string;
  host: string;
  method: string;
  path: string;
  requestHash: string;
  requestSize: number;
  group: string;
  sourceExchangeId?: string;
  lastReplayId?: string;
  lastStatus: number;
  dirty: boolean;
  tags: string[];
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectStoreRepeaterTabFull extends ProjectStoreRepeaterTabRecord {
  rawRequest: Buffer;
}

export interface ProjectStoreRepeaterTabQuery {
  group?: string;
  host?: string;
  text?: string;
  dirty?: boolean;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreRepeaterSendInput {
  id?: string;
  tabId?: string;
  exchangeId?: string;
  targetUrl: string;
  rawRequest: string | Buffer;
  responseRaw: string | Buffer;
  method?: string;
  host?: string;
  path?: string;
  protocol?: string;
  status?: number;
  mime?: string;
  timingMs?: number;
  sourceExchangeId?: string;
  sessionProfileId?: string;
  oastPayloadIds?: string[];
  tags?: string[];
  notes?: string;
  createdAt?: string;
}

export interface ProjectStoreRepeaterSendRecord {
  id: string;
  tabId?: string;
  exchangeId?: string;
  targetUrl: string;
  host: string;
  method: string;
  path: string;
  protocol: string;
  status: number;
  mime: string;
  requestHash: string;
  responseHash: string;
  requestSize: number;
  responseSize: number;
  timingMs: number;
  sourceExchangeId?: string;
  sessionProfileId?: string;
  oastPayloadIds: string[];
  tags: string[];
  notes: string;
  createdAt: string;
}

export interface ProjectStoreRepeaterSendFull extends ProjectStoreRepeaterSendRecord {
  rawRequest: Buffer;
  responseRaw: Buffer;
}

export interface ProjectStoreRepeaterSendQuery {
  tabId?: string;
  exchangeId?: string;
  sourceExchangeId?: string;
  host?: string;
  statusMin?: number;
  statusMax?: number;
  text?: string;
  limit?: number;
  offset?: number;
}

export type ProjectStoreWebSocketDirection = 'client' | 'server';
export type ProjectStoreWebSocketFrameType = 'text' | 'binary' | 'close' | 'ping' | 'pong' | 'other';
export type ProjectStoreWebSocketPayloadEncoding = 'text' | 'hex' | 'base64';

export interface ProjectStoreWebSocketConnectionInput {
  id: string;
  url: string;
  host?: string;
  path?: string;
  protocol?: string;
  parentExchangeId?: string;
  tags?: string[];
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ProjectStoreWebSocketConnectionRecord {
  id: string;
  url: string;
  host: string;
  path: string;
  protocol: string;
  parentExchangeId?: string;
  firstFrameAt?: string;
  lastFrameAt?: string;
  frameCount: number;
  clientFrameCount: number;
  serverFrameCount: number;
  tags: string[];
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectStoreWebSocketConnectionQuery {
  host?: string;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreWebSocketFrameInput {
  id?: string;
  connectionId: string;
  direction: ProjectStoreWebSocketDirection;
  host?: string;
  path?: string;
  url: string;
  opcode: number;
  type: ProjectStoreWebSocketFrameType;
  payload: string | Buffer;
  payloadEncoding?: ProjectStoreWebSocketPayloadEncoding;
  length?: number;
  intercepted?: boolean;
  modified?: boolean;
  dropped?: boolean;
  replayed?: boolean;
  rewritten?: boolean;
  tags?: string[];
  source?: string;
  notes?: string;
  createdAt?: string;
}

export interface ProjectStoreWebSocketFrameRecord {
  id: string;
  connectionId: string;
  direction: ProjectStoreWebSocketDirection;
  host: string;
  path: string;
  url: string;
  opcode: number;
  type: ProjectStoreWebSocketFrameType;
  payloadHash: string;
  payloadSize: number;
  payloadEncoding: ProjectStoreWebSocketPayloadEncoding;
  intercepted: boolean;
  modified: boolean;
  dropped: boolean;
  replayed: boolean;
  rewritten: boolean;
  tags: string[];
  source: string;
  notes: string;
  createdAt: string;
}

export interface ProjectStoreWebSocketFrameFull extends ProjectStoreWebSocketFrameRecord {
  payload: Buffer;
}

export interface ProjectStoreWebSocketFrameQuery {
  connectionId?: string;
  direction?: ProjectStoreWebSocketDirection;
  type?: ProjectStoreWebSocketFrameType;
  host?: string;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreIntruderAttackInput {
  id?: string;
  targetUrl: string;
  rawRequest: string | Buffer;
  attackMode: IntruderAttackMode;
  payloadPositions: number;
  totalRequests: number;
  blocked: boolean;
  message: string;
  payloads?: string[];
  payloadSets?: string[][];
  payloadProcessors?: string[];
  payloadRules?: string[];
  scopeAllowlist?: string[];
  startOffset?: number;
  nextOffset?: number;
  hasMore?: boolean;
  payloadPlanCount?: number;
  payloadRuleCount?: number;
  resourcePoolName?: string;
  resourcePoolMaxConcurrent?: number;
  streamSummary?: Record<string, unknown>;
  oastSummary?: Record<string, unknown>;
  tags?: string[];
  notes?: string;
  startedAt?: string;
  completedAt?: string;
  results?: IntruderAttackResult[];
}

export interface ProjectStoreIntruderAttackRecord {
  id: string;
  targetUrl: string;
  host: string;
  path: string;
  attackMode: IntruderAttackMode;
  baseRequestHash: string;
  baseRequestSize: number;
  payloadPositions: number;
  totalRequests: number;
  retainedResultCount: number;
  blocked: boolean;
  message: string;
  payloads: string[];
  payloadSets: string[][];
  payloadProcessors: string[];
  payloadRules: string[];
  scopeAllowlist: string[];
  startOffset?: number;
  nextOffset?: number;
  hasMore: boolean;
  payloadPlanCount: number;
  payloadRuleCount: number;
  resourcePoolName: string;
  resourcePoolMaxConcurrent: number;
  streamSummary: Record<string, unknown>;
  oastSummary: Record<string, unknown>;
  tags: string[];
  notes: string;
  startedAt: string;
  completedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectStoreIntruderAttackFull extends ProjectStoreIntruderAttackRecord {
  rawRequest: Buffer;
}

export interface ProjectStoreIntruderAttackQuery {
  host?: string;
  attackMode?: IntruderAttackMode;
  blocked?: boolean;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreIntruderResultInput {
  attackId: string;
  rowIndex?: number;
  result: IntruderAttackResult;
  createdAt?: string;
}

export interface ProjectStoreIntruderResultRecord {
  id: string;
  attackId: string;
  rowIndex: number;
  payload: string;
  payloads: string[];
  attackMode: IntruderAttackMode;
  status: number;
  length: number;
  mime: string;
  timing: number;
  requestHash: string;
  responseHash: string;
  requestSize: number;
  responseSize: number;
  grepMatches: string[];
  extractMatches: string[];
  oastPayloadIds: string[];
  callbackInteractionIds: string[];
  tags: string[];
  notes: string;
  createdAt: string;
}

export interface ProjectStoreIntruderResultFull extends ProjectStoreIntruderResultRecord {
  requestRaw: Buffer;
  responseRaw: Buffer;
}

export interface ProjectStoreIntruderResultQuery {
  attackId?: string;
  statusMin?: number;
  statusMax?: number;
  grep?: string;
  text?: string;
  limit?: number;
  offset?: number;
}

export type ProjectStoreScannerTaskKind = 'active' | 'crawl-audit';

export interface ProjectStoreScannerTaskInput {
  id?: string;
  kind?: ProjectStoreScannerTaskKind;
  request: ActiveScanRequest;
  summary: ActiveScanSummary;
  exchanges?: HttpExchange[];
  tags?: string[];
  notes?: string;
}

export interface ProjectStoreScannerTaskRecord {
  id: string;
  kind: ProjectStoreScannerTaskKind;
  targetUrl: string;
  host: string;
  path: string;
  requestedChecks: ActiveScanCheckId[];
  scopeAllowlist: string[];
  totalRequests: number;
  exchangeIds: string[];
  findingCount: number;
  suppressedFindingCount: number;
  blocked: boolean;
  message: string;
  tuning: Record<string, unknown>;
  tags: string[];
  notes: string;
  startedAt: string;
  completedAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectStoreScannerTaskQuery {
  kind?: ProjectStoreScannerTaskKind;
  host?: string;
  blocked?: boolean;
  checkId?: ActiveScanCheckId;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreScannerFindingInput {
  taskId: string;
  finding: ActiveScanFinding | ActiveScanSuppressedFinding;
  suppressed?: boolean;
  suppressionReason?: string;
  createdAt?: string;
}

export interface ProjectStoreScannerFindingRecord {
  id: string;
  taskId: string;
  checkId: ActiveScanCheckId;
  title: string;
  severity: ProjectStoreIssueSeverity;
  confidence: ProjectStoreIssueConfidence;
  host: string;
  path: string;
  detail: string;
  remediation: string;
  evidenceExchangeId?: string;
  dedupeKey: string;
  confidenceReason: string;
  suppressed: boolean;
  suppressionReason: string;
  tags: string[];
  createdAt: string;
}

export interface ProjectStoreScannerFindingFull extends ProjectStoreScannerFindingRecord {
  evidenceExchange?: ProjectStoreHttpExchangeFull;
}

export interface ProjectStoreScannerFindingQuery {
  taskId?: string;
  checkId?: ActiveScanCheckId;
  severity?: ProjectStoreIssueSeverity;
  confidence?: ProjectStoreIssueConfidence;
  suppressed?: boolean;
  text?: string;
  limit?: number;
  offset?: number;
}

export type ProjectStoreIssueSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type ProjectStoreIssueConfidence = 'certain' | 'firm' | 'tentative';
export type ProjectStoreIssueStatus = 'open' | 'triaged' | 'false-positive' | 'fixed';

export interface ProjectStoreEvidenceRef {
  kind: string;
  id: string;
  label?: string;
  source?: string;
  hash?: string;
}

export interface ProjectStoreIssueInput {
  id?: string;
  title: string;
  type?: string;
  severity: ProjectStoreIssueSeverity;
  confidence: ProjectStoreIssueConfidence;
  status: ProjectStoreIssueStatus;
  host: string;
  path: string;
  detail: string;
  remediation: string;
  evidenceRefs?: ProjectStoreEvidenceRef[];
  dedupeKey?: string;
  source?: string;
  assignee?: string;
  triageNote?: string;
  createdAt?: string;
  updatedAt?: string;
  lastTriagedAt?: string;
}

export interface ProjectStoreIssueRecord {
  id: string;
  title: string;
  type: string;
  severity: ProjectStoreIssueSeverity;
  confidence: ProjectStoreIssueConfidence;
  status: ProjectStoreIssueStatus;
  host: string;
  path: string;
  detail: string;
  remediation: string;
  evidenceRefs: ProjectStoreEvidenceRef[];
  dedupeKey: string;
  source: string;
  assignee?: string;
  triageNote: string;
  createdAt: string;
  updatedAt: string;
  lastTriagedAt?: string;
}

export interface ProjectStoreIssueQuery {
  severity?: ProjectStoreIssueSeverity;
  status?: ProjectStoreIssueStatus;
  host?: string;
  source?: string;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreReportExportInput {
  id?: string;
  format: ReportFormat;
  fileName: string;
  path: string;
  content: string | Buffer;
  issueIds?: string[];
  exchangeIds?: string[];
  templateId?: ReportTemplateId;
  sections?: ReportSection[];
  preparedFor?: string;
  engagementId?: string;
  bundleHash?: string;
  signatureStatus?: string;
  signerName?: string;
  keyId?: string;
  redacted?: boolean;
  notes?: string;
  createdAt?: string;
}

export interface ProjectStoreReportExportRecord {
  id: string;
  format: ReportFormat;
  fileName: string;
  path: string;
  contentHash: string;
  contentSize: number;
  issueIds: string[];
  exchangeIds: string[];
  templateId: string;
  sections: ReportSection[];
  preparedFor: string;
  engagementId: string;
  bundleHash?: string;
  signatureStatus: string;
  signerName: string;
  keyId: string;
  redacted: boolean;
  notes: string;
  createdAt: string;
}

export interface ProjectStoreReportExportFull extends ProjectStoreReportExportRecord {
  content: Buffer;
}

export interface ProjectStoreReportExportQuery {
  format?: ReportFormat;
  issueId?: string;
  text?: string;
  limit?: number;
  offset?: number;
}

export type ProjectStoreAutomationRunStatus = 'ready' | 'running' | 'blocked' | 'complete';
export type ProjectStoreAutomationTrigger = 'manual' | 'scheduled' | 'on-tag' | 'ci' | string;

export interface ProjectStoreAutomationRunInput {
  id?: string;
  workflowId: string;
  workflowName: string;
  status: ProjectStoreAutomationRunStatus | string;
  trigger: ProjectStoreAutomationTrigger;
  startedAt?: string;
  completedAt?: string;
  durationMs?: number;
  totalRequests?: number;
  logs?: string[];
  exchange?: HttpExchange;
  issue?: ProjectStoreIssueInput;
  operationalRawMaterial?: Record<string, unknown>;
  schedulerJobId?: string;
  schedulerLeaseId?: string;
  ciProvider?: string;
  ciConfig?: string;
  tags?: string[];
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ProjectStoreAutomationRunRecord {
  id: string;
  workflowId: string;
  workflowName: string;
  status: ProjectStoreAutomationRunStatus;
  trigger: string;
  startedAt: string;
  completedAt: string;
  durationMs: number;
  totalRequests: number;
  exchangeId?: string;
  issueId?: string;
  schedulerJobId?: string;
  schedulerLeaseId?: string;
  ciProvider?: string;
  ciConfig: string;
  logs: string[];
  operationalRawMaterial: Record<string, unknown>;
  tags: string[];
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectStoreAutomationRunFull extends ProjectStoreAutomationRunRecord {
  exchange?: ProjectStoreHttpExchangeFull;
  issue?: ProjectStoreIssueRecord;
}

export interface ProjectStoreAutomationRunQuery {
  workflowId?: string;
  status?: ProjectStoreAutomationRunStatus | string;
  trigger?: string;
  text?: string;
  limit?: number;
  offset?: number;
}

export type ProjectStoreAiRunStatus = 'complete' | 'unavailable' | 'error';

export interface ProjectStoreAiRunInput {
  id?: string;
  providerId: string;
  task: string;
  status: ProjectStoreAiRunStatus | string;
  model: string;
  startedAt?: string;
  completedAt?: string;
  summary: string;
  output: string | Buffer;
  prompt?: string | Buffer;
  evidenceCount?: number;
  command?: string;
  providerLabel?: string;
  contextDigest?: string;
  usage?: Record<string, unknown>;
  streamEvents?: Record<string, unknown>[];
  promptEvaluation?: Record<string, unknown>;
  suggestedActions?: Record<string, unknown>[];
  tags?: string[];
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ProjectStoreAiRunRecord {
  id: string;
  providerId: string;
  task: string;
  status: ProjectStoreAiRunStatus;
  model: string;
  startedAt: string;
  completedAt: string;
  summary: string;
  outputHash: string;
  outputSize: number;
  promptHash?: string;
  promptSize: number;
  evidenceCount: number;
  command?: string;
  providerLabel?: string;
  contextDigest?: string;
  usage: Record<string, unknown>;
  streamEvents: Record<string, unknown>[];
  promptEvaluation: Record<string, unknown>;
  suggestedActions: Record<string, unknown>[];
  tags: string[];
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectStoreAiRunFull extends ProjectStoreAiRunRecord {
  output: Buffer;
  prompt?: Buffer;
}

export interface ProjectStoreAiRunQuery {
  providerId?: string;
  task?: string;
  status?: ProjectStoreAiRunStatus | string;
  text?: string;
  limit?: number;
  offset?: number;
}

export type ProjectStoreExtensionRunStatus = 'complete' | 'blocked' | 'error';

export interface ProjectStoreExtensionRunInput {
  id?: string;
  extensionId: string;
  extensionName: string;
  hook: string;
  status: ProjectStoreExtensionRunStatus | string;
  target: string;
  startedAt?: string;
  completedAt?: string;
  summary: string;
  logs?: string[];
  issue?: ProjectStoreIssueInput;
  exchange?: HttpExchange;
  tags?: string[];
  notes?: string;
  createdAt?: string;
  updatedAt?: string;
}

export interface ProjectStoreExtensionRunRecord {
  id: string;
  extensionId: string;
  extensionName: string;
  hook: string;
  status: ProjectStoreExtensionRunStatus;
  target: string;
  startedAt: string;
  completedAt: string;
  summary: string;
  logs: string[];
  issueId?: string;
  exchangeId?: string;
  tags: string[];
  notes: string;
  createdAt: string;
  updatedAt: string;
}

export interface ProjectStoreExtensionRunFull extends ProjectStoreExtensionRunRecord {
  issue?: ProjectStoreIssueRecord;
  exchange?: ProjectStoreHttpExchangeFull;
}

export interface ProjectStoreExtensionRunQuery {
  extensionId?: string;
  hook?: string;
  status?: ProjectStoreExtensionRunStatus | string;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreCallbackQuery {
  payloadId?: string;
  protocol?: ProjectStoreCallbackProtocol;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreCallbackEvidenceExportOptions extends ProjectStoreCallbackQuery {
  signerName?: string;
  keyId?: string;
  signingSecret?: string;
  generatedAt?: string;
}

export interface ProjectStoreCallbackEvidencePackage {
  kind: 'proxyforge-project-store-callback-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  projectId: string;
  projectName: string;
  query: {
    payloadId?: string;
    protocol?: ProjectStoreCallbackProtocol;
    text?: string;
    limit: number;
    offset: number;
  };
  stats: {
    payloadCount: number;
    interactionCount: number;
    sourceExchangeCount: number;
    rawInteractionBytes: number;
  };
  payloads: ProjectStoreCallbackPayloadRecord[];
  interactions: Array<ProjectStoreCallbackInteractionRecord & {
    raw: string;
    rawSha256: string;
  }>;
  sourceExchanges: Array<ProjectStoreHttpExchangeRecord & {
    requestRaw: string;
    responseRaw: string;
    requestSha256: string;
    responseSha256: string;
  }>;
  requirements: {
    payloadsIncluded: boolean;
    interactionsIncluded: boolean;
    rawInteractionsPreserved: boolean;
    sourceExchangesLinked: boolean;
    hmacSignatureCovered: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  signature: {
    algorithm: 'HMAC-SHA256';
    canonicalization: 'proxyforge-project-store-callback-evidence-v1';
    keyId: string;
    signerName: string;
    signedAt: string;
    packageDigestSha256: string;
    signature: string;
    status: 'signed';
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: true;
  summary: string;
  content: string;
}

export interface ProjectStoreCallbackEvidenceVerification {
  valid: boolean;
  kind: string;
  signatureMatches: boolean;
  digestMatches: boolean;
  packageDigestSha256: string;
  expectedSignature: string;
  suppliedSignature: string;
  keyId: string;
  signerName: string;
  error?: string;
}

export interface ProjectStoreSettingsEvidencePackage {
  kind: 'proxyforge-project-store-settings-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  projectId: string;
  projectName: string;
  query: {
    category?: ProjectStoreSettingCategory;
    key?: string;
    text?: string;
    enabled?: boolean;
    limit: number;
    offset: number;
  };
  stats: {
    settingCount: number;
    categoryCount: number;
    enabledCount: number;
    disabledCount: number;
  };
  settings: ProjectStoreSettingRecord[];
  categories: ProjectStoreSettingCategory[];
  requirements: {
    scopeSettingsIncluded: boolean;
    proxySettingsIncluded: boolean;
    scannerSettingsIncluded: boolean;
    sessionSettingsIncluded: boolean;
    oastSettingsIncluded: boolean;
    reportSettingsIncluded: boolean;
    networkSettingsIncluded: boolean;
    rawOperationalSecretsPreserved: boolean;
    restartReady: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export interface ProjectStoreSessionCookieEvidencePackage {
  kind: 'proxyforge-project-store-cookie-jar-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  projectId: string;
  projectName: string;
  query: {
    domain?: string;
    path?: string;
    name?: string;
    source?: string;
    secure?: boolean;
    hostOnly?: boolean;
    includeExpired?: boolean;
    text?: string;
    limit: number;
    offset: number;
  };
  stats: {
    cookieCount: number;
    domainCount: number;
    secureCount: number;
    hostOnlyCount: number;
    expiredCount: number;
  };
  cookies: ProjectStoreSessionCookieRecord[];
  requirements: {
    cookiesPersisted: boolean;
    domainPathRulesRepresented: boolean;
    secureCookiesRepresented: boolean;
    hostOnlyAndDomainCookiesRepresented: boolean;
    rawOperationalSecretsPreserved: boolean;
    restartReady: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export interface ProjectStoreSearchQuery {
  method?: string;
  host?: string;
  pathIncludes?: string;
  statusMin?: number;
  statusMax?: number;
  text?: string;
  limit?: number;
  offset?: number;
}

export interface ProjectStoreStats {
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

export interface ProjectStoreImportPlan {
  accepted: boolean;
  entryCount: number;
  rejectedEntries: string[];
  requiredEntriesPresent: boolean;
}

export type ProjectStoreAuditDecision = 'allowed' | 'blocked' | 'completed' | 'updated';

export interface ProjectStoreAuditEventInput {
  id?: string;
  actor?: string;
  action: string;
  targetRef: string;
  decision: ProjectStoreAuditDecision;
  detail?: string;
  createdAt?: string;
}

export interface ProjectStoreAuditEventRecord {
  id: string;
  actor: string;
  action: string;
  targetRef: string;
  decision: ProjectStoreAuditDecision;
  detail: string;
  createdAt: string;
  previousHash?: string;
  hash: string;
}

export interface ProjectStoreProxyRecorderStats {
  rootDir: string;
  persistedCount: number;
  failedCount: number;
  pendingCount: number;
  lastExchangeId?: string;
  lastError?: string;
}

export interface ProjectStoreRecoveryReport {
  kind: 'proxyforge-project-store-recovery-report';
  schemaVersion: 1;
  rootDir: string;
  recoveredAt: string;
  journalPath: string;
  committedJournalPath: string;
  pendingRecordCount: number;
  committedRecordCount: number;
  recoveredHttpExchangeCount: number;
  skippedCommittedCount: number;
  skippedExistingCount: number;
  failedCount: number;
  recoveredIds: string[];
  skippedIds: string[];
  failedIds: string[];
  requirements: {
    durableJournalPresent: boolean;
    recoveryReplayAttempted: boolean;
    sqliteWalEnabled: boolean;
    rawOperationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
}

export interface ProjectStoreBackupOptions {
  label?: string;
  createdAt?: string;
}

export interface ProjectStoreBackupManifest {
  kind: 'proxyforge-project-store-backup';
  schemaVersion: 1;
  projectId: string;
  projectName: string;
  sourceRootDir: string;
  backupRootDir: string;
  backupDir: string;
  label: string;
  createdAt: string;
  stats: ProjectStoreStats;
  requirements: {
    manifestCopied: boolean;
    databaseCopied: boolean;
    blobsCopied: boolean;
    recoveryJournalCopied: boolean;
    rawOperationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
}

export interface ProjectStoreBackupResult extends ProjectStoreBackupManifest {
  manifestPath: string;
  content: string;
}

interface ProjectStorePendingHttpExchangeJournalRecord {
  kind: 'proxyforge-project-store-pending-http-exchange';
  schemaVersion: 1;
  recordedAt: string;
  exchange: ProjectStoreHttpExchangeInput & { id: string };
}

interface ProjectStoreCommittedHttpExchangeJournalRecord {
  kind: 'proxyforge-project-store-committed-http-exchange';
  schemaVersion: 1;
  id: string;
  committedAt: string;
  disposition: 'captured' | 'recovered' | 'already-in-store';
}

export interface ProjectStoreCallbackRecorderStats {
  rootDir: string;
  persistedPayloadCount: number;
  persistedInteractionCount: number;
  failedCount: number;
  pendingCount: number;
  lastPayloadId?: string;
  lastInteractionId?: string;
  lastError?: string;
}

export interface ProjectStoreRepeaterRecorderStats {
  rootDir: string;
  persistedTabCount: number;
  persistedSendCount: number;
  failedCount: number;
  pendingCount: number;
  lastSendId?: string;
  lastExchangeId?: string;
  lastError?: string;
}

export interface ProjectStoreReportRecorderStats {
  rootDir: string;
  persistedIssueCount: number;
  persistedReportCount: number;
  failedCount: number;
  pendingCount: number;
  lastReportId?: string;
  lastError?: string;
}

export interface ProjectStoreWebSocketRecorderStats {
  rootDir: string;
  persistedFrameCount: number;
  failedCount: number;
  pendingCount: number;
  lastConnectionId?: string;
  lastFrameId?: string;
  lastError?: string;
}

export interface ProjectStoreIntruderRecorderStats {
  rootDir: string;
  persistedAttackCount: number;
  persistedResultCount: number;
  failedCount: number;
  pendingCount: number;
  lastAttackId?: string;
  lastError?: string;
}

export interface ProjectStoreScannerRecorderStats {
  rootDir: string;
  persistedTaskCount: number;
  persistedFindingCount: number;
  failedCount: number;
  pendingCount: number;
  lastTaskId?: string;
  lastError?: string;
}

interface SqliteModule {
  DatabaseSync: new (filePath: string, options?: { readOnly?: boolean }) => SqliteDatabase;
}

interface SqliteDatabase {
  exec: (sql: string) => void;
  prepare: (sql: string) => SqliteStatement;
  close: () => void;
}

interface SqliteStatement {
  run: (...params: unknown[]) => void;
  get: (...params: unknown[]) => unknown;
  all: (...params: unknown[]) => unknown[];
}

export class ProjectStore {
  readonly rootDir: string;
  readonly manifest: ProjectStoreManifest;

  private readonly database: SqliteDatabase;
  private readonly knownBlobHashes = new Set<string>();

  private constructor(rootDir: string, manifest: ProjectStoreManifest, database: SqliteDatabase) {
    this.rootDir = rootDir;
    this.manifest = manifest;
    this.database = database;
  }

  static async create(rootDir: string, options: ProjectStoreOpenOptions = {}) {
    const now = new Date().toISOString();
    const manifest: ProjectStoreManifest = {
      kind: 'proxyforge-project-store',
      schemaVersion: CURRENT_SCHEMA_VERSION,
      projectId: options.projectId?.trim() || randomUUID(),
      projectName: options.projectName?.trim() || 'ProxyForge Project',
      createdAt: now,
      updatedAt: now,
    };

    await fs.mkdir(rootDir, { recursive: true, mode: SECURE_DIR_MODE });
    await chmodIfPossible(rootDir, SECURE_DIR_MODE);
    await fs.mkdir(blobRoot(rootDir), { recursive: true, mode: SECURE_DIR_MODE });
    await chmodIfPossible(blobRoot(rootDir), SECURE_DIR_MODE);
    await writeJsonAtomic(manifestPath(rootDir), manifest);

    const sqlite = await loadSqlite();
    const database = new sqlite.DatabaseSync(databasePath(rootDir));
    const store = new ProjectStore(rootDir, manifest, database);
    store.applyMigrations();
    await secureProjectStorePermissions(rootDir);
    return store;
  }

  static async open(rootDir: string, options: ProjectStoreOpenOptions = {}) {
    if (options.create) return ProjectStore.create(rootDir, options);

    const manifest = await readManifest(rootDir);
    const sqlite = await loadSqlite();
    const database = new sqlite.DatabaseSync(databasePath(rootDir));
    const store = new ProjectStore(rootDir, manifest, database);
    store.applyMigrations();
    await secureProjectStorePermissions(rootDir);
    if (options.recover !== false) await store.recoverPendingHttpExchanges();
    return store;
  }

  async addScopeRule(pattern: string, type: 'include' | 'exclude' = 'include', source = 'operator') {
    const normalized = pattern.trim();
    if (!normalized) throw new Error('Scope rule pattern is required.');
    const now = new Date().toISOString();
    this.database.prepare([
      'insert into scope_rules (id, type, pattern, enabled, source, created_at)',
      'values (?, ?, ?, 1, ?, ?)',
      'on conflict(id) do update set type = excluded.type, pattern = excluded.pattern, enabled = excluded.enabled, source = excluded.source',
    ].join(' ')).run(`scope-${sha256(normalized).slice(0, 16)}`, type, normalized, source, now);
    await this.touchManifest(now);
  }

  async addHttpExchange(input: ProjectStoreHttpExchangeInput) {
    await this.addHttpExchanges([input]);
  }

  async addHttpExchanges(inputs: ProjectStoreHttpExchangeInput[]) {
    if (inputs.length === 0) return;
    const records = [];
    for (const input of inputs) {
      const requestRaw = toBuffer(input.requestRaw);
      const responseRaw = toBuffer(input.responseRaw);
      const requestHash = await this.writeBlob(requestRaw);
      const responseHash = await this.writeBlob(responseRaw);
      records.push(normalizeExchangeInput(input, requestRaw, responseRaw, requestHash, responseHash));
    }

    const insertExchange = this.database.prepare([
      'insert into http_exchanges',
      '(id, method, url, host, path, protocol, status, mime, request_hash, response_hash, request_size, response_size, timing_ms, source, tags_json, notes, scope_state, created_at, updated_at, request_index, response_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'method = excluded.method, url = excluded.url, host = excluded.host, path = excluded.path, protocol = excluded.protocol,',
      'status = excluded.status, mime = excluded.mime, request_hash = excluded.request_hash, response_hash = excluded.response_hash,',
      'request_size = excluded.request_size, response_size = excluded.response_size, timing_ms = excluded.timing_ms, source = excluded.source,',
      'tags_json = excluded.tags_json, notes = excluded.notes, scope_state = excluded.scope_state, updated_at = excluded.updated_at,',
      'request_index = excluded.request_index, response_index = excluded.response_index',
    ].join(' '));
    const insertMessage = this.database.prepare([
      'insert into http_messages (exchange_id, direction, raw_blob_hash, body_blob_hash, headers_json, size, encoding)',
      'values (?, ?, ?, ?, ?, ?, ?)',
      'on conflict(exchange_id, direction) do update set',
      'raw_blob_hash = excluded.raw_blob_hash, body_blob_hash = excluded.body_blob_hash, headers_json = excluded.headers_json, size = excluded.size, encoding = excluded.encoding',
    ].join(' '));
    const insertTargetHost = this.database.prepare([
      'insert into target_hosts',
      '(id, host, scheme, port, scope_state, technology_summary_json, source, exchange_count, route_count, tags_json, notes, first_seen_at, last_seen_at, updated_at)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'scope_state = excluded.scope_state,',
      'technology_summary_json = case when excluded.technology_summary_json = \'{}\' then target_hosts.technology_summary_json else excluded.technology_summary_json end,',
      'source = excluded.source,',
      'exchange_count = target_hosts.exchange_count + excluded.exchange_count, tags_json = excluded.tags_json, notes = excluded.notes,',
      'last_seen_at = max(target_hosts.last_seen_at, excluded.last_seen_at), updated_at = excluded.updated_at',
    ].join(' '));
    const insertTargetRoute = this.database.prepare([
      'insert into target_routes',
      '(id, host_id, host, scheme, port, method, path, normalized_path, content_type, status, source, evidence_exchange_id, parameter_count, issue_count, tags_json, notes, first_seen_at, last_seen_at, updated_at)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'path = excluded.path, content_type = excluded.content_type, status = excluded.status, source = excluded.source,',
      'evidence_exchange_id = coalesce(excluded.evidence_exchange_id, target_routes.evidence_exchange_id), tags_json = excluded.tags_json, notes = excluded.notes,',
      'last_seen_at = max(target_routes.last_seen_at, excluded.last_seen_at), updated_at = excluded.updated_at',
    ].join(' '));
    const insertParameter = this.database.prepare([
      'insert into parameters',
      '(id, route_id, exchange_id, host, method, path, location, name, value_hash, value_sample, inferred_type, insertion_candidate, source, evidence_count, tags_json, notes, first_seen_at, last_seen_at, updated_at)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'exchange_id = coalesce(excluded.exchange_id, parameters.exchange_id), path = excluded.path, value_hash = excluded.value_hash,',
      'value_sample = excluded.value_sample, inferred_type = excluded.inferred_type, insertion_candidate = excluded.insertion_candidate,',
      'source = excluded.source, evidence_count = parameters.evidence_count + excluded.evidence_count, tags_json = excluded.tags_json, notes = excluded.notes,',
      'last_seen_at = max(parameters.last_seen_at, excluded.last_seen_at), updated_at = excluded.updated_at',
    ].join(' '));
    const updateRouteStats = this.database.prepare([
      'update target_routes set parameter_count = (select count(*) from parameters where route_id = ?), updated_at = ? where id = ?',
    ].join(' '));
    const updateHostStats = this.database.prepare([
      'update target_hosts set route_count = (select count(*) from target_routes where host_id = ?), updated_at = ? where id = ?',
    ].join(' '));

    this.database.exec('begin immediate');
    try {
      const inventoryRouteIds = new Set<string>();
      const inventoryHostIds = new Set<string>();
      for (const record of records) {
        insertExchange.run(
          record.id,
          record.method,
          record.url,
          record.host,
          record.path,
          record.protocol,
          record.status,
          record.mime,
          record.requestHash,
          record.responseHash,
          record.requestSize,
          record.responseSize,
          record.timingMs,
          record.source,
          JSON.stringify(record.tags),
          record.notes,
          record.scopeState,
          record.createdAt,
          record.updatedAt,
          record.requestIndex,
          record.responseIndex,
        );
        insertMessage.run(record.id, 'request', record.requestHash, record.requestHash, JSON.stringify(parseHeaders(record.requestRaw)), record.requestSize, 'raw');
        insertMessage.run(record.id, 'response', record.responseHash, record.responseHash, JSON.stringify(parseHeaders(record.responseRaw)), record.responseSize, 'raw');
        const inventory = deriveTargetInventoryFromExchange(record);
        insertTargetHost.run(
          inventory.host.id,
          inventory.host.host,
          inventory.host.scheme,
          inventory.host.port,
          inventory.host.scopeState,
          JSON.stringify(inventory.host.technologySummary),
          inventory.host.source,
          inventory.host.exchangeCount,
          inventory.host.routeCount,
          JSON.stringify(inventory.host.tags),
          inventory.host.notes,
          inventory.host.firstSeenAt,
          inventory.host.lastSeenAt,
          inventory.host.updatedAt,
        );
        insertTargetRoute.run(
          inventory.route.id,
          inventory.route.hostId,
          inventory.route.host,
          inventory.route.scheme,
          inventory.route.port,
          inventory.route.method,
          inventory.route.path,
          inventory.route.normalizedPath,
          inventory.route.contentType,
          inventory.route.status,
          inventory.route.source,
          inventory.route.evidenceExchangeId ?? null,
          inventory.route.parameterCount,
          inventory.route.issueCount,
          JSON.stringify(inventory.route.tags),
          inventory.route.notes,
          inventory.route.firstSeenAt,
          inventory.route.lastSeenAt,
          inventory.route.updatedAt,
        );
        for (const parameter of inventory.parameters) {
          insertParameter.run(
            parameter.id,
            parameter.routeId,
            parameter.exchangeId ?? null,
            parameter.host,
            parameter.method,
            parameter.path,
            parameter.location,
            parameter.name,
            parameter.valueHash,
            parameter.valueSample,
            parameter.inferredType,
            parameter.insertionCandidate ? 1 : 0,
            parameter.source,
            parameter.evidenceCount,
            JSON.stringify(parameter.tags),
            parameter.notes,
            parameter.firstSeenAt,
            parameter.lastSeenAt,
            parameter.updatedAt,
          );
        }
        inventoryRouteIds.add(inventory.route.id);
        inventoryHostIds.add(inventory.host.id);
      }
      const statsUpdatedAt = new Date().toISOString();
      for (const routeId of inventoryRouteIds) updateRouteStats.run(routeId, statsUpdatedAt, routeId);
      for (const hostId of inventoryHostIds) updateHostStats.run(hostId, statsUpdatedAt, hostId);
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(new Date().toISOString());
  }

  importSnapshot(snapshot: ProjectSnapshot) {
    return this.addHttpExchanges(snapshot.exchanges.map((exchange) => ({
      id: exchange.id,
      method: exchange.method,
      url: exchange.url,
      host: exchange.host,
      path: exchange.path,
      status: exchange.status,
      mime: exchange.mime,
      timingMs: exchange.timing,
      source: exchange.source,
      tags: exchange.tags,
      notes: exchange.notes,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      createdAt: exchange.time,
    })));
  }

  async importSnapshotContent(content: string, savedAt = new Date().toISOString()) {
    const snapshot = parseProjectSnapshotContent(content, savedAt);
    for (const scope of snapshot.scopeAllowlist) {
      await this.addScopeRule(scope, 'include', 'snapshot-import');
    }
    await this.importSnapshot(snapshot);
    return snapshot;
  }

  async upsertProjectSetting(input: ProjectStoreSettingInput) {
    await this.upsertProjectSettings([input]);
  }

  async addAuditEvent(input: ProjectStoreAuditEventInput): Promise<ProjectStoreAuditEventRecord> {
    const createdAt = input.createdAt?.trim() || new Date().toISOString();
    const action = input.action.trim();
    const targetRef = input.targetRef.trim();
    if (!action) throw new Error('Audit action is required.');
    if (!targetRef) throw new Error('Audit target is required.');
    const actor = input.actor?.trim() || 'local-operator';
    const decision = normalizeAuditDecision(input.decision);
    const detail = input.detail?.trim() || '';
    const previous = this.database.prepare('select hash from audit_events order by created_at desc, id desc limit 1').get() as Record<string, unknown> | undefined;
    const previousHash = typeof previous?.hash === 'string' ? previous.hash : undefined;
    const id = input.id?.trim() || `audit-${createdAt.replace(/[^0-9TZ]/g, '')}-${sha256(`${actor}:${action}:${targetRef}:${createdAt}:${previousHash ?? ''}`).slice(0, 12)}`;
    const unsigned = { id, actor, action, targetRef, decision, detail, createdAt, previousHash };
    const hash = sha256(canonicalize(unsigned));
    const record: ProjectStoreAuditEventRecord = { ...unsigned, hash };
    this.database.prepare([
      'insert into audit_events (id, actor, action, target_ref, decision, detail, created_at, previous_hash, hash)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?)',
    ].join(' ')).run(record.id, record.actor, record.action, record.targetRef, record.decision, record.detail, record.createdAt, record.previousHash ?? null, record.hash);
    await this.touchManifest(createdAt);
    return record;
  }

  listAuditEvents(limit = 200): ProjectStoreAuditEventRecord[] {
    const safeLimit = clampInteger(limit, 1, 1000);
    const rows = this.database.prepare('select * from audit_events order by created_at desc, id desc limit ?').all(safeLimit) as Record<string, unknown>[];
    return rows.map(rowToAuditEventRecord);
  }

  async upsertProjectSettings(inputs: ProjectStoreSettingInput[]) {
    if (inputs.length === 0) return;
    const now = new Date().toISOString();
    const records = inputs.map((input) => normalizeProjectSettingInput(input, now));
    const upsert = this.database.prepare([
      'insert into project_settings',
      '(id, category, key, value_json, value_sha256, source, enabled, notes, created_at, updated_at)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(category, key) do update set',
      'value_json = excluded.value_json, value_sha256 = excluded.value_sha256, source = excluded.source,',
      'enabled = excluded.enabled, notes = excluded.notes, updated_at = excluded.updated_at',
    ].join(' '));
    this.database.exec('begin immediate');
    try {
      for (const record of records) {
        upsert.run(
          record.id,
          record.category,
          record.key,
          JSON.stringify(record.value),
          record.valueSha256,
          record.source,
          record.enabled ? 1 : 0,
          record.notes,
          record.createdAt,
          record.updatedAt,
        );
      }
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
  }

  getProjectSetting(category: ProjectStoreSettingCategory, key: string): ProjectStoreSettingRecord | null {
    const normalizedCategory = normalizeProjectSettingCategory(category);
    const normalizedKey = key.trim();
    if (!normalizedKey) throw new Error('Project setting key is required.');
    const row = this.database.prepare('select * from project_settings where category = ? and key = ?').get(normalizedCategory, normalizedKey);
    return row ? rowToProjectSettingRecord(row) : null;
  }

  listProjectSettings(query: ProjectStoreSettingsQuery = {}): ProjectStoreSettingRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.category) {
      clauses.push('category = ?');
      params.push(normalizeProjectSettingCategory(query.category));
    }
    if (query.key) {
      clauses.push('key = ?');
      params.push(query.key.trim());
    }
    if (typeof query.enabled === 'boolean') {
      clauses.push('enabled = ?');
      params.push(query.enabled ? 1 : 0);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['category', 'key', 'value_json', 'source', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 200, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from project_settings',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by category asc, key asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToProjectSettingRecord);
  }

  exportProjectSettingsEvidence(query: ProjectStoreSettingsQuery = {}): ProjectStoreSettingsEvidencePackage {
    const limit = clampInteger(query.limit ?? 500, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const settings = this.listProjectSettings({ ...query, limit, offset });
    const categories = Array.from(new Set(settings.map((setting) => setting.category))).sort() as ProjectStoreSettingCategory[];
    const serializedSettings = JSON.stringify(settings);
    const hasCategory = (category: ProjectStoreSettingCategory) => categories.includes(category);
    const packageBody = {
      kind: 'proxyforge-project-store-settings-evidence-package',
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      projectId: this.manifest.projectId,
      projectName: this.manifest.projectName,
      query: {
        category: query.category,
        key: query.key,
        text: query.text,
        enabled: query.enabled,
        limit,
        offset,
      },
      stats: {
        settingCount: settings.length,
        categoryCount: categories.length,
        enabledCount: settings.filter((setting) => setting.enabled).length,
        disabledCount: settings.filter((setting) => !setting.enabled).length,
      },
      settings,
      categories,
      requirements: {
        scopeSettingsIncluded: hasCategory('scope'),
        proxySettingsIncluded: hasCategory('proxy'),
        scannerSettingsIncluded: hasCategory('scanner'),
        sessionSettingsIncluded: hasCategory('sessions'),
        oastSettingsIncluded: hasCategory('oast'),
        reportSettingsIncluded: hasCategory('reports'),
        networkSettingsIncluded: hasCategory('network'),
        rawOperationalSecretsPreserved: /Authorization|Bearer|Cookie|session|csrf|api[-_]?key|password|token/i.test(serializedSettings),
        restartReady: true,
        reportPhaseOnlyRedaction: true,
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
      summary: `Project Store settings evidence exported ${settings.length} setting(s) across ${categories.length} categor${categories.length === 1 ? 'y' : 'ies'}.`,
    } as const;
    return {
      ...packageBody,
      content: JSON.stringify(packageBody, null, 2),
    };
  }

  async upsertSessionCookie(input: ProjectStoreSessionCookieInput) {
    await this.upsertSessionCookies([input]);
  }

  async upsertSessionCookies(inputs: ProjectStoreSessionCookieInput[]) {
    if (inputs.length === 0) return;
    const now = new Date().toISOString();
    const records = inputs.map((input) => normalizeSessionCookieInput(input, now));
    const upsert = this.database.prepare([
      'insert into session_cookies',
      '(name, value, domain, path, secure, http_only, host_only, same_site, expires_at, source, created_at, updated_at, last_seen_at, value_sha256)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(domain, path, name) do update set',
      'value = excluded.value, secure = excluded.secure, http_only = excluded.http_only, host_only = excluded.host_only,',
      'same_site = excluded.same_site, expires_at = excluded.expires_at, source = excluded.source, updated_at = excluded.updated_at,',
      'last_seen_at = excluded.last_seen_at, value_sha256 = excluded.value_sha256',
    ].join(' '));
    this.database.exec('begin immediate');
    try {
      for (const record of records) {
        upsert.run(
          record.name,
          record.value,
          record.domain,
          record.path,
          record.secure ? 1 : 0,
          record.httpOnly ? 1 : 0,
          record.hostOnly ? 1 : 0,
          record.sameSite ?? null,
          record.expiresAt ?? null,
          record.source,
          record.createdAt,
          record.updatedAt,
          record.lastSeenAt,
          record.valueSha256,
        );
      }
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
  }

  getSessionCookie(domain: string, pathValue: string, name: string): ProjectStoreSessionCookieRecord | null {
    const row = this.database.prepare('select * from session_cookies where domain = ? and path = ? and name = ?')
      .get(normalizeCookieDomain(domain), normalizeCookiePath(pathValue), name.trim());
    return row ? rowToSessionCookieRecord(row) : null;
  }

  listSessionCookies(query: ProjectStoreSessionCookieQuery = {}): ProjectStoreSessionCookieRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.domain) {
      clauses.push('domain = ?');
      params.push(normalizeCookieDomain(query.domain));
    }
    if (query.path) {
      clauses.push('path = ?');
      params.push(normalizeCookiePath(query.path));
    }
    if (query.name) {
      clauses.push('name = ?');
      params.push(query.name.trim());
    }
    if (query.source) {
      clauses.push('source = ?');
      params.push(query.source.trim());
    }
    if (typeof query.secure === 'boolean') {
      clauses.push('secure = ?');
      params.push(query.secure ? 1 : 0);
    }
    if (typeof query.hostOnly === 'boolean') {
      clauses.push('host_only = ?');
      params.push(query.hostOnly ? 1 : 0);
    }
    if (!query.includeExpired) {
      clauses.push('(expires_at is null or expires_at > ?)');
      params.push(new Date().toISOString());
    }
    if (query.text) {
      clauses.push(likeAnyClause(['name', 'value', 'domain', 'path', 'source']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 200, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from session_cookies',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by domain asc, path asc, name asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToSessionCookieRecord);
  }

  exportSessionCookieJarEvidence(query: ProjectStoreSessionCookieQuery = {}): ProjectStoreSessionCookieEvidencePackage {
    const limit = clampInteger(query.limit ?? 500, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const cookies = this.listSessionCookies({ ...query, limit, offset });
    const now = new Date();
    const serialized = JSON.stringify(cookies);
    const domains = new Set(cookies.map((cookie) => cookie.domain));
    const packageBody = {
      kind: 'proxyforge-project-store-cookie-jar-evidence-package',
      schemaVersion: 1,
      generatedAt: now.toISOString(),
      projectId: this.manifest.projectId,
      projectName: this.manifest.projectName,
      query: {
        domain: query.domain,
        path: query.path,
        name: query.name,
        source: query.source,
        secure: query.secure,
        hostOnly: query.hostOnly,
        includeExpired: query.includeExpired,
        text: query.text,
        limit,
        offset,
      },
      stats: {
        cookieCount: cookies.length,
        domainCount: domains.size,
        secureCount: cookies.filter((cookie) => cookie.secure).length,
        hostOnlyCount: cookies.filter((cookie) => cookie.hostOnly).length,
        expiredCount: cookies.filter((cookie) => cookie.expiresAt && Date.parse(cookie.expiresAt) <= now.getTime()).length,
      },
      cookies,
      requirements: {
        cookiesPersisted: cookies.length > 0,
        domainPathRulesRepresented: cookies.some((cookie) => cookie.path !== '/') && domains.size > 1,
        secureCookiesRepresented: cookies.some((cookie) => cookie.secure),
        hostOnlyAndDomainCookiesRepresented: cookies.some((cookie) => cookie.hostOnly) && cookies.some((cookie) => !cookie.hostOnly),
        rawOperationalSecretsPreserved: /session=|csrf=|token|secret|api[-_]?key|password/i.test(serialized),
        restartReady: true,
        reportPhaseOnlyRedaction: true,
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
      summary: `Project Store cookie jar evidence exported ${cookies.length} cookie(s) across ${domains.size} domain(s).`,
    } as const;
    return {
      ...packageBody,
      content: JSON.stringify(packageBody, null, 2),
    };
  }

  searchHttpExchanges(query: ProjectStoreSearchQuery = {}): ProjectStoreHttpExchangeRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.method) {
      clauses.push('method = ?');
      params.push(query.method.toUpperCase());
    }
    if (query.host) {
      clauses.push('host = ?');
      params.push(query.host);
    }
    if (query.pathIncludes) {
      clauses.push(likeClause('path'));
      params.push(`%${escapeLike(query.pathIncludes)}%`);
    }
    if (typeof query.statusMin === 'number') {
      clauses.push('status >= ?');
      params.push(query.statusMin);
    }
    if (typeof query.statusMax === 'number') {
      clauses.push('status <= ?');
      params.push(query.statusMax);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['request_index', 'response_index', 'notes', 'tags_json']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from http_exchanges',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by created_at asc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToExchangeRecord);
  }

  getHttpExchange(id: string): ProjectStoreHttpExchangeFull | null {
    const row = this.database.prepare('select * from http_exchanges where id = ?').get(id);
    if (!row) return null;
    const record = rowToExchangeRecord(row);
    return {
      ...record,
      requestRaw: this.readBlobSync(record.requestHash),
      responseRaw: this.readBlobSync(record.responseHash),
    };
  }

  listTargetHosts(query: ProjectStoreTargetHostQuery = {}): ProjectStoreTargetHostRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.host) {
      clauses.push('host = ?');
      params.push(normalizeInventoryHost(query.host));
    }
    if (query.scheme) {
      clauses.push('scheme = ?');
      params.push(normalizeInventoryScheme(query.scheme));
    }
    if (query.scopeState) {
      clauses.push('scope_state = ?');
      params.push(query.scopeState.trim());
    }
    if (query.source) {
      clauses.push('source = ?');
      params.push(normalizeTargetInventorySource(query.source));
    }
    if (query.text) {
      clauses.push(likeAnyClause(['host', 'technology_summary_json', 'tags_json', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from target_hosts',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by last_seen_at desc, host asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToTargetHostRecord);
  }

  getTargetHost(id: string): ProjectStoreTargetHostRecord | null {
    const row = this.database.prepare('select * from target_hosts where id = ?').get(id.trim());
    return row ? rowToTargetHostRecord(row) : null;
  }

  listTargetRoutes(query: ProjectStoreTargetRouteQuery = {}): ProjectStoreTargetRouteRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.host) {
      clauses.push('host = ?');
      params.push(normalizeInventoryHost(query.host));
    }
    if (query.method) {
      clauses.push('method = ?');
      params.push(query.method.trim().toUpperCase());
    }
    if (query.pathIncludes) {
      clauses.push(likeAnyClause(['path', 'normalized_path']));
      const pathQuery = `%${escapeLike(query.pathIncludes)}%`;
      params.push(pathQuery, pathQuery);
    }
    if (query.normalizedPath) {
      clauses.push('normalized_path = ?');
      params.push(normalizeRoutePath(query.normalizedPath));
    }
    if (query.source) {
      clauses.push('source = ?');
      params.push(normalizeTargetInventorySource(query.source));
    }
    if (typeof query.hasParameters === 'boolean') {
      clauses.push(query.hasParameters ? 'parameter_count > 0' : 'parameter_count = 0');
    }
    if (query.text) {
      clauses.push(likeAnyClause(['host', 'path', 'normalized_path', 'content_type', 'tags_json', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from target_routes',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by last_seen_at desc, host asc, method asc, normalized_path asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToTargetRouteRecord);
  }

  getTargetRoute(id: string): ProjectStoreTargetRouteRecord | null {
    const row = this.database.prepare('select * from target_routes where id = ?').get(id.trim());
    return row ? rowToTargetRouteRecord(row) : null;
  }

  listParameters(query: ProjectStoreParameterQuery = {}): ProjectStoreParameterRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.routeId) {
      clauses.push('route_id = ?');
      params.push(query.routeId.trim());
    }
    if (query.exchangeId) {
      clauses.push('exchange_id = ?');
      params.push(query.exchangeId.trim());
    }
    if (query.host) {
      clauses.push('host = ?');
      params.push(normalizeInventoryHost(query.host));
    }
    if (query.method) {
      clauses.push('method = ?');
      params.push(query.method.trim().toUpperCase());
    }
    if (query.location) {
      clauses.push('location = ?');
      params.push(normalizeParameterLocation(query.location));
    }
    if (query.name) {
      clauses.push('name = ?');
      params.push(query.name.trim());
    }
    if (typeof query.insertionCandidate === 'boolean') {
      clauses.push('insertion_candidate = ?');
      params.push(query.insertionCandidate ? 1 : 0);
    }
    if (query.source) {
      clauses.push('source = ?');
      params.push(normalizeTargetInventorySource(query.source));
    }
    if (query.text) {
      clauses.push(likeAnyClause(['host', 'path', 'location', 'name', 'value_sample', 'inferred_type', 'tags_json', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 200, 1, 10000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from parameters',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by last_seen_at desc, host asc, path asc, location asc, name asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToParameterRecord);
  }

  getParameter(id: string): ProjectStoreParameterRecord | null {
    const row = this.database.prepare('select * from parameters where id = ?').get(id.trim());
    return row ? rowToParameterRecord(row) : null;
  }

  async addCallbackPayload(input: ProjectStoreCallbackPayloadInput) {
    await this.addCallbackPayloads([input]);
  }

  async addCallbackPayloads(inputs: ProjectStoreCallbackPayloadInput[]) {
    if (inputs.length === 0) return;
    const now = new Date().toISOString();
    const insert = this.database.prepare([
      'insert into callback_payloads',
      '(id, token, label, protocol, endpoint, status, source_exchange_id, source_host, source_path, notes, created_at, updated_at, last_interaction_at)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'token = excluded.token, label = excluded.label, protocol = excluded.protocol, endpoint = excluded.endpoint, status = excluded.status,',
      'source_exchange_id = excluded.source_exchange_id, source_host = excluded.source_host, source_path = excluded.source_path, notes = excluded.notes,',
      'updated_at = excluded.updated_at, last_interaction_at = coalesce(excluded.last_interaction_at, callback_payloads.last_interaction_at)',
    ].join(' '));
    this.database.exec('begin immediate');
    try {
      for (const input of inputs) {
        const record = normalizeCallbackPayloadInput(input, now);
        insert.run(
          record.id,
          record.token,
          record.label,
          record.protocol,
          record.endpoint,
          record.status,
          record.sourceExchangeId ?? null,
          record.sourceHost,
          record.sourcePath,
          record.notes,
          record.createdAt,
          record.updatedAt,
          record.lastInteractionAt ?? null,
        );
      }
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
  }

  async addCallbackInteraction(input: ProjectStoreCallbackInteractionInput) {
    await this.addCallbackInteractions([input]);
  }

  async addCallbackInteractions(inputs: ProjectStoreCallbackInteractionInput[]) {
    if (inputs.length === 0) return;
    const now = new Date().toISOString();
    const records = [];
    for (const input of inputs) {
      const raw = toBuffer(input.raw);
      const rawHash = await this.writeBlob(raw);
      records.push(normalizeCallbackInteractionInput(input, raw, rawHash, now));
    }

    const insert = this.database.prepare([
      'insert into callback_interactions',
      '(id, payload_id, protocol, observed_at, source_ip, source_host, request_line, user_agent, raw_hash, raw_size, severity, tags_json, created_at, raw_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'payload_id = excluded.payload_id, protocol = excluded.protocol, observed_at = excluded.observed_at, source_ip = excluded.source_ip,',
      'source_host = excluded.source_host, request_line = excluded.request_line, user_agent = excluded.user_agent, raw_hash = excluded.raw_hash,',
      'raw_size = excluded.raw_size, severity = excluded.severity, tags_json = excluded.tags_json, raw_index = excluded.raw_index',
    ].join(' '));
    const updatePayload = this.database.prepare([
      'update callback_payloads set status = ?, last_interaction_at = ?, updated_at = ? where id = ?',
    ].join(' '));

    this.database.exec('begin immediate');
    try {
      for (const record of records) {
        insert.run(
          record.id,
          record.payloadId,
          record.protocol,
          record.observedAt,
          record.sourceIp,
          record.sourceHost,
          record.requestLine,
          record.userAgent,
          record.rawHash,
          record.rawSize,
          record.severity,
          JSON.stringify(record.tags),
          record.createdAt,
          record.rawIndex,
        );
        if (record.payloadId !== 'unmatched') {
          updatePayload.run('observed', record.observedAt, now, record.payloadId);
        }
      }
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
  }

  listCallbackPayloads(query: ProjectStoreCallbackQuery = {}): ProjectStoreCallbackPayloadRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.payloadId) {
      clauses.push('payloads.id = ?');
      params.push(query.payloadId);
    }
    if (query.protocol) {
      clauses.push('payloads.protocol = ?');
      params.push(query.protocol);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['payloads.token', 'payloads.endpoint', 'payloads.label', 'payloads.notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select payloads.*, count(interactions.id) as interaction_count',
      'from callback_payloads payloads',
      'left join callback_interactions interactions on interactions.payload_id = payloads.id',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'group by payloads.id',
      'order by payloads.created_at asc, payloads.id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToCallbackPayloadRecord);
  }

  listCallbackInteractions(query: ProjectStoreCallbackQuery = {}): ProjectStoreCallbackInteractionRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.payloadId) {
      clauses.push('payload_id = ?');
      params.push(query.payloadId);
    }
    if (query.protocol) {
      clauses.push('protocol = ?');
      params.push(query.protocol);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['raw_index', 'request_line', 'user_agent', 'tags_json']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from callback_interactions',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by observed_at asc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToCallbackInteractionRecord);
  }

  getCallbackInteraction(id: string): ProjectStoreCallbackInteractionFull | null {
    const row = this.database.prepare('select * from callback_interactions where id = ?').get(id);
    if (!row) return null;
    const record = rowToCallbackInteractionRecord(row);
    return {
      ...record,
      raw: this.readBlobSync(record.rawHash),
    };
  }

  async upsertRepeaterTab(input: ProjectStoreRepeaterTabInput) {
    await this.upsertRepeaterTabs([input]);
  }

  async upsertRepeaterTabs(inputs: ProjectStoreRepeaterTabInput[]) {
    if (inputs.length === 0) return;
    const now = new Date().toISOString();
    const records = [];
    for (const input of inputs) {
      const rawRequest = toBuffer(input.rawRequest);
      const requestHash = await this.writeBlob(rawRequest);
      records.push(normalizeRepeaterTabInput(input, rawRequest, requestHash, now));
    }

    const upsert = this.database.prepare([
      'insert into repeater_tabs',
      '(id, name, target_url, host, method, path, request_hash, request_size, group_name, source_exchange_id, last_replay_id, last_status, dirty, tags_json, notes, created_at, updated_at, request_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'name = excluded.name, target_url = excluded.target_url, host = excluded.host, method = excluded.method, path = excluded.path,',
      'request_hash = excluded.request_hash, request_size = excluded.request_size, group_name = excluded.group_name,',
      'source_exchange_id = excluded.source_exchange_id, last_replay_id = excluded.last_replay_id, last_status = excluded.last_status,',
      'dirty = excluded.dirty, tags_json = excluded.tags_json, notes = excluded.notes, updated_at = excluded.updated_at, request_index = excluded.request_index',
    ].join(' '));
    this.database.exec('begin immediate');
    try {
      for (const record of records) {
        upsert.run(
          record.id,
          record.name,
          record.targetUrl,
          record.host,
          record.method,
          record.path,
          record.requestHash,
          record.requestSize,
          record.group,
          record.sourceExchangeId ?? null,
          record.lastReplayId ?? null,
          record.lastStatus,
          record.dirty ? 1 : 0,
          JSON.stringify(record.tags),
          record.notes,
          record.createdAt,
          record.updatedAt,
          record.requestIndex,
        );
      }
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
  }

  async addRepeaterSend(input: ProjectStoreRepeaterSendInput): Promise<ProjectStoreRepeaterSendRecord> {
    const records = await this.addRepeaterSends([input]);
    return records[0];
  }

  async addRepeaterSends(inputs: ProjectStoreRepeaterSendInput[]): Promise<ProjectStoreRepeaterSendRecord[]> {
    if (inputs.length === 0) return [];
    const now = new Date().toISOString();
    const records = [];
    for (const input of inputs) {
      const rawRequest = toBuffer(input.rawRequest);
      const responseRaw = toBuffer(input.responseRaw);
      const requestHash = await this.writeBlob(rawRequest);
      const responseHash = await this.writeBlob(responseRaw);
      records.push(normalizeRepeaterSendInput(input, rawRequest, responseRaw, requestHash, responseHash, now));
    }

    const insert = this.database.prepare([
      'insert into repeater_sends',
      '(id, tab_id, exchange_id, target_url, host, method, path, protocol, status, mime, request_hash, response_hash, request_size, response_size, timing_ms, source_exchange_id, session_profile_id, oast_payload_ids_json, tags_json, notes, created_at, request_index, response_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'tab_id = excluded.tab_id, exchange_id = excluded.exchange_id, target_url = excluded.target_url, host = excluded.host, method = excluded.method,',
      'path = excluded.path, protocol = excluded.protocol, status = excluded.status, mime = excluded.mime, request_hash = excluded.request_hash,',
      'response_hash = excluded.response_hash, request_size = excluded.request_size, response_size = excluded.response_size, timing_ms = excluded.timing_ms,',
      'source_exchange_id = excluded.source_exchange_id, session_profile_id = excluded.session_profile_id,',
      'oast_payload_ids_json = excluded.oast_payload_ids_json, tags_json = excluded.tags_json, notes = excluded.notes, request_index = excluded.request_index, response_index = excluded.response_index',
    ].join(' '));
    this.database.exec('begin immediate');
    try {
      for (const record of records) {
        insert.run(
          record.id,
          record.tabId ?? null,
          record.exchangeId ?? null,
          record.targetUrl,
          record.host,
          record.method,
          record.path,
          record.protocol,
          record.status,
          record.mime,
          record.requestHash,
          record.responseHash,
          record.requestSize,
          record.responseSize,
          record.timingMs,
          record.sourceExchangeId ?? null,
          record.sessionProfileId ?? null,
          JSON.stringify(record.oastPayloadIds),
          JSON.stringify(record.tags),
          record.notes,
          record.createdAt,
          record.requestIndex,
          record.responseIndex,
        );
      }
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
    return records.map(({ rawRequest, responseRaw, requestIndex, responseIndex, ...record }) => record);
  }

  listRepeaterTabs(query: ProjectStoreRepeaterTabQuery = {}): ProjectStoreRepeaterTabRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.group) {
      clauses.push('group_name = ?');
      params.push(query.group.trim());
    }
    if (query.host) {
      clauses.push('host = ?');
      params.push(query.host.trim());
    }
    if (typeof query.dirty === 'boolean') {
      clauses.push('dirty = ?');
      params.push(query.dirty ? 1 : 0);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['name', 'target_url', 'request_index', 'tags_json', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from repeater_tabs',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by updated_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToRepeaterTabRecord);
  }

  getRepeaterTab(id: string): ProjectStoreRepeaterTabFull | null {
    const row = this.database.prepare('select * from repeater_tabs where id = ?').get(id);
    if (!row) return null;
    const record = rowToRepeaterTabRecord(row);
    return {
      ...record,
      rawRequest: this.readBlobSync(record.requestHash),
    };
  }

  listRepeaterSends(query: ProjectStoreRepeaterSendQuery = {}): ProjectStoreRepeaterSendRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.tabId) {
      clauses.push('tab_id = ?');
      params.push(query.tabId.trim());
    }
    if (query.exchangeId) {
      clauses.push('exchange_id = ?');
      params.push(query.exchangeId.trim());
    }
    if (query.sourceExchangeId) {
      clauses.push('source_exchange_id = ?');
      params.push(query.sourceExchangeId.trim());
    }
    if (query.host) {
      clauses.push('host = ?');
      params.push(query.host.trim());
    }
    if (typeof query.statusMin === 'number') {
      clauses.push('status >= ?');
      params.push(query.statusMin);
    }
    if (typeof query.statusMax === 'number') {
      clauses.push('status <= ?');
      params.push(query.statusMax);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['target_url', 'request_index', 'response_index', 'tags_json', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from repeater_sends',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by created_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToRepeaterSendRecord);
  }

  getRepeaterSend(id: string): ProjectStoreRepeaterSendFull | null {
    const row = this.database.prepare('select * from repeater_sends where id = ?').get(id);
    if (!row) return null;
    const record = rowToRepeaterSendRecord(row);
    return {
      ...record,
      rawRequest: this.readBlobSync(record.requestHash),
      responseRaw: this.readBlobSync(record.responseHash),
    };
  }

  async upsertWebSocketConnection(input: ProjectStoreWebSocketConnectionInput) {
    await this.upsertWebSocketConnections([input]);
  }

  async upsertWebSocketConnections(inputs: ProjectStoreWebSocketConnectionInput[]) {
    if (inputs.length === 0) return;
    const now = new Date().toISOString();
    const records = inputs.map((input) => normalizeWebSocketConnectionInput(input, now));
    const upsert = this.database.prepare([
      'insert into websocket_connections',
      '(id, url, host, path, protocol, parent_exchange_id, first_frame_at, last_frame_at, frame_count, client_frame_count, server_frame_count, tags_json, notes, created_at, updated_at)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'url = excluded.url, host = excluded.host, path = excluded.path, protocol = excluded.protocol, parent_exchange_id = excluded.parent_exchange_id,',
      'tags_json = excluded.tags_json, notes = excluded.notes, updated_at = excluded.updated_at',
    ].join(' '));
    this.database.exec('begin immediate');
    try {
      for (const record of records) {
        upsert.run(
          record.id,
          record.url,
          record.host,
          record.path,
          record.protocol,
          record.parentExchangeId ?? null,
          record.firstFrameAt ?? null,
          record.lastFrameAt ?? null,
          record.frameCount,
          record.clientFrameCount,
          record.serverFrameCount,
          JSON.stringify(record.tags),
          record.notes,
          record.createdAt,
          record.updatedAt,
        );
      }
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
  }

  async addWebSocketFrame(input: ProjectStoreWebSocketFrameInput): Promise<ProjectStoreWebSocketFrameRecord> {
    const records = await this.addWebSocketFrames([input]);
    return records[0];
  }

  async addWebSocketFrames(inputs: ProjectStoreWebSocketFrameInput[]): Promise<ProjectStoreWebSocketFrameRecord[]> {
    if (inputs.length === 0) return [];
    const now = new Date().toISOString();
    const records = [];
    const connectionInputs = new Map<string, ProjectStoreWebSocketConnectionInput>();
    for (const input of inputs) {
      const payload = webSocketPayloadToBuffer(input.payload, input.payloadEncoding);
      const payloadHash = await this.writeBlob(payload);
      const record = normalizeWebSocketFrameInput(input, payload, payloadHash, now);
      records.push(record);
      if (!connectionInputs.has(record.connectionId)) {
        connectionInputs.set(record.connectionId, {
          id: record.connectionId,
          url: record.url,
          host: record.host,
          path: record.path,
          protocol: safeUrl(record.url).protocol.replace(':', '') || 'ws',
          tags: ['websocket'],
          createdAt: record.createdAt,
          updatedAt: now,
        });
      }
    }

    const upsertConnection = this.database.prepare([
      'insert into websocket_connections',
      '(id, url, host, path, protocol, parent_exchange_id, first_frame_at, last_frame_at, frame_count, client_frame_count, server_frame_count, tags_json, notes, created_at, updated_at)',
      'values (?, ?, ?, ?, ?, ?, null, null, 0, 0, 0, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'url = excluded.url, host = excluded.host, path = excluded.path, protocol = excluded.protocol, updated_at = excluded.updated_at',
    ].join(' '));
    const insertFrame = this.database.prepare([
      'insert into websocket_frames',
      '(id, connection_id, direction, host, path, url, opcode, type, payload_hash, payload_size, payload_encoding, intercepted, modified, dropped, replayed, rewritten, tags_json, notes, source, created_at, payload_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'connection_id = excluded.connection_id, direction = excluded.direction, host = excluded.host, path = excluded.path, url = excluded.url,',
      'opcode = excluded.opcode, type = excluded.type, payload_hash = excluded.payload_hash, payload_size = excluded.payload_size,',
      'payload_encoding = excluded.payload_encoding, intercepted = excluded.intercepted, modified = excluded.modified, dropped = excluded.dropped,',
      'replayed = excluded.replayed, rewritten = excluded.rewritten, tags_json = excluded.tags_json, notes = excluded.notes, source = excluded.source, payload_index = excluded.payload_index',
    ].join(' '));

    this.database.exec('begin immediate');
    try {
      for (const connection of connectionInputs.values()) {
        const normalized = normalizeWebSocketConnectionInput(connection, now);
        upsertConnection.run(
          normalized.id,
          normalized.url,
          normalized.host,
          normalized.path,
          normalized.protocol,
          normalized.parentExchangeId ?? null,
          JSON.stringify(normalized.tags),
          normalized.notes,
          normalized.createdAt,
          normalized.updatedAt,
        );
      }
      for (const record of records) {
        insertFrame.run(
          record.id,
          record.connectionId,
          record.direction,
          record.host,
          record.path,
          record.url,
          record.opcode,
          record.type,
          record.payloadHash,
          record.payloadSize,
          record.payloadEncoding,
          record.intercepted ? 1 : 0,
          record.modified ? 1 : 0,
          record.dropped ? 1 : 0,
          record.replayed ? 1 : 0,
          record.rewritten ? 1 : 0,
          JSON.stringify(record.tags),
          record.notes,
          record.source,
          record.createdAt,
          record.payloadIndex,
        );
      }
      this.refreshWebSocketConnectionStats([...connectionInputs.keys()], now);
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
    return records.map(({ payloadIndex, ...record }) => record);
  }

  listWebSocketConnections(query: ProjectStoreWebSocketConnectionQuery = {}): ProjectStoreWebSocketConnectionRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.host) {
      clauses.push('host = ?');
      params.push(query.host.trim());
    }
    if (query.text) {
      clauses.push(likeAnyClause(['url', 'host', 'path', 'tags_json', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from websocket_connections',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by last_frame_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToWebSocketConnectionRecord);
  }

  listWebSocketFrames(query: ProjectStoreWebSocketFrameQuery = {}): ProjectStoreWebSocketFrameRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.connectionId) {
      clauses.push('connection_id = ?');
      params.push(query.connectionId.trim());
    }
    if (query.direction) {
      clauses.push('direction = ?');
      params.push(normalizeWebSocketDirection(query.direction));
    }
    if (query.type) {
      clauses.push('type = ?');
      params.push(normalizeWebSocketFrameType(query.type));
    }
    if (query.host) {
      clauses.push('host = ?');
      params.push(query.host.trim());
    }
    if (query.text) {
      clauses.push(likeAnyClause(['url', 'path', 'payload_index', 'tags_json', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from websocket_frames',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by created_at asc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToWebSocketFrameRecord);
  }

  getWebSocketFrame(id: string): ProjectStoreWebSocketFrameFull | null {
    const row = this.database.prepare('select * from websocket_frames where id = ?').get(id);
    if (!row) return null;
    const record = rowToWebSocketFrameRecord(row);
    return {
      ...record,
      payload: this.readBlobSync(record.payloadHash),
    };
  }

  async addIntruderAttack(input: ProjectStoreIntruderAttackInput): Promise<ProjectStoreIntruderAttackRecord> {
    const now = new Date().toISOString();
    const rawRequest = toBuffer(input.rawRequest);
    const baseRequestHash = await this.writeBlob(rawRequest);
    const record = normalizeIntruderAttackInput(input, rawRequest, baseRequestHash, now);
    const upsertAttack = this.database.prepare([
      'insert into intruder_attacks',
      '(id, target_url, host, path, attack_mode, base_request_hash, base_request_size, payload_positions, total_requests, retained_result_count, blocked, message, payloads_json, payload_sets_json, payload_processors_json, payload_rules_json, scope_allowlist_json, start_offset, next_offset, has_more, payload_plan_count, payload_rule_count, resource_pool_name, resource_pool_max_concurrent, stream_summary_json, oast_summary_json, tags_json, notes, started_at, completed_at, created_at, updated_at, request_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'target_url = excluded.target_url, host = excluded.host, path = excluded.path, attack_mode = excluded.attack_mode,',
      'base_request_hash = excluded.base_request_hash, base_request_size = excluded.base_request_size, payload_positions = excluded.payload_positions,',
      'total_requests = excluded.total_requests, retained_result_count = excluded.retained_result_count, blocked = excluded.blocked, message = excluded.message,',
      'payloads_json = excluded.payloads_json, payload_sets_json = excluded.payload_sets_json, payload_processors_json = excluded.payload_processors_json,',
      'payload_rules_json = excluded.payload_rules_json, scope_allowlist_json = excluded.scope_allowlist_json, start_offset = excluded.start_offset,',
      'next_offset = excluded.next_offset, has_more = excluded.has_more, payload_plan_count = excluded.payload_plan_count, payload_rule_count = excluded.payload_rule_count,',
      'resource_pool_name = excluded.resource_pool_name, resource_pool_max_concurrent = excluded.resource_pool_max_concurrent, stream_summary_json = excluded.stream_summary_json,',
      'oast_summary_json = excluded.oast_summary_json, tags_json = excluded.tags_json, notes = excluded.notes, completed_at = excluded.completed_at, updated_at = excluded.updated_at, request_index = excluded.request_index',
    ].join(' '));
    this.database.exec('begin immediate');
    try {
      upsertAttack.run(
        record.id,
        record.targetUrl,
        record.host,
        record.path,
        record.attackMode,
        record.baseRequestHash,
        record.baseRequestSize,
        record.payloadPositions,
        record.totalRequests,
        record.retainedResultCount,
        record.blocked ? 1 : 0,
        record.message,
        JSON.stringify(record.payloads),
        JSON.stringify(record.payloadSets),
        JSON.stringify(record.payloadProcessors),
        JSON.stringify(record.payloadRules),
        JSON.stringify(record.scopeAllowlist),
        record.startOffset ?? null,
        record.nextOffset ?? null,
        record.hasMore ? 1 : 0,
        record.payloadPlanCount,
        record.payloadRuleCount,
        record.resourcePoolName,
        record.resourcePoolMaxConcurrent,
        JSON.stringify(record.streamSummary),
        JSON.stringify(record.oastSummary),
        JSON.stringify(record.tags),
        record.notes,
        record.startedAt,
        record.completedAt,
        record.createdAt,
        record.updatedAt,
        record.requestIndex,
      );
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    if (input.results?.length) {
      await this.addIntruderResults(input.results.map((result, index) => ({
        attackId: record.id,
        rowIndex: index,
        result,
        createdAt: record.completedAt,
      })));
    }
    await this.touchManifest(now);
    const { requestIndex, ...publicRecord } = record;
    return publicRecord;
  }

  async addIntruderResults(inputs: ProjectStoreIntruderResultInput[]): Promise<ProjectStoreIntruderResultRecord[]> {
    if (inputs.length === 0) return [];
    const now = new Date().toISOString();
    const records = [];
    for (const input of inputs) {
      const requestRaw = toBuffer(input.result.requestRaw);
      const responseRaw = toBuffer(input.result.responseRaw);
      const requestHash = await this.writeBlob(requestRaw);
      const responseHash = await this.writeBlob(responseRaw);
      records.push(normalizeIntruderResultInput(input, requestRaw, responseRaw, requestHash, responseHash, now));
    }
    const insert = this.database.prepare([
      'insert into intruder_results',
      '(id, attack_id, row_index, payload, payloads_json, attack_mode, status, length, mime, timing_ms, request_hash, response_hash, request_size, response_size, grep_matches_json, extract_matches_json, oast_payload_ids_json, callback_interaction_ids_json, tags_json, notes, created_at, request_index, response_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'attack_id = excluded.attack_id, row_index = excluded.row_index, payload = excluded.payload, payloads_json = excluded.payloads_json, attack_mode = excluded.attack_mode,',
      'status = excluded.status, length = excluded.length, mime = excluded.mime, timing_ms = excluded.timing_ms, request_hash = excluded.request_hash, response_hash = excluded.response_hash,',
      'request_size = excluded.request_size, response_size = excluded.response_size, grep_matches_json = excluded.grep_matches_json, extract_matches_json = excluded.extract_matches_json,',
      'oast_payload_ids_json = excluded.oast_payload_ids_json, callback_interaction_ids_json = excluded.callback_interaction_ids_json, tags_json = excluded.tags_json,',
      'notes = excluded.notes, request_index = excluded.request_index, response_index = excluded.response_index',
    ].join(' '));
    const updateAttack = this.database.prepare('update intruder_attacks set retained_result_count = (select count(*) from intruder_results where attack_id = ?), updated_at = ? where id = ?');
    const attackIds = new Set(records.map((record) => record.attackId));
    this.database.exec('begin immediate');
    try {
      for (const record of records) {
        insert.run(
          record.id,
          record.attackId,
          record.rowIndex,
          record.payload,
          JSON.stringify(record.payloads),
          record.attackMode,
          record.status,
          record.length,
          record.mime,
          record.timing,
          record.requestHash,
          record.responseHash,
          record.requestSize,
          record.responseSize,
          JSON.stringify(record.grepMatches),
          JSON.stringify(record.extractMatches),
          JSON.stringify(record.oastPayloadIds),
          JSON.stringify(record.callbackInteractionIds),
          JSON.stringify(record.tags),
          record.notes,
          record.createdAt,
          record.requestIndex,
          record.responseIndex,
        );
      }
      for (const attackId of attackIds) updateAttack.run(attackId, now, attackId);
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
    return records.map(({ requestIndex, responseIndex, ...record }) => record);
  }

  listIntruderAttacks(query: ProjectStoreIntruderAttackQuery = {}): ProjectStoreIntruderAttackRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.host) {
      clauses.push('host = ?');
      params.push(query.host.trim());
    }
    if (query.attackMode) {
      clauses.push('attack_mode = ?');
      params.push(normalizeIntruderAttackMode(query.attackMode));
    }
    if (typeof query.blocked === 'boolean') {
      clauses.push('blocked = ?');
      params.push(query.blocked ? 1 : 0);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['target_url', 'request_index', 'message', 'payloads_json', 'payload_sets_json', 'tags_json', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from intruder_attacks',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by started_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToIntruderAttackRecord);
  }

  getIntruderAttack(id: string): ProjectStoreIntruderAttackFull | null {
    const row = this.database.prepare('select * from intruder_attacks where id = ?').get(id);
    if (!row) return null;
    const record = rowToIntruderAttackRecord(row);
    return {
      ...record,
      rawRequest: this.readBlobSync(record.baseRequestHash),
    };
  }

  listIntruderResults(query: ProjectStoreIntruderResultQuery = {}): ProjectStoreIntruderResultRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.attackId) {
      clauses.push('attack_id = ?');
      params.push(query.attackId.trim());
    }
    if (typeof query.statusMin === 'number') {
      clauses.push('status >= ?');
      params.push(query.statusMin);
    }
    if (typeof query.statusMax === 'number') {
      clauses.push('status <= ?');
      params.push(query.statusMax);
    }
    if (query.grep) {
      clauses.push(likeClause('grep_matches_json'));
      params.push(`%${escapeLike(query.grep)}%`);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['payload', 'payloads_json', 'request_index', 'response_index', 'grep_matches_json', 'extract_matches_json', 'tags_json', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from intruder_results',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by row_index asc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToIntruderResultRecord);
  }

  getIntruderResult(id: string): ProjectStoreIntruderResultFull | null {
    const row = this.database.prepare('select * from intruder_results where id = ?').get(id);
    if (!row) return null;
    const record = rowToIntruderResultRecord(row);
    return {
      ...record,
      requestRaw: this.readBlobSync(record.requestHash),
      responseRaw: this.readBlobSync(record.responseHash),
    };
  }

  async addScannerTask(input: ProjectStoreScannerTaskInput): Promise<ProjectStoreScannerTaskRecord> {
    const now = new Date().toISOString();
    const exchanges = input.exchanges ?? input.summary.exchanges ?? [];
    if (exchanges.length) {
      await this.addHttpExchanges(exchanges.map((exchange) => ({
        id: exchange.id,
        method: exchange.method,
        url: exchange.url,
        host: exchange.host,
        path: exchange.path,
        status: exchange.status,
        mime: exchange.mime,
        timingMs: exchange.timing,
        source: exchange.source,
        tags: exchange.tags,
        notes: exchange.notes,
        requestRaw: exchange.requestRaw,
        responseRaw: exchange.responseRaw,
        createdAt: exchange.time,
        scopeState: exchange.tags.includes('blocked-by-scope') ? 'blocked' : 'scanned',
      })));
    }
    const record = normalizeScannerTaskInput(input, exchanges, now);
    const findings = [
      ...input.summary.findings.map((finding) => normalizeScannerFindingInput({
        taskId: record.id,
        finding,
        suppressed: false,
        createdAt: record.completedAt,
      }, now)),
      ...input.summary.suppressedFindings.map((finding) => normalizeScannerFindingInput({
        taskId: record.id,
        finding,
        suppressed: true,
        suppressionReason: finding.reason,
        createdAt: record.completedAt,
      }, now)),
    ];
    const upsertTask = this.database.prepare([
      'insert into scanner_tasks',
      '(id, kind, target_url, host, path, requested_checks_json, scope_allowlist_json, total_requests, exchange_ids_json, finding_count, suppressed_finding_count, blocked, message, tuning_json, tags_json, notes, started_at, completed_at, created_at, updated_at)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'kind = excluded.kind, target_url = excluded.target_url, host = excluded.host, path = excluded.path,',
      'requested_checks_json = excluded.requested_checks_json, scope_allowlist_json = excluded.scope_allowlist_json, total_requests = excluded.total_requests,',
      'exchange_ids_json = excluded.exchange_ids_json, finding_count = excluded.finding_count, suppressed_finding_count = excluded.suppressed_finding_count,',
      'blocked = excluded.blocked, message = excluded.message, tuning_json = excluded.tuning_json, tags_json = excluded.tags_json, notes = excluded.notes,',
      'completed_at = excluded.completed_at, updated_at = excluded.updated_at',
    ].join(' '));
    const upsertFinding = this.database.prepare([
      'insert into scanner_findings',
      '(id, task_id, check_id, title, severity, confidence, host, path, detail, remediation, evidence_exchange_id, dedupe_key, confidence_reason, suppressed, suppression_reason, tags_json, created_at)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'task_id = excluded.task_id, check_id = excluded.check_id, title = excluded.title, severity = excluded.severity, confidence = excluded.confidence,',
      'host = excluded.host, path = excluded.path, detail = excluded.detail, remediation = excluded.remediation, evidence_exchange_id = excluded.evidence_exchange_id,',
      'dedupe_key = excluded.dedupe_key, confidence_reason = excluded.confidence_reason, suppressed = excluded.suppressed, suppression_reason = excluded.suppression_reason, tags_json = excluded.tags_json',
    ].join(' '));
    this.database.exec('begin immediate');
    try {
      upsertTask.run(
        record.id,
        record.kind,
        record.targetUrl,
        record.host,
        record.path,
        JSON.stringify(record.requestedChecks),
        JSON.stringify(record.scopeAllowlist),
        record.totalRequests,
        JSON.stringify(record.exchangeIds),
        record.findingCount,
        record.suppressedFindingCount,
        record.blocked ? 1 : 0,
        record.message,
        JSON.stringify(record.tuning),
        JSON.stringify(record.tags),
        record.notes,
        record.startedAt,
        record.completedAt,
        record.createdAt,
        record.updatedAt,
      );
      for (const finding of findings) {
        upsertFinding.run(
          finding.id,
          finding.taskId,
          finding.checkId,
          finding.title,
          finding.severity,
          finding.confidence,
          finding.host,
          finding.path,
          finding.detail,
          finding.remediation,
          finding.evidenceExchangeId ?? null,
          finding.dedupeKey,
          finding.confidenceReason,
          finding.suppressed ? 1 : 0,
          finding.suppressionReason,
          JSON.stringify(finding.tags),
          finding.createdAt,
        );
      }
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
    return record;
  }

  listScannerTasks(query: ProjectStoreScannerTaskQuery = {}): ProjectStoreScannerTaskRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.kind) {
      clauses.push('kind = ?');
      params.push(normalizeScannerTaskKind(query.kind));
    }
    if (query.host) {
      clauses.push('host = ?');
      params.push(query.host.trim());
    }
    if (typeof query.blocked === 'boolean') {
      clauses.push('blocked = ?');
      params.push(query.blocked ? 1 : 0);
    }
    if (query.checkId) {
      clauses.push(likeClause('requested_checks_json'));
      params.push(`%${escapeLike(normalizeActiveScanCheckId(query.checkId))}%`);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['target_url', 'message', 'requested_checks_json', 'exchange_ids_json', 'tags_json', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from scanner_tasks',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by started_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToScannerTaskRecord);
  }

  getScannerTask(id: string): ProjectStoreScannerTaskRecord | null {
    const row = this.database.prepare('select * from scanner_tasks where id = ?').get(id);
    return row ? rowToScannerTaskRecord(row) : null;
  }

  listScannerFindings(query: ProjectStoreScannerFindingQuery = {}): ProjectStoreScannerFindingRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.taskId) {
      clauses.push('task_id = ?');
      params.push(query.taskId.trim());
    }
    if (query.checkId) {
      clauses.push('check_id = ?');
      params.push(normalizeActiveScanCheckId(query.checkId));
    }
    if (query.severity) {
      clauses.push('severity = ?');
      params.push(normalizeIssueSeverity(query.severity));
    }
    if (query.confidence) {
      clauses.push('confidence = ?');
      params.push(normalizeIssueConfidence(query.confidence));
    }
    if (typeof query.suppressed === 'boolean') {
      clauses.push('suppressed = ?');
      params.push(query.suppressed ? 1 : 0);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['title', 'detail', 'remediation', 'dedupe_key', 'confidence_reason', 'suppression_reason', 'tags_json']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from scanner_findings',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by created_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToScannerFindingRecord);
  }

  getScannerFinding(id: string): ProjectStoreScannerFindingFull | null {
    const row = this.database.prepare('select * from scanner_findings where id = ?').get(id);
    if (!row) return null;
    const record = rowToScannerFindingRecord(row);
    return {
      ...record,
      evidenceExchange: record.evidenceExchangeId ? this.getHttpExchange(record.evidenceExchangeId) ?? undefined : undefined,
    };
  }

  async upsertIssue(input: ProjectStoreIssueInput) {
    await this.upsertIssues([input]);
  }

  async upsertIssues(inputs: ProjectStoreIssueInput[]) {
    if (inputs.length === 0) return;
    const now = new Date().toISOString();
    const records = inputs.map((input) => normalizeIssueInput(input, now));
    const upsert = this.database.prepare([
      'insert into issues',
      '(id, title, type, severity, confidence, status, host, path, detail, remediation, evidence_refs_json, dedupe_key, source, assignee, triage_note, created_at, updated_at, last_triaged_at)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'title = excluded.title, type = excluded.type, severity = excluded.severity, confidence = excluded.confidence, status = excluded.status,',
      'host = excluded.host, path = excluded.path, detail = excluded.detail, remediation = excluded.remediation,',
      'evidence_refs_json = excluded.evidence_refs_json, dedupe_key = excluded.dedupe_key, source = excluded.source,',
      'assignee = excluded.assignee, triage_note = excluded.triage_note, updated_at = excluded.updated_at, last_triaged_at = excluded.last_triaged_at',
    ].join(' '));
    this.database.exec('begin immediate');
    try {
      for (const record of records) {
        upsert.run(
          record.id,
          record.title,
          record.type,
          record.severity,
          record.confidence,
          record.status,
          record.host,
          record.path,
          record.detail,
          record.remediation,
          JSON.stringify(record.evidenceRefs),
          record.dedupeKey,
          record.source,
          record.assignee ?? null,
          record.triageNote,
          record.createdAt,
          record.updatedAt,
          record.lastTriagedAt ?? null,
        );
      }
      this.database.exec('commit');
    } catch (error) {
      this.database.exec('rollback');
      throw error;
    }
    await this.touchManifest(now);
  }

  listIssues(query: ProjectStoreIssueQuery = {}): ProjectStoreIssueRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.severity) {
      clauses.push('severity = ?');
      params.push(normalizeIssueSeverity(query.severity));
    }
    if (query.status) {
      clauses.push('status = ?');
      params.push(normalizeIssueStatus(query.status));
    }
    if (query.host) {
      clauses.push('host = ?');
      params.push(query.host.trim());
    }
    if (query.source) {
      clauses.push('source = ?');
      params.push(query.source.trim());
    }
    if (query.text) {
      clauses.push(likeAnyClause(['title', 'type', 'detail', 'remediation', 'evidence_refs_json', 'dedupe_key']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from issues',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by updated_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToIssueRecord);
  }

  getIssue(id: string): ProjectStoreIssueRecord | null {
    const row = this.database.prepare('select * from issues where id = ?').get(id);
    return row ? rowToIssueRecord(row) : null;
  }

  async addReportExport(input: ProjectStoreReportExportInput): Promise<ProjectStoreReportExportRecord> {
    const now = new Date().toISOString();
    const content = toBuffer(input.content);
    const contentHash = await this.writeBlob(content);
    const record = normalizeReportExportInput(input, content, contentHash, now);
    this.database.prepare([
      'insert into reports',
      '(id, format, file_name, path, content_hash, content_size, issue_ids_json, exchange_ids_json, template_id, sections_json, prepared_for, engagement_id, bundle_hash, signature_status, signer_name, key_id, redacted, notes, created_at, content_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'format = excluded.format, file_name = excluded.file_name, path = excluded.path, content_hash = excluded.content_hash, content_size = excluded.content_size,',
      'issue_ids_json = excluded.issue_ids_json, exchange_ids_json = excluded.exchange_ids_json, template_id = excluded.template_id, sections_json = excluded.sections_json,',
      'prepared_for = excluded.prepared_for, engagement_id = excluded.engagement_id, bundle_hash = excluded.bundle_hash, signature_status = excluded.signature_status,',
      'signer_name = excluded.signer_name, key_id = excluded.key_id, redacted = excluded.redacted, notes = excluded.notes, content_index = excluded.content_index',
    ].join(' ')).run(
      record.id,
      record.format,
      record.fileName,
      record.path,
      record.contentHash,
      record.contentSize,
      JSON.stringify(record.issueIds),
      JSON.stringify(record.exchangeIds),
      record.templateId,
      JSON.stringify(record.sections),
      record.preparedFor,
      record.engagementId,
      record.bundleHash ?? null,
      record.signatureStatus,
      record.signerName,
      record.keyId,
      record.redacted ? 1 : 0,
      record.notes,
      record.createdAt,
      record.contentIndex,
    );
    await this.touchManifest(record.createdAt);
    const { contentIndex, ...publicRecord } = record;
    return publicRecord;
  }

  listReportExports(query: ProjectStoreReportExportQuery = {}): ProjectStoreReportExportRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.format) {
      clauses.push('format = ?');
      params.push(query.format);
    }
    if (query.issueId) {
      clauses.push(likeClause('issue_ids_json'));
      params.push(`%${escapeLike(query.issueId)}%`);
    }
    if (query.text) {
      clauses.push(likeAnyClause(['file_name', 'path', 'content_index', 'notes']));
      const textQuery = `%${escapeLike(query.text)}%`;
      params.push(textQuery, textQuery, textQuery, textQuery);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from reports',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by created_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToReportExportRecord);
  }

  getReportExport(id: string): ProjectStoreReportExportFull | null {
    const row = this.database.prepare('select * from reports where id = ?').get(id);
    if (!row) return null;
    const record = rowToReportExportRecord(row);
    return {
      ...record,
      content: this.readBlobSync(record.contentHash),
    };
  }

  async addAutomationRun(input: ProjectStoreAutomationRunInput): Promise<ProjectStoreAutomationRunRecord> {
    if (input.exchange) await this.addHttpExchange(httpExchangeToProjectStoreInput(input.exchange, input.exchange.source || 'automation', 'automation'));
    if (input.issue) await this.upsertIssue(input.issue);
    const now = new Date().toISOString();
    const record = normalizeAutomationRunInput(input, now);
    this.database.prepare([
      'insert into automation_runs',
      '(id, workflow_id, workflow_name, status, trigger, started_at, completed_at, duration_ms, total_requests, exchange_id, issue_id,',
      'scheduler_job_id, scheduler_lease_id, ci_provider, ci_config, logs_json, raw_material_json, tags_json, notes, created_at, updated_at, search_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'workflow_id = excluded.workflow_id, workflow_name = excluded.workflow_name, status = excluded.status, trigger = excluded.trigger,',
      'started_at = excluded.started_at, completed_at = excluded.completed_at, duration_ms = excluded.duration_ms, total_requests = excluded.total_requests,',
      'exchange_id = excluded.exchange_id, issue_id = excluded.issue_id, scheduler_job_id = excluded.scheduler_job_id, scheduler_lease_id = excluded.scheduler_lease_id,',
      'ci_provider = excluded.ci_provider, ci_config = excluded.ci_config, logs_json = excluded.logs_json, raw_material_json = excluded.raw_material_json,',
      'tags_json = excluded.tags_json, notes = excluded.notes, updated_at = excluded.updated_at, search_index = excluded.search_index',
    ].join(' ')).run(
      record.id,
      record.workflowId,
      record.workflowName,
      record.status,
      record.trigger,
      record.startedAt,
      record.completedAt,
      record.durationMs,
      record.totalRequests,
      record.exchangeId ?? null,
      record.issueId ?? null,
      record.schedulerJobId ?? null,
      record.schedulerLeaseId ?? null,
      record.ciProvider ?? null,
      record.ciConfig,
      JSON.stringify(record.logs),
      JSON.stringify(record.operationalRawMaterial),
      JSON.stringify(record.tags),
      record.notes,
      record.createdAt,
      record.updatedAt,
      automationRunSearchIndex(record),
    );
    await this.touchManifest(record.updatedAt);
    return record;
  }

  listAutomationRuns(query: ProjectStoreAutomationRunQuery = {}): ProjectStoreAutomationRunRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.workflowId) {
      clauses.push('workflow_id = ?');
      params.push(query.workflowId.trim());
    }
    if (query.status) {
      clauses.push('status = ?');
      params.push(normalizeAutomationRunStatus(query.status));
    }
    if (query.trigger) {
      clauses.push('trigger = ?');
      params.push(query.trigger.trim());
    }
    if (query.text) {
      clauses.push(likeClause('search_index'));
      params.push(`%${escapeLike(query.text)}%`);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from automation_runs',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by started_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToAutomationRunRecord);
  }

  getAutomationRun(id: string): ProjectStoreAutomationRunFull | null {
    const row = this.database.prepare('select * from automation_runs where id = ?').get(id.trim());
    if (!row) return null;
    const record = rowToAutomationRunRecord(row);
    return {
      ...record,
      exchange: record.exchangeId ? this.getHttpExchange(record.exchangeId) ?? undefined : undefined,
      issue: record.issueId ? this.getIssue(record.issueId) ?? undefined : undefined,
    };
  }

  async addAiRun(input: ProjectStoreAiRunInput): Promise<ProjectStoreAiRunRecord> {
    const now = new Date().toISOString();
    const output = toBuffer(input.output);
    const prompt = input.prompt === undefined ? undefined : toBuffer(input.prompt);
    const outputHash = await this.writeBlob(output);
    const promptHash = prompt ? await this.writeBlob(prompt) : undefined;
    const record = normalizeAiRunInput(input, output, prompt, outputHash, promptHash, now);
    this.database.prepare([
      'insert into ai_runs',
      '(id, provider_id, task, status, model, started_at, completed_at, summary, output_hash, output_size, prompt_hash, prompt_size,',
      'evidence_count, command, provider_label, context_digest, usage_json, stream_events_json, prompt_evaluation_json, suggested_actions_json, tags_json, notes, created_at, updated_at, search_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'provider_id = excluded.provider_id, task = excluded.task, status = excluded.status, model = excluded.model, started_at = excluded.started_at,',
      'completed_at = excluded.completed_at, summary = excluded.summary, output_hash = excluded.output_hash, output_size = excluded.output_size,',
      'prompt_hash = excluded.prompt_hash, prompt_size = excluded.prompt_size, evidence_count = excluded.evidence_count, command = excluded.command,',
      'provider_label = excluded.provider_label, context_digest = excluded.context_digest, usage_json = excluded.usage_json,',
      'stream_events_json = excluded.stream_events_json, prompt_evaluation_json = excluded.prompt_evaluation_json, suggested_actions_json = excluded.suggested_actions_json,',
      'tags_json = excluded.tags_json, notes = excluded.notes, updated_at = excluded.updated_at, search_index = excluded.search_index',
    ].join(' ')).run(
      record.id,
      record.providerId,
      record.task,
      record.status,
      record.model,
      record.startedAt,
      record.completedAt,
      record.summary,
      record.outputHash,
      record.outputSize,
      record.promptHash ?? null,
      record.promptSize,
      record.evidenceCount,
      record.command ?? null,
      record.providerLabel ?? null,
      record.contextDigest ?? null,
      JSON.stringify(record.usage),
      JSON.stringify(record.streamEvents),
      JSON.stringify(record.promptEvaluation),
      JSON.stringify(record.suggestedActions),
      JSON.stringify(record.tags),
      record.notes,
      record.createdAt,
      record.updatedAt,
      aiRunSearchIndex(record, prompt, output),
    );
    await this.touchManifest(record.updatedAt);
    return record;
  }

  listAiRuns(query: ProjectStoreAiRunQuery = {}): ProjectStoreAiRunRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.providerId) {
      clauses.push('provider_id = ?');
      params.push(query.providerId.trim());
    }
    if (query.task) {
      clauses.push('task = ?');
      params.push(query.task.trim());
    }
    if (query.status) {
      clauses.push('status = ?');
      params.push(normalizeAiRunStatus(query.status));
    }
    if (query.text) {
      clauses.push(likeClause('search_index'));
      params.push(`%${escapeLike(query.text)}%`);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from ai_runs',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by started_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToAiRunRecord);
  }

  getAiRun(id: string): ProjectStoreAiRunFull | null {
    const row = this.database.prepare('select * from ai_runs where id = ?').get(id.trim());
    if (!row) return null;
    const record = rowToAiRunRecord(row);
    return {
      ...record,
      output: this.readBlobSync(record.outputHash),
      prompt: record.promptHash ? this.readBlobSync(record.promptHash) : undefined,
    };
  }

  async addExtensionRun(input: ProjectStoreExtensionRunInput): Promise<ProjectStoreExtensionRunRecord> {
    if (input.exchange) await this.addHttpExchange(httpExchangeToProjectStoreInput(input.exchange, input.exchange.source || 'extension', 'extension'));
    if (input.issue) await this.upsertIssue(input.issue);
    const now = new Date().toISOString();
    const record = normalizeExtensionRunInput(input, now);
    this.database.prepare([
      'insert into extension_runs',
      '(id, extension_id, extension_name, hook, status, target, started_at, completed_at, summary, logs_json, issue_id, exchange_id, tags_json, notes, created_at, updated_at, search_index)',
      'values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
      'on conflict(id) do update set',
      'extension_id = excluded.extension_id, extension_name = excluded.extension_name, hook = excluded.hook, status = excluded.status, target = excluded.target,',
      'started_at = excluded.started_at, completed_at = excluded.completed_at, summary = excluded.summary, logs_json = excluded.logs_json,',
      'issue_id = excluded.issue_id, exchange_id = excluded.exchange_id, tags_json = excluded.tags_json, notes = excluded.notes, updated_at = excluded.updated_at, search_index = excluded.search_index',
    ].join(' ')).run(
      record.id,
      record.extensionId,
      record.extensionName,
      record.hook,
      record.status,
      record.target,
      record.startedAt,
      record.completedAt,
      record.summary,
      JSON.stringify(record.logs),
      record.issueId ?? null,
      record.exchangeId ?? null,
      JSON.stringify(record.tags),
      record.notes,
      record.createdAt,
      record.updatedAt,
      extensionRunSearchIndex(record),
    );
    await this.touchManifest(record.updatedAt);
    return record;
  }

  listExtensionRuns(query: ProjectStoreExtensionRunQuery = {}): ProjectStoreExtensionRunRecord[] {
    const clauses = [];
    const params: unknown[] = [];
    if (query.extensionId) {
      clauses.push('extension_id = ?');
      params.push(query.extensionId.trim());
    }
    if (query.hook) {
      clauses.push('hook = ?');
      params.push(query.hook.trim());
    }
    if (query.status) {
      clauses.push('status = ?');
      params.push(normalizeExtensionRunStatus(query.status));
    }
    if (query.text) {
      clauses.push(likeClause('search_index'));
      params.push(`%${escapeLike(query.text)}%`);
    }
    const limit = clampInteger(query.limit ?? 100, 1, 5000);
    const offset = clampInteger(query.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const rows = this.database.prepare([
      'select * from extension_runs',
      clauses.length ? `where ${clauses.join(' and ')}` : '',
      'order by started_at desc, id asc',
      'limit ? offset ?',
    ].filter(Boolean).join(' ')).all(...params, limit, offset);
    return rows.map(rowToExtensionRunRecord);
  }

  getExtensionRun(id: string): ProjectStoreExtensionRunFull | null {
    const row = this.database.prepare('select * from extension_runs where id = ?').get(id.trim());
    if (!row) return null;
    const record = rowToExtensionRunRecord(row);
    return {
      ...record,
      issue: record.issueId ? this.getIssue(record.issueId) ?? undefined : undefined,
      exchange: record.exchangeId ? this.getHttpExchange(record.exchangeId) ?? undefined : undefined,
    };
  }

  exportSignedCallbackEvidence(options: ProjectStoreCallbackEvidenceExportOptions = {}): ProjectStoreCallbackEvidencePackage {
    const generatedAt = options.generatedAt ?? new Date().toISOString();
    const limit = clampInteger(options.limit ?? 500, 1, 5000);
    const offset = clampInteger(options.offset ?? 0, 0, Number.MAX_SAFE_INTEGER);
    const payloads = this.listCallbackPayloads({
      payloadId: options.payloadId,
      protocol: options.protocol,
      text: options.text,
      limit,
      offset,
    });
    const payloadIds = new Set(payloads.map((payload) => payload.id));
    const interactionRows = payloads.flatMap((payload) => this.listCallbackInteractions({ payloadId: payload.id, limit: 5000 }));
    const interactions = interactionRows
      .filter((interaction) => payloadIds.has(interaction.payloadId))
      .map((interaction) => {
        const full = this.getCallbackInteraction(interaction.id);
        const raw = full?.raw ?? Buffer.alloc(0);
        return {
          ...interaction,
          raw: raw.toString('utf8'),
          rawSha256: sha256(raw),
        };
      });
    const sourceExchangeIds = Array.from(new Set(payloads.map((payload) => payload.sourceExchangeId).filter(Boolean) as string[]));
    const sourceExchanges = sourceExchangeIds.flatMap((id) => {
      const exchange = this.getHttpExchange(id);
      if (!exchange) return [];
      return [{
        ...exchange,
        requestRaw: exchange.requestRaw.toString('utf8'),
        responseRaw: exchange.responseRaw.toString('utf8'),
        requestSha256: sha256(exchange.requestRaw),
        responseSha256: sha256(exchange.responseRaw),
      }];
    });
    const rawMaterial = [
      ...interactions.map((interaction) => interaction.raw),
      ...sourceExchanges.flatMap((exchange) => [exchange.requestRaw, exchange.responseRaw]),
    ];
    const requirements = {
      payloadsIncluded: payloads.length > 0,
      interactionsIncluded: interactions.length > 0,
      rawInteractionsPreserved: interactions.every((interaction) => interaction.raw.length > 0 && interaction.rawSha256 === sha256(interaction.raw)),
      sourceExchangesLinked: sourceExchangeIds.length === 0 || sourceExchanges.length === sourceExchangeIds.length,
      hmacSignatureCovered: true,
      operationalSecretsPreserved: rawMaterial.some((value) => /Authorization:|Cookie:|X-API-Key:|Bearer|session=|token/i.test(value)),
      reportPhaseOnlyRedaction: true,
    };
    const unsigned = {
      kind: 'proxyforge-project-store-callback-evidence-package',
      schemaVersion: 1,
      generatedAt,
      projectId: this.manifest.projectId,
      projectName: this.manifest.projectName,
      query: {
        payloadId: options.payloadId,
        protocol: options.protocol,
        text: options.text,
        limit,
        offset,
      },
      stats: {
        payloadCount: payloads.length,
        interactionCount: interactions.length,
        sourceExchangeCount: sourceExchanges.length,
        rawInteractionBytes: interactions.reduce((total, interaction) => total + Buffer.byteLength(interaction.raw), 0),
      },
      payloads,
      interactions,
      sourceExchanges,
      requirements,
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
      reportReady: true,
      summary: `Project Store callback evidence exported ${payloads.length} payload(s), ${interactions.length} interaction(s), and ${sourceExchanges.length} source exchange(s).`,
    } as const;
    const canonical = canonicalize(unsigned);
    const packageDigestSha256 = sha256(canonical);
    const signingSecret = options.signingSecret ?? `${this.manifest.projectId}:project-store-callback-evidence`;
    const signature = {
      algorithm: 'HMAC-SHA256' as const,
      canonicalization: 'proxyforge-project-store-callback-evidence-v1' as const,
      keyId: options.keyId?.trim() || 'project-store-callback-local',
      signerName: options.signerName?.trim() || 'ProxyForge Project Store',
      signedAt: generatedAt,
      packageDigestSha256,
      signature: createHmac('sha256', signingSecret).update(canonical).digest('hex'),
      status: 'signed' as const,
    };
    const signed = { ...unsigned, signature };
    return {
      ...signed,
      content: JSON.stringify(signed, null, 2),
    };
  }

  stats(): ProjectStoreStats {
    const exchangeRow = this.database.prepare([
      'select count(*) as exchangeCount, coalesce(sum(request_size), 0) as requestBytes, coalesce(sum(response_size), 0) as responseBytes',
      'from http_exchanges',
    ].join(' ')).get() as Record<string, unknown>;
    const scopeRow = this.database.prepare('select count(*) as scopeRuleCount from scope_rules').get() as Record<string, unknown>;
    const auditRow = this.database.prepare('select count(*) as auditEventCount from audit_events').get() as Record<string, unknown>;
    const settingsRow = this.database.prepare('select count(*) as projectSettingCount from project_settings').get() as Record<string, unknown>;
    const sessionCookieRow = this.database.prepare('select count(*) as sessionCookieCount from session_cookies').get() as Record<string, unknown>;
    const targetHostRow = this.database.prepare('select count(*) as targetHostCount from target_hosts').get() as Record<string, unknown>;
    const targetRouteRow = this.database.prepare('select count(*) as targetRouteCount from target_routes').get() as Record<string, unknown>;
    const parameterRow = this.database.prepare('select count(*) as parameterCount from parameters').get() as Record<string, unknown>;
    const callbackPayloadRow = this.database.prepare('select count(*) as callbackPayloadCount from callback_payloads').get() as Record<string, unknown>;
    const callbackInteractionRow = this.database.prepare('select count(*) as callbackInteractionCount, coalesce(sum(raw_size), 0) as callbackBytes from callback_interactions').get() as Record<string, unknown>;
    const repeaterTabRow = this.database.prepare('select count(*) as repeaterTabCount from repeater_tabs').get() as Record<string, unknown>;
    const repeaterSendRow = this.database.prepare([
      'select count(*) as repeaterSendCount, coalesce(sum(request_size), 0) as repeaterRequestBytes, coalesce(sum(response_size), 0) as repeaterResponseBytes',
      'from repeater_sends',
    ].join(' ')).get() as Record<string, unknown>;
    const webSocketConnectionRow = this.database.prepare('select count(*) as webSocketConnectionCount from websocket_connections').get() as Record<string, unknown>;
    const webSocketFrameRow = this.database.prepare('select count(*) as webSocketFrameCount, coalesce(sum(payload_size), 0) as webSocketPayloadBytes from websocket_frames').get() as Record<string, unknown>;
    const intruderAttackRow = this.database.prepare('select count(*) as intruderAttackCount from intruder_attacks').get() as Record<string, unknown>;
    const intruderResultRow = this.database.prepare([
      'select count(*) as intruderResultCount, coalesce(sum(request_size), 0) as intruderRequestBytes, coalesce(sum(response_size), 0) as intruderResponseBytes',
      'from intruder_results',
    ].join(' ')).get() as Record<string, unknown>;
    const scannerTaskRow = this.database.prepare('select count(*) as scannerTaskCount from scanner_tasks').get() as Record<string, unknown>;
    const scannerFindingRow = this.database.prepare([
      'select count(*) as scannerFindingCount, coalesce(sum(case when suppressed = 1 then 1 else 0 end), 0) as scannerSuppressedFindingCount',
      'from scanner_findings',
    ].join(' ')).get() as Record<string, unknown>;
    const issueRow = this.database.prepare('select count(*) as issueCount from issues').get() as Record<string, unknown>;
    const reportRow = this.database.prepare('select count(*) as reportExportCount, coalesce(sum(content_size), 0) as reportBytes from reports').get() as Record<string, unknown>;
    const automationRunRow = this.database.prepare('select count(*) as automationRunCount from automation_runs').get() as Record<string, unknown>;
    const aiRunRow = this.database.prepare([
      'select count(*) as aiRunCount, coalesce(sum(prompt_size), 0) as aiPromptBytes, coalesce(sum(output_size), 0) as aiOutputBytes',
      'from ai_runs',
    ].join(' ')).get() as Record<string, unknown>;
    const extensionRunRow = this.database.prepare('select count(*) as extensionRunCount from extension_runs').get() as Record<string, unknown>;
    const blobRow = this.database.prepare([
      'select count(distinct raw_blob_hash) as blobCount from (',
      'select raw_blob_hash from http_messages',
      'union all',
      'select raw_hash as raw_blob_hash from callback_interactions',
      'union all',
      'select request_hash as raw_blob_hash from repeater_tabs',
      'union all',
      'select request_hash as raw_blob_hash from repeater_sends',
      'union all',
      'select response_hash as raw_blob_hash from repeater_sends',
      'union all',
      'select payload_hash as raw_blob_hash from websocket_frames',
      'union all',
      'select base_request_hash as raw_blob_hash from intruder_attacks',
      'union all',
      'select request_hash as raw_blob_hash from intruder_results',
      'union all',
      'select response_hash as raw_blob_hash from intruder_results',
      'union all',
      'select content_hash as raw_blob_hash from reports',
      'union all',
      'select output_hash as raw_blob_hash from ai_runs',
      'union all',
      'select prompt_hash as raw_blob_hash from ai_runs where prompt_hash is not null',
      ')',
    ].join(' ')).get() as Record<string, unknown>;
    return {
      projectName: this.manifest.projectName,
      schemaVersion: CURRENT_SCHEMA_VERSION,
      exchangeCount: Number(exchangeRow.exchangeCount ?? 0),
      scopeRuleCount: Number(scopeRow.scopeRuleCount ?? 0),
      auditEventCount: Number(auditRow.auditEventCount ?? 0),
      projectSettingCount: Number(settingsRow.projectSettingCount ?? 0),
      sessionCookieCount: Number(sessionCookieRow.sessionCookieCount ?? 0),
      targetHostCount: Number(targetHostRow.targetHostCount ?? 0),
      targetRouteCount: Number(targetRouteRow.targetRouteCount ?? 0),
      parameterCount: Number(parameterRow.parameterCount ?? 0),
      callbackPayloadCount: Number(callbackPayloadRow.callbackPayloadCount ?? 0),
      callbackInteractionCount: Number(callbackInteractionRow.callbackInteractionCount ?? 0),
      repeaterTabCount: Number(repeaterTabRow.repeaterTabCount ?? 0),
      repeaterSendCount: Number(repeaterSendRow.repeaterSendCount ?? 0),
      webSocketConnectionCount: Number(webSocketConnectionRow.webSocketConnectionCount ?? 0),
      webSocketFrameCount: Number(webSocketFrameRow.webSocketFrameCount ?? 0),
      intruderAttackCount: Number(intruderAttackRow.intruderAttackCount ?? 0),
      intruderResultCount: Number(intruderResultRow.intruderResultCount ?? 0),
      scannerTaskCount: Number(scannerTaskRow.scannerTaskCount ?? 0),
      scannerFindingCount: Number(scannerFindingRow.scannerFindingCount ?? 0),
      scannerSuppressedFindingCount: Number(scannerFindingRow.scannerSuppressedFindingCount ?? 0),
      issueCount: Number(issueRow.issueCount ?? 0),
      reportExportCount: Number(reportRow.reportExportCount ?? 0),
      automationRunCount: Number(automationRunRow.automationRunCount ?? 0),
      aiRunCount: Number(aiRunRow.aiRunCount ?? 0),
      extensionRunCount: Number(extensionRunRow.extensionRunCount ?? 0),
      blobCount: Number(blobRow.blobCount ?? 0),
      requestBytes: Number(exchangeRow.requestBytes ?? 0),
      responseBytes: Number(exchangeRow.responseBytes ?? 0),
      callbackBytes: Number(callbackInteractionRow.callbackBytes ?? 0),
      repeaterRequestBytes: Number(repeaterSendRow.repeaterRequestBytes ?? 0),
      repeaterResponseBytes: Number(repeaterSendRow.repeaterResponseBytes ?? 0),
      webSocketPayloadBytes: Number(webSocketFrameRow.webSocketPayloadBytes ?? 0),
      intruderRequestBytes: Number(intruderResultRow.intruderRequestBytes ?? 0),
      intruderResponseBytes: Number(intruderResultRow.intruderResponseBytes ?? 0),
      reportBytes: Number(reportRow.reportBytes ?? 0),
      aiPromptBytes: Number(aiRunRow.aiPromptBytes ?? 0),
      aiOutputBytes: Number(aiRunRow.aiOutputBytes ?? 0),
    };
  }

  exportManifest() {
    return { ...this.manifest };
  }

  async recoverPendingHttpExchanges(): Promise<ProjectStoreRecoveryReport> {
    const recoveredAt = new Date().toISOString();
    await ensurePrivateProjectStoreDirectory(recoveryRoot(this.rootDir));
    const pending = await readPendingHttpExchangeJournal(this.rootDir);
    const committed = await readCommittedHttpExchangeJournal(this.rootDir);
    const committedIds = new Set(committed.map((record) => record.id));
    const candidates = pending.filter((record) => !committedIds.has(record.exchange.id));
    const recoveredIds: string[] = [];
    const skippedIds: string[] = [];
    const failedIds: string[] = [];
    const recoverable = [];
    for (const record of candidates) {
      if (this.getHttpExchange(record.exchange.id)) {
        skippedIds.push(record.exchange.id);
        await appendCommittedHttpExchangeJournal(this.rootDir, record.exchange.id, 'already-in-store');
        continue;
      }
      recoverable.push(record.exchange);
    }
    for (const exchange of recoverable) {
      try {
        await this.addHttpExchange(exchange);
        await appendCommittedHttpExchangeJournal(this.rootDir, exchange.id, 'recovered');
        recoveredIds.push(exchange.id);
      } catch {
        failedIds.push(exchange.id);
      }
    }
    const rawJournal = pending.map((record) => [
      record.exchange.requestRaw,
      record.exchange.responseRaw,
      JSON.stringify(record),
    ].map((value) => Buffer.isBuffer(value) ? value.toString('utf8') : String(value)).join('\n')).join('\n');
    return {
      kind: 'proxyforge-project-store-recovery-report',
      schemaVersion: 1,
      rootDir: this.rootDir,
      recoveredAt,
      journalPath: pendingJournalPath(this.rootDir),
      committedJournalPath: committedJournalPath(this.rootDir),
      pendingRecordCount: pending.length,
      committedRecordCount: committed.length,
      recoveredHttpExchangeCount: recoveredIds.length,
      skippedCommittedCount: pending.filter((record) => committedIds.has(record.exchange.id)).length,
      skippedExistingCount: skippedIds.length,
      failedCount: failedIds.length,
      recoveredIds,
      skippedIds,
      failedIds,
      requirements: {
        durableJournalPresent: pending.length > 0 || await fileExists(pendingJournalPath(this.rootDir)),
        recoveryReplayAttempted: candidates.length > 0,
        sqliteWalEnabled: this.sqliteJournalMode().toLowerCase().includes('wal'),
        rawOperationalSecretsPreserved: /Authorization:|Bearer|Cookie:|session=|token|api[-_]?key|secret/i.test(rawJournal),
        reportPhaseOnlyRedaction: true,
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
      summary: `Project Store recovery replayed ${recoveredIds.length} pending HTTP exchange(s), skipped ${skippedIds.length} already-present exchange(s), and left ${failedIds.length} failed record(s).`,
    };
  }

  async createBackup(backupRootDir: string, options: ProjectStoreBackupOptions = {}): Promise<ProjectStoreBackupResult> {
    const createdAt = options.createdAt?.trim() || new Date().toISOString();
    const label = sanitizeBackupLabel(options.label || this.manifest.projectName || 'project-store');
    const backupDir = path.join(backupRootDir, `${label}-${createdAt.replace(/[:.]/g, '-')}.proxyforge-backup`);
    await this.recoverPendingHttpExchanges();
    this.database.exec('pragma wal_checkpoint(full)');
    await fs.mkdir(backupDir, { recursive: true });
    await copyIfExists(manifestPath(this.rootDir), manifestPath(backupDir));
    await copyIfExists(databasePath(this.rootDir), databasePath(backupDir));
    await copyDirectoryIfExists(blobRoot(this.rootDir), blobRoot(backupDir));
    await copyDirectoryIfExists(recoveryRoot(this.rootDir), recoveryRoot(backupDir));
    const stats = this.stats();
    const manifest: ProjectStoreBackupManifest = {
      kind: 'proxyforge-project-store-backup',
      schemaVersion: 1,
      projectId: this.manifest.projectId,
      projectName: this.manifest.projectName,
      sourceRootDir: this.rootDir,
      backupRootDir,
      backupDir,
      label,
      createdAt,
      stats,
      requirements: {
        manifestCopied: await fileExists(manifestPath(backupDir)),
        databaseCopied: await fileExists(databasePath(backupDir)),
        blobsCopied: await fileExists(blobRoot(backupDir)),
        recoveryJournalCopied: await fileExists(recoveryRoot(backupDir)),
        rawOperationalSecretsPreserved: true,
        reportPhaseOnlyRedaction: true,
      },
      secretHandling: 'execution-full-fidelity-secrets-preserved',
      reportRedactionBoundary: 'redact-only-during-report-export',
    };
    const manifestFile = path.join(backupDir, 'backup-manifest.json');
    await writeJsonAtomic(manifestFile, manifest);
    return {
      ...manifest,
      manifestPath: manifestFile,
      content: JSON.stringify(manifest, null, 2),
    };
  }

  close() {
    this.database.close();
  }

  private applyMigrations() {
    this.database.exec('pragma journal_mode = wal');
    this.database.exec('pragma synchronous = normal');
    this.database.exec('pragma foreign_keys = on');
    const applied = new Set((this.database.prepare('select name from sqlite_master where type = ? and name = ?').all('table', 'migrations') as Record<string, unknown>[])
      .map((row) => String(row.name)));
    if (!applied.has('migrations')) {
      this.database.exec('create table migrations (version integer primary key, name text not null, applied_at text not null)');
    }
    const current = this.database.prepare('select max(version) as version from migrations').get() as Record<string, unknown> | undefined;
    const currentVersion = Number(current?.version ?? 0);
    if (currentVersion < 1) {
      this.database.exec([
        'create table if not exists scope_rules (',
        'id text primary key, type text not null, pattern text not null, enabled integer not null default 1, source text not null, created_at text not null',
        ')',
      ].join(' '));
      this.database.exec([
        'create table if not exists http_exchanges (',
        'id text primary key, method text not null, url text not null, host text not null, path text not null, protocol text not null,',
        'status integer not null, mime text not null, request_hash text not null, response_hash text not null,',
        'request_size integer not null, response_size integer not null, timing_ms integer not null, source text not null,',
        'tags_json text not null, notes text not null, scope_state text not null, created_at text not null, updated_at text not null,',
        'request_index text not null, response_index text not null',
        ')',
      ].join(' '));
      this.database.exec([
        'create table if not exists http_messages (',
        'exchange_id text not null, direction text not null, raw_blob_hash text not null, body_blob_hash text not null,',
        'headers_json text not null, size integer not null, encoding text not null,',
        'primary key(exchange_id, direction), foreign key(exchange_id) references http_exchanges(id) on delete cascade',
        ')',
      ].join(' '));
      this.database.exec('create index if not exists http_exchanges_host_idx on http_exchanges(host)');
      this.database.exec('create index if not exists http_exchanges_method_status_idx on http_exchanges(method, status)');
      this.database.exec('create index if not exists http_exchanges_path_idx on http_exchanges(path)');
      this.database.prepare('insert or replace into migrations (version, name, applied_at) values (?, ?, ?)')
        .run(1, 'initial-project-store-v2', new Date().toISOString());
    }
    if (currentVersion < CURRENT_SCHEMA_VERSION) {
      this.database.exec([
        'create table if not exists audit_events (',
        'id text primary key, actor text not null, action text not null, target_ref text not null, decision text not null,',
        'detail text not null default \'\', created_at text not null, hash text not null, previous_hash text',
        ')',
      ].join(' '));
      this.database.prepare('insert or replace into migrations (version, name, applied_at) values (?, ?, ?)')
        .run(CURRENT_SCHEMA_VERSION, 'audit-event-foundation', new Date().toISOString());
    }
    const auditColumns = new Set((this.database.prepare('pragma table_info(audit_events)').all() as Record<string, unknown>[])
      .map((row) => String(row.name)));
    if (!auditColumns.has('detail')) {
      this.database.exec('alter table audit_events add column detail text not null default \'\'');
    }
    this.database.exec([
      'create table if not exists project_settings (',
      'id text primary key, category text not null, key text not null, value_json text not null, value_sha256 text not null,',
      'source text not null, enabled integer not null default 1, notes text not null, created_at text not null, updated_at text not null,',
      'unique(category, key)',
      ')',
    ].join(' '));
    this.database.exec('create index if not exists project_settings_category_idx on project_settings(category)');
    this.database.exec('create index if not exists project_settings_key_idx on project_settings(key)');
    this.database.exec('create index if not exists project_settings_value_sha_idx on project_settings(value_sha256)');
    this.database.exec([
      'create table if not exists session_cookies (',
      'name text not null, value text not null, domain text not null, path text not null, secure integer not null,',
      'http_only integer not null, host_only integer not null, same_site text, expires_at text, source text not null,',
      'created_at text not null, updated_at text not null, last_seen_at text not null, value_sha256 text not null,',
      'primary key(domain, path, name)',
      ')',
    ].join(' '));
    this.database.exec('create index if not exists session_cookies_domain_idx on session_cookies(domain)');
    this.database.exec('create index if not exists session_cookies_source_idx on session_cookies(source)');
    this.database.exec('create index if not exists session_cookies_value_sha_idx on session_cookies(value_sha256)');
    this.database.exec([
      'create table if not exists target_hosts (',
      'id text primary key, host text not null, scheme text not null, port integer not null, scope_state text not null,',
      'technology_summary_json text not null, source text not null, exchange_count integer not null, route_count integer not null,',
      'tags_json text not null, notes text not null, first_seen_at text not null, last_seen_at text not null, updated_at text not null,',
      'unique(host, scheme, port)',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists target_routes (',
      'id text primary key, host_id text not null, host text not null, scheme text not null, port integer not null, method text not null,',
      'path text not null, normalized_path text not null, content_type text not null, status integer not null, source text not null,',
      'evidence_exchange_id text, parameter_count integer not null, issue_count integer not null, tags_json text not null, notes text not null,',
      'first_seen_at text not null, last_seen_at text not null, updated_at text not null,',
      'unique(host_id, method, normalized_path),',
      'foreign key(host_id) references target_hosts(id) on delete cascade,',
      'foreign key(evidence_exchange_id) references http_exchanges(id) on delete set null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists parameters (',
      'id text primary key, route_id text not null, exchange_id text, host text not null, method text not null, path text not null,',
      'location text not null, name text not null, value_hash text not null, value_sample text not null, inferred_type text not null,',
      'insertion_candidate integer not null, source text not null, evidence_count integer not null, tags_json text not null, notes text not null,',
      'first_seen_at text not null, last_seen_at text not null, updated_at text not null,',
      'unique(route_id, location, name),',
      'foreign key(route_id) references target_routes(id) on delete cascade,',
      'foreign key(exchange_id) references http_exchanges(id) on delete set null',
      ')',
    ].join(' '));
    this.database.exec('create index if not exists target_hosts_host_idx on target_hosts(host)');
    this.database.exec('create index if not exists target_hosts_last_seen_idx on target_hosts(last_seen_at)');
    this.database.exec('create index if not exists target_routes_host_method_idx on target_routes(host, method)');
    this.database.exec('create index if not exists target_routes_normalized_path_idx on target_routes(normalized_path)');
    this.database.exec('create index if not exists target_routes_evidence_idx on target_routes(evidence_exchange_id)');
    this.database.exec('create index if not exists parameters_route_idx on parameters(route_id)');
    this.database.exec('create index if not exists parameters_exchange_idx on parameters(exchange_id)');
    this.database.exec('create index if not exists parameters_host_location_idx on parameters(host, location)');
    this.database.exec('create index if not exists parameters_name_idx on parameters(name)');
    this.database.exec([
      'create table if not exists callback_payloads (',
      'id text primary key, token text not null, label text not null, protocol text not null, endpoint text not null,',
      'status text not null, source_exchange_id text, source_host text not null, source_path text not null, notes text not null,',
      'created_at text not null, updated_at text not null, last_interaction_at text,',
      'foreign key(source_exchange_id) references http_exchanges(id) on delete set null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists callback_interactions (',
      'id text primary key, payload_id text not null, protocol text not null, observed_at text not null, source_ip text not null,',
      'source_host text not null, request_line text not null, user_agent text not null, raw_hash text not null, raw_size integer not null,',
      'severity text not null, tags_json text not null, created_at text not null, raw_index text not null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists repeater_tabs (',
      'id text primary key, name text not null, target_url text not null, host text not null, method text not null, path text not null,',
      'request_hash text not null, request_size integer not null, group_name text not null, source_exchange_id text, last_replay_id text,',
      'last_status integer not null, dirty integer not null, tags_json text not null, notes text not null, created_at text not null,',
      'updated_at text not null, request_index text not null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists repeater_sends (',
      'id text primary key, tab_id text, exchange_id text, target_url text not null, host text not null, method text not null, path text not null,',
      'protocol text not null, status integer not null, mime text not null, request_hash text not null, response_hash text not null,',
      'request_size integer not null, response_size integer not null, timing_ms integer not null, source_exchange_id text, session_profile_id text,',
      'oast_payload_ids_json text not null, tags_json text not null, notes text not null, created_at text not null, request_index text not null, response_index text not null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists websocket_connections (',
      'id text primary key, url text not null, host text not null, path text not null, protocol text not null, parent_exchange_id text,',
      'first_frame_at text, last_frame_at text, frame_count integer not null, client_frame_count integer not null, server_frame_count integer not null,',
      'tags_json text not null, notes text not null, created_at text not null, updated_at text not null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists websocket_frames (',
      'id text primary key, connection_id text not null, direction text not null, host text not null, path text not null, url text not null,',
      'opcode integer not null, type text not null, payload_hash text not null, payload_size integer not null, payload_encoding text not null,',
      'intercepted integer not null, modified integer not null, dropped integer not null, replayed integer not null, rewritten integer not null,',
      'tags_json text not null, notes text not null, source text not null, created_at text not null, payload_index text not null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists intruder_attacks (',
      'id text primary key, target_url text not null, host text not null, path text not null, attack_mode text not null,',
      'base_request_hash text not null, base_request_size integer not null, payload_positions integer not null, total_requests integer not null,',
      'retained_result_count integer not null, blocked integer not null, message text not null, payloads_json text not null,',
      'payload_sets_json text not null, payload_processors_json text not null, payload_rules_json text not null, scope_allowlist_json text not null,',
      'start_offset integer, next_offset integer, has_more integer not null, payload_plan_count integer not null, payload_rule_count integer not null,',
      'resource_pool_name text not null, resource_pool_max_concurrent integer not null, stream_summary_json text not null, oast_summary_json text not null,',
      'tags_json text not null, notes text not null, started_at text not null, completed_at text not null, created_at text not null, updated_at text not null,',
      'request_index text not null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists intruder_results (',
      'id text primary key, attack_id text not null, row_index integer not null, payload text not null, payloads_json text not null,',
      'attack_mode text not null, status integer not null, length integer not null, mime text not null, timing_ms integer not null,',
      'request_hash text not null, response_hash text not null, request_size integer not null, response_size integer not null,',
      'grep_matches_json text not null, extract_matches_json text not null, oast_payload_ids_json text not null, callback_interaction_ids_json text not null,',
      'tags_json text not null, notes text not null, created_at text not null, request_index text not null, response_index text not null,',
      'foreign key(attack_id) references intruder_attacks(id) on delete cascade',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists scanner_tasks (',
      'id text primary key, kind text not null, target_url text not null, host text not null, path text not null,',
      'requested_checks_json text not null, scope_allowlist_json text not null, total_requests integer not null, exchange_ids_json text not null,',
      'finding_count integer not null, suppressed_finding_count integer not null, blocked integer not null, message text not null,',
      'tuning_json text not null, tags_json text not null, notes text not null, started_at text not null, completed_at text not null,',
      'created_at text not null, updated_at text not null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists scanner_findings (',
      'id text primary key, task_id text not null, check_id text not null, title text not null, severity text not null, confidence text not null,',
      'host text not null, path text not null, detail text not null, remediation text not null, evidence_exchange_id text,',
      'dedupe_key text not null, confidence_reason text not null, suppressed integer not null, suppression_reason text not null,',
      'tags_json text not null, created_at text not null,',
      'foreign key(task_id) references scanner_tasks(id) on delete cascade,',
      'foreign key(evidence_exchange_id) references http_exchanges(id) on delete set null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists issues (',
      'id text primary key, title text not null, type text not null, severity text not null, confidence text not null, status text not null,',
      'host text not null, path text not null, detail text not null, remediation text not null, evidence_refs_json text not null,',
      'dedupe_key text not null, source text not null, assignee text, triage_note text not null, created_at text not null, updated_at text not null, last_triaged_at text',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists reports (',
      'id text primary key, format text not null, file_name text not null, path text not null, content_hash text not null, content_size integer not null,',
      'issue_ids_json text not null, exchange_ids_json text not null, template_id text not null, sections_json text not null,',
      'prepared_for text not null, engagement_id text not null, bundle_hash text, signature_status text not null, signer_name text not null,',
      'key_id text not null, redacted integer not null, notes text not null, created_at text not null, content_index text not null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists automation_runs (',
      'id text primary key, workflow_id text not null, workflow_name text not null, status text not null, trigger text not null,',
      'started_at text not null, completed_at text not null, duration_ms integer not null, total_requests integer not null,',
      'exchange_id text, issue_id text, scheduler_job_id text, scheduler_lease_id text, ci_provider text, ci_config text not null,',
      'logs_json text not null, raw_material_json text not null, tags_json text not null, notes text not null, created_at text not null, updated_at text not null, search_index text not null,',
      'foreign key(exchange_id) references http_exchanges(id) on delete set null,',
      'foreign key(issue_id) references issues(id) on delete set null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists ai_runs (',
      'id text primary key, provider_id text not null, task text not null, status text not null, model text not null,',
      'started_at text not null, completed_at text not null, summary text not null, output_hash text not null, output_size integer not null,',
      'prompt_hash text, prompt_size integer not null, evidence_count integer not null, command text, provider_label text, context_digest text,',
      'usage_json text not null, stream_events_json text not null, prompt_evaluation_json text not null, suggested_actions_json text not null,',
      'tags_json text not null, notes text not null, created_at text not null, updated_at text not null, search_index text not null',
      ')',
    ].join(' '));
    this.database.exec([
      'create table if not exists extension_runs (',
      'id text primary key, extension_id text not null, extension_name text not null, hook text not null, status text not null, target text not null,',
      'started_at text not null, completed_at text not null, summary text not null, logs_json text not null, issue_id text, exchange_id text,',
      'tags_json text not null, notes text not null, created_at text not null, updated_at text not null, search_index text not null,',
      'foreign key(issue_id) references issues(id) on delete set null,',
      'foreign key(exchange_id) references http_exchanges(id) on delete set null',
      ')',
    ].join(' '));
    this.database.exec('create index if not exists callback_payloads_protocol_idx on callback_payloads(protocol)');
    this.database.exec('create index if not exists callback_payloads_source_exchange_idx on callback_payloads(source_exchange_id)');
    this.database.exec('create index if not exists callback_interactions_payload_idx on callback_interactions(payload_id)');
    this.database.exec('create index if not exists callback_interactions_protocol_idx on callback_interactions(protocol)');
    this.database.exec('create index if not exists repeater_tabs_host_idx on repeater_tabs(host)');
    this.database.exec('create index if not exists repeater_tabs_group_idx on repeater_tabs(group_name)');
    this.database.exec('create index if not exists repeater_tabs_source_exchange_idx on repeater_tabs(source_exchange_id)');
    this.database.exec('create index if not exists repeater_sends_tab_idx on repeater_sends(tab_id)');
    this.database.exec('create index if not exists repeater_sends_exchange_idx on repeater_sends(exchange_id)');
    this.database.exec('create index if not exists repeater_sends_host_status_idx on repeater_sends(host, status)');
    this.database.exec('create index if not exists repeater_sends_source_exchange_idx on repeater_sends(source_exchange_id)');
    this.database.exec('create index if not exists websocket_connections_host_idx on websocket_connections(host)');
    this.database.exec('create index if not exists websocket_connections_last_frame_idx on websocket_connections(last_frame_at)');
    this.database.exec('create index if not exists websocket_frames_connection_idx on websocket_frames(connection_id)');
    this.database.exec('create index if not exists websocket_frames_host_type_idx on websocket_frames(host, type)');
    this.database.exec('create index if not exists websocket_frames_created_idx on websocket_frames(created_at)');
    this.database.exec('create index if not exists intruder_attacks_host_mode_idx on intruder_attacks(host, attack_mode)');
    this.database.exec('create index if not exists intruder_attacks_started_idx on intruder_attacks(started_at)');
    this.database.exec('create index if not exists intruder_results_attack_idx on intruder_results(attack_id)');
    this.database.exec('create index if not exists intruder_results_status_idx on intruder_results(status)');
    this.database.exec('create index if not exists intruder_results_created_idx on intruder_results(created_at)');
    this.database.exec('create index if not exists scanner_tasks_host_kind_idx on scanner_tasks(host, kind)');
    this.database.exec('create index if not exists scanner_tasks_started_idx on scanner_tasks(started_at)');
    this.database.exec('create index if not exists scanner_findings_task_idx on scanner_findings(task_id)');
    this.database.exec('create index if not exists scanner_findings_check_idx on scanner_findings(check_id)');
    this.database.exec('create index if not exists scanner_findings_severity_idx on scanner_findings(severity)');
    this.database.exec('create index if not exists scanner_findings_evidence_idx on scanner_findings(evidence_exchange_id)');
    this.database.exec('create index if not exists issues_host_status_idx on issues(host, status)');
    this.database.exec('create index if not exists issues_severity_idx on issues(severity)');
    this.database.exec('create index if not exists issues_dedupe_idx on issues(dedupe_key)');
    this.database.exec('create index if not exists reports_format_idx on reports(format)');
    this.database.exec('create index if not exists reports_created_idx on reports(created_at)');
    this.database.exec('create index if not exists automation_runs_workflow_idx on automation_runs(workflow_id)');
    this.database.exec('create index if not exists automation_runs_status_started_idx on automation_runs(status, started_at)');
    this.database.exec('create index if not exists automation_runs_exchange_idx on automation_runs(exchange_id)');
    this.database.exec('create index if not exists ai_runs_provider_task_idx on ai_runs(provider_id, task)');
    this.database.exec('create index if not exists ai_runs_status_started_idx on ai_runs(status, started_at)');
    this.database.exec('create index if not exists extension_runs_extension_hook_idx on extension_runs(extension_id, hook)');
    this.database.exec('create index if not exists extension_runs_status_started_idx on extension_runs(status, started_at)');
    this.database.exec('create index if not exists extension_runs_exchange_idx on extension_runs(exchange_id)');
  }

  private refreshWebSocketConnectionStats(connectionIds: string[], updatedAt: string) {
    const update = this.database.prepare([
      'update websocket_connections set first_frame_at = ?, last_frame_at = ?, frame_count = ?, client_frame_count = ?, server_frame_count = ?, updated_at = ? where id = ?',
    ].join(' '));
    const statsStatement = this.database.prepare([
      'select min(created_at) as firstFrameAt, max(created_at) as lastFrameAt, count(*) as frameCount,',
      'coalesce(sum(case when direction = \'client\' then 1 else 0 end), 0) as clientFrameCount,',
      'coalesce(sum(case when direction = \'server\' then 1 else 0 end), 0) as serverFrameCount',
      'from websocket_frames where connection_id = ?',
    ].join(' '));
    for (const connectionId of connectionIds) {
      const row = statsStatement.get(connectionId) as Record<string, unknown>;
      update.run(
        row.firstFrameAt ? String(row.firstFrameAt) : null,
        row.lastFrameAt ? String(row.lastFrameAt) : null,
        Number(row.frameCount ?? 0),
        Number(row.clientFrameCount ?? 0),
        Number(row.serverFrameCount ?? 0),
        updatedAt,
        connectionId,
      );
    }
  }

  private async writeBlob(bytes: Buffer) {
    const hash = sha256(bytes);
    if (this.knownBlobHashes.has(hash)) return hash;
    const finalPath = blobPath(this.rootDir, hash);
    await fs.mkdir(path.dirname(finalPath), { recursive: true, mode: SECURE_DIR_MODE });
    await chmodIfPossible(path.dirname(finalPath), SECURE_DIR_MODE);
    try {
      await fs.writeFile(finalPath, bytes, { flag: 'wx', mode: SECURE_FILE_MODE });
      await chmodIfPossible(finalPath, SECURE_FILE_MODE);
    } catch (error) {
      if (!isFileExistsError(error)) throw error;
    }
    this.knownBlobHashes.add(hash);
    return hash;
  }

  private readBlobSync(hash: string) {
    return readFileSync(blobPath(this.rootDir, hash));
  }

  private async touchManifest(updatedAt: string) {
    this.manifest.updatedAt = updatedAt;
    await writeJsonAtomic(manifestPath(this.rootDir), this.manifest);
  }

  private sqliteJournalMode() {
    const row = this.database.prepare('pragma journal_mode').get() as Record<string, unknown> | undefined;
    return String(row?.journal_mode ?? row?.journalMode ?? '');
  }
}

export class ProjectStoreProxyRecorder {
  private storePromise: Promise<ProjectStore> | null = null;
  private readonly pending = new Set<Promise<void>>();
  private persistedCount = 0;
  private failedCount = 0;
  private lastExchangeId: string | undefined;
  private lastError: string | undefined;

  constructor(
    readonly rootDir: string,
    private readonly options: ProjectStoreOpenOptions = {},
  ) {}

  capture(exchange: HttpExchange) {
    const pending = this.record(exchange);
    this.pending.add(pending);
    pending.finally(() => this.pending.delete(pending)).catch(() => undefined);
  }

  async record(exchange: HttpExchange) {
    const input = {
      id: exchange.id,
      method: exchange.method,
      url: exchange.url,
      host: exchange.host,
      path: exchange.path,
      status: exchange.status,
      mime: exchange.mime,
      timingMs: exchange.timing,
      source: exchange.source,
      tags: exchange.tags,
      notes: exchange.notes,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      createdAt: exchange.time,
      scopeState: exchange.tags.includes('blocked-by-scope') ? 'blocked' : 'captured',
    };
    try {
      const store = await this.openStore();
      await appendPendingHttpExchangeJournal(this.rootDir, input);
      await store.addHttpExchange(input);
      await appendCommittedHttpExchangeJournal(this.rootDir, input.id, 'captured');
      this.persistedCount += 1;
      this.lastExchangeId = exchange.id;
      this.lastError = undefined;
    } catch (error) {
      this.failedCount += 1;
      this.lastError = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  async flush() {
    await Promise.all([...this.pending]);
  }

  stats(): ProjectStoreProxyRecorderStats {
    return {
      rootDir: this.rootDir,
      persistedCount: this.persistedCount,
      failedCount: this.failedCount,
      pendingCount: this.pending.size,
      lastExchangeId: this.lastExchangeId,
      lastError: this.lastError,
    };
  }

  async close() {
    await this.flush();
    if (!this.storePromise) return;
    const store = await this.storePromise;
    store.close();
    this.storePromise = null;
  }

  private async openStore() {
    if (!this.storePromise) {
      this.storePromise = projectStoreExists(this.rootDir)
        .then((exists) => (exists
          ? ProjectStore.open(this.rootDir)
          : ProjectStore.create(this.rootDir, this.options)));
    }
    return this.storePromise;
  }
}

export class ProjectStoreRepeaterRecorder {
  private storePromise: Promise<ProjectStore> | null = null;
  private readonly pending = new Set<Promise<void>>();
  private persistedTabCount = 0;
  private persistedSendCount = 0;
  private failedCount = 0;
  private lastSendId: string | undefined;
  private lastExchangeId: string | undefined;
  private lastError: string | undefined;

  constructor(
    readonly rootDir: string,
    private readonly options: ProjectStoreOpenOptions = {},
  ) {}

  capture(request: ReplayRequest, exchange: HttpExchange) {
    const pending = this.recordSend(request, exchange);
    this.pending.add(pending);
    pending.finally(() => this.pending.delete(pending)).catch(() => undefined);
  }

  async recordSend(request: ReplayRequest, exchange: HttpExchange) {
    try {
      const store = await this.openStore();
      await store.addHttpExchange({
        id: exchange.id,
        method: exchange.method,
        url: exchange.url,
        host: exchange.host,
        path: exchange.path,
        status: exchange.status,
        mime: exchange.mime,
        timingMs: exchange.timing,
        source: exchange.source,
        tags: exchange.tags,
        notes: exchange.notes,
        requestRaw: exchange.requestRaw,
        responseRaw: exchange.responseRaw,
        createdAt: exchange.time,
        scopeState: exchange.tags.includes('blocked-by-scope') ? 'blocked' : 'replayed',
      });

      const tabId = request.repeaterTabId?.trim();
      if (tabId) {
        await store.upsertRepeaterTab({
          id: tabId,
          name: request.repeaterTabName,
          targetUrl: request.targetUrl,
          rawRequest: request.rawRequest,
          group: request.repeaterTabGroup,
          sourceExchangeId: request.sourceExchangeId,
          lastReplayId: exchange.id,
          lastStatus: exchange.status,
          dirty: false,
          tags: ['repeater-tab', ...(request.tags ?? [])],
          notes: request.notes,
          updatedAt: new Date().toISOString(),
        });
        this.persistedTabCount += 1;
      }

      const send = await store.addRepeaterSend({
        id: request.repeaterSendId,
        tabId,
        exchangeId: exchange.id,
        targetUrl: request.targetUrl,
        rawRequest: exchange.requestRaw || request.rawRequest,
        responseRaw: exchange.responseRaw,
        method: exchange.method,
        host: exchange.host,
        path: exchange.path,
        protocol: safeUrl(exchange.url).protocol.replace(':', '') || 'http',
        status: exchange.status,
        mime: exchange.mime,
        timingMs: exchange.timing,
        sourceExchangeId: request.sourceExchangeId,
        sessionProfileId: request.sessionProfile?.id,
        oastPayloadIds: request.oastPayloads?.map((payload) => payload.id) ?? [],
        tags: ['repeater-send', ...exchange.tags, ...(request.tags ?? [])],
        notes: request.notes || exchange.notes,
        createdAt: exchange.time,
      });
      await store.addAuditEvent({
        actor: request.operator || 'local-operator',
        action: 'repeater.send',
        targetRef: send.id,
        decision: exchange.status === 0 ? 'blocked' : 'completed',
        detail: `Repeater send ${exchange.method} ${exchange.url} stored as ${exchange.id}.`,
        createdAt: new Date().toISOString(),
      });
      this.persistedSendCount += 1;
      this.lastSendId = send.id;
      this.lastExchangeId = exchange.id;
      this.lastError = undefined;
    } catch (error) {
      this.failedCount += 1;
      this.lastError = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  async flush() {
    await Promise.all([...this.pending]);
  }

  stats(): ProjectStoreRepeaterRecorderStats {
    return {
      rootDir: this.rootDir,
      persistedTabCount: this.persistedTabCount,
      persistedSendCount: this.persistedSendCount,
      failedCount: this.failedCount,
      pendingCount: this.pending.size,
      lastSendId: this.lastSendId,
      lastExchangeId: this.lastExchangeId,
      lastError: this.lastError,
    };
  }

  async close() {
    await this.flush();
    if (!this.storePromise) return;
    const store = await this.storePromise;
    store.close();
    this.storePromise = null;
  }

  private async openStore() {
    if (!this.storePromise) {
      this.storePromise = projectStoreExists(this.rootDir)
        .then((exists) => (exists
          ? ProjectStore.open(this.rootDir)
          : ProjectStore.create(this.rootDir, this.options)));
    }
    return this.storePromise;
  }
}

export class ProjectStoreIntruderRecorder {
  private storePromise: Promise<ProjectStore> | null = null;
  private readonly pending = new Set<Promise<void>>();
  private persistedAttackCount = 0;
  private persistedResultCount = 0;
  private failedCount = 0;
  private lastAttackId: string | undefined;
  private lastError: string | undefined;

  constructor(
    readonly rootDir: string,
    private readonly options: ProjectStoreOpenOptions = {},
  ) {}

  capture(request: IntruderAttackRequest, summary: IntruderAttackSummary) {
    const pending = this.recordAttack(request, summary);
    this.pending.add(pending);
    pending.finally(() => this.pending.delete(pending)).catch(() => undefined);
  }

  async recordAttack(request: IntruderAttackRequest, summary: IntruderAttackSummary) {
    try {
      const store = await this.openStore();
      const attack = await store.addIntruderAttack({
        id: summary.id,
        targetUrl: summary.targetUrl,
        rawRequest: request.rawRequest,
        attackMode: summary.attackMode,
        payloadPositions: summary.payloadPositions,
        totalRequests: summary.totalRequests,
        blocked: summary.blocked,
        message: summary.message,
        payloads: request.payloads,
        payloadSets: request.payloadSets,
        payloadProcessors: request.payloadProcessors,
        payloadRules: request.payloadRules,
        scopeAllowlist: request.scopeAllowlist,
        startOffset: summary.startOffset,
        nextOffset: summary.nextOffset,
        hasMore: summary.hasMore,
        payloadPlanCount: summary.payloadPlanCount,
        payloadRuleCount: summary.payloadRuleCount,
        resourcePoolName: summary.resourcePoolName,
        resourcePoolMaxConcurrent: summary.resourcePoolMaxConcurrent,
        streamSummary: summary.streaming as unknown as Record<string, unknown>,
        oastSummary: summary.oast as unknown as Record<string, unknown>,
        tags: ['intruder-attack', summary.attackMode, summary.blocked ? 'blocked' : summary.hasMore ? 'checkpoint' : 'completed'],
        notes: summary.message,
        startedAt: summary.startedAt,
        completedAt: summary.completedAt,
        results: summary.results,
      });
      await store.addAuditEvent({
        actor: 'local-operator',
        action: 'intruder.attackCompleted',
        targetRef: attack.id,
        decision: summary.blocked ? 'blocked' : summary.hasMore ? 'updated' : 'completed',
        detail: `Stored Intruder ${summary.attackMode} attack with ${summary.totalRequests} request(s) and ${summary.results.length} retained result row(s).`,
        createdAt: new Date().toISOString(),
      });
      this.persistedAttackCount += 1;
      this.persistedResultCount += summary.results.length;
      this.lastAttackId = attack.id;
      this.lastError = undefined;
    } catch (error) {
      this.failedCount += 1;
      this.lastError = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  async flush() {
    await Promise.all([...this.pending]);
  }

  stats(): ProjectStoreIntruderRecorderStats {
    return {
      rootDir: this.rootDir,
      persistedAttackCount: this.persistedAttackCount,
      persistedResultCount: this.persistedResultCount,
      failedCount: this.failedCount,
      pendingCount: this.pending.size,
      lastAttackId: this.lastAttackId,
      lastError: this.lastError,
    };
  }

  async close() {
    await this.flush();
    if (!this.storePromise) return;
    const store = await this.storePromise;
    store.close();
    this.storePromise = null;
  }

  private async openStore() {
    if (!this.storePromise) {
      this.storePromise = projectStoreExists(this.rootDir)
        .then((exists) => (exists
          ? ProjectStore.open(this.rootDir)
          : ProjectStore.create(this.rootDir, this.options)));
    }
    return this.storePromise;
  }
}

export class ProjectStoreScannerRecorder {
  private storePromise: Promise<ProjectStore> | null = null;
  private readonly pending = new Set<Promise<void>>();
  private persistedTaskCount = 0;
  private persistedFindingCount = 0;
  private failedCount = 0;
  private lastTaskId: string | undefined;
  private lastError: string | undefined;

  constructor(
    readonly rootDir: string,
    private readonly options: ProjectStoreOpenOptions = {},
  ) {}

  capture(request: ActiveScanRequest, summary: ActiveScanSummary, kind: ProjectStoreScannerTaskKind = 'active') {
    const pending = this.recordTask(request, summary, kind);
    this.pending.add(pending);
    pending.finally(() => this.pending.delete(pending)).catch(() => undefined);
  }

  async recordTask(request: ActiveScanRequest, summary: ActiveScanSummary, kind: ProjectStoreScannerTaskKind = 'active') {
    try {
      const store = await this.openStore();
      const task = await store.addScannerTask({
        id: summary.id,
        kind,
        request,
        summary,
        exchanges: summary.exchanges,
        tags: ['scanner-task', kind, summary.blocked ? 'blocked' : 'completed'],
        notes: summary.message,
      });
      await store.addAuditEvent({
        actor: 'local-operator',
        action: 'scanner.taskCompleted',
        targetRef: task.id,
        decision: summary.blocked ? 'blocked' : 'completed',
        detail: `Stored scanner ${kind} task with ${summary.totalRequests} probe(s), ${summary.findings.length} finding(s), and ${summary.suppressedFindings.length} suppressed signal(s).`,
        createdAt: new Date().toISOString(),
      });
      this.persistedTaskCount += 1;
      this.persistedFindingCount += summary.findings.length + summary.suppressedFindings.length;
      this.lastTaskId = task.id;
      this.lastError = undefined;
    } catch (error) {
      this.failedCount += 1;
      this.lastError = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  async flush() {
    await Promise.all([...this.pending]);
  }

  stats(): ProjectStoreScannerRecorderStats {
    return {
      rootDir: this.rootDir,
      persistedTaskCount: this.persistedTaskCount,
      persistedFindingCount: this.persistedFindingCount,
      failedCount: this.failedCount,
      pendingCount: this.pending.size,
      lastTaskId: this.lastTaskId,
      lastError: this.lastError,
    };
  }

  async close() {
    await this.flush();
    if (!this.storePromise) return;
    const store = await this.storePromise;
    store.close();
    this.storePromise = null;
  }

  private async openStore() {
    if (!this.storePromise) {
      this.storePromise = projectStoreExists(this.rootDir)
        .then((exists) => (exists
          ? ProjectStore.open(this.rootDir)
          : ProjectStore.create(this.rootDir, this.options)));
    }
    return this.storePromise;
  }
}

export class ProjectStoreWebSocketRecorder {
  private storePromise: Promise<ProjectStore> | null = null;
  private readonly pending = new Set<Promise<void>>();
  private persistedFrameCount = 0;
  private failedCount = 0;
  private lastConnectionId: string | undefined;
  private lastFrameId: string | undefined;
  private lastError: string | undefined;

  constructor(
    readonly rootDir: string,
    private readonly options: ProjectStoreOpenOptions = {},
  ) {}

  capture(message: WebSocketMessage) {
    const pending = this.recordMessage(message);
    this.pending.add(pending);
    pending.finally(() => this.pending.delete(pending)).catch(() => undefined);
  }

  async recordMessage(message: WebSocketMessage) {
    try {
      const store = await this.openStore();
      const frame = await store.addWebSocketFrame({
        id: message.id,
        connectionId: message.connectionId,
        direction: message.direction,
        host: message.host,
        path: message.path,
        url: message.url,
        opcode: message.opcode,
        type: message.type,
        payload: message.payload,
        payloadEncoding: message.payloadEncoding,
        length: message.length,
        tags: message.tags,
        source: message.tags.includes('replayed') ? 'replay' : 'proxy',
        createdAt: new Date().toISOString(),
      });
      await store.addAuditEvent({
        actor: 'local-operator',
        action: 'websocket.frameCaptured',
        targetRef: frame.id,
        decision: frame.dropped ? 'blocked' : 'completed',
        detail: `Stored WebSocket ${frame.direction} ${frame.type} frame for ${frame.host}${frame.path}.`,
        createdAt: new Date().toISOString(),
      });
      this.persistedFrameCount += 1;
      this.lastConnectionId = frame.connectionId;
      this.lastFrameId = frame.id;
      this.lastError = undefined;
    } catch (error) {
      this.failedCount += 1;
      this.lastError = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  async flush() {
    await Promise.all([...this.pending]);
  }

  stats(): ProjectStoreWebSocketRecorderStats {
    return {
      rootDir: this.rootDir,
      persistedFrameCount: this.persistedFrameCount,
      failedCount: this.failedCount,
      pendingCount: this.pending.size,
      lastConnectionId: this.lastConnectionId,
      lastFrameId: this.lastFrameId,
      lastError: this.lastError,
    };
  }

  async close() {
    await this.flush();
    if (!this.storePromise) return;
    const store = await this.storePromise;
    store.close();
    this.storePromise = null;
  }

  private async openStore() {
    if (!this.storePromise) {
      this.storePromise = projectStoreExists(this.rootDir)
        .then((exists) => (exists
          ? ProjectStore.open(this.rootDir)
          : ProjectStore.create(this.rootDir, this.options)));
    }
    return this.storePromise;
  }
}

export class ProjectStoreReportRecorder {
  private storePromise: Promise<ProjectStore> | null = null;
  private readonly pending = new Set<Promise<void>>();
  private persistedIssueCount = 0;
  private persistedReportCount = 0;
  private failedCount = 0;
  private lastReportId: string | undefined;
  private lastError: string | undefined;

  constructor(
    readonly rootDir: string,
    private readonly options: ProjectStoreOpenOptions = {},
  ) {}

  capture(request: ReportExportRequest, artifact: ReportArtifact) {
    const pending = this.recordExport(request, artifact);
    this.pending.add(pending);
    pending.finally(() => this.pending.delete(pending)).catch(() => undefined);
  }

  async recordExport(request: ReportExportRequest, artifact: ReportArtifact) {
    try {
      const store = await this.openStore();
      const issues = request.issues.map((issue) => reportIssueToProjectStoreIssue(issue, request, artifact.generatedAt));
      await store.upsertIssues(issues);
      const signature = reportSignatureMetadata(artifact.content);
      const report = await store.addReportExport({
        id: artifact.id,
        format: artifact.format,
        fileName: artifact.fileName,
        path: artifact.path,
        content: artifact.content,
        issueIds: request.issues.map((issue) => issue.id),
        exchangeIds: request.exchanges.map((exchange) => exchange.id),
        templateId: request.templateId,
        sections: request.sections,
        preparedFor: request.preparedFor,
        engagementId: request.engagementId,
        bundleHash: signature.bundleHash,
        signatureStatus: signature.status,
        signerName: signature.signerName,
        keyId: signature.keyId,
        redacted: reportArtifactLooksRedacted(artifact.content, request),
        notes: `Report export ${artifact.fileName} with ${artifact.issueCount} issue(s) and ${artifact.exchangeCount} evidence item(s).`,
        createdAt: artifact.generatedAt,
      });
      await store.addAuditEvent({
        actor: 'local-operator',
        action: 'report.exported',
        targetRef: report.id,
        decision: 'completed',
        detail: `Stored ${artifact.format} report ${artifact.fileName} with ${issues.length} issue(s).`,
        createdAt: new Date().toISOString(),
      });
      this.persistedIssueCount += issues.length;
      this.persistedReportCount += 1;
      this.lastReportId = report.id;
      this.lastError = undefined;
    } catch (error) {
      this.failedCount += 1;
      this.lastError = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  async flush() {
    await Promise.all([...this.pending]);
  }

  stats(): ProjectStoreReportRecorderStats {
    return {
      rootDir: this.rootDir,
      persistedIssueCount: this.persistedIssueCount,
      persistedReportCount: this.persistedReportCount,
      failedCount: this.failedCount,
      pendingCount: this.pending.size,
      lastReportId: this.lastReportId,
      lastError: this.lastError,
    };
  }

  async close() {
    await this.flush();
    if (!this.storePromise) return;
    const store = await this.storePromise;
    store.close();
    this.storePromise = null;
  }

  private async openStore() {
    if (!this.storePromise) {
      this.storePromise = projectStoreExists(this.rootDir)
        .then((exists) => (exists
          ? ProjectStore.open(this.rootDir)
          : ProjectStore.create(this.rootDir, this.options)));
    }
    return this.storePromise;
  }
}

export class ProjectStoreCallbackRecorder {
  private storePromise: Promise<ProjectStore> | null = null;
  private readonly pending = new Set<Promise<void>>();
  private persistedPayloadCount = 0;
  private persistedInteractionCount = 0;
  private failedCount = 0;
  private lastPayloadId: string | undefined;
  private lastInteractionId: string | undefined;
  private lastError: string | undefined;

  constructor(
    readonly rootDir: string,
    private readonly options: ProjectStoreOpenOptions = {},
  ) {}

  capturePayloads(payloads: CallbackPayload[]) {
    const pending = this.recordPayloads(payloads);
    this.pending.add(pending);
    pending.finally(() => this.pending.delete(pending)).catch(() => undefined);
  }

  captureInteraction(interaction: CallbackInteraction) {
    const pending = this.recordInteractions([interaction]);
    this.pending.add(pending);
    pending.finally(() => this.pending.delete(pending)).catch(() => undefined);
  }

  async recordPayloads(payloads: CallbackPayload[]) {
    if (payloads.length === 0) return;
    try {
      const store = await this.openStore();
      await store.addCallbackPayloads(payloads.map((payload) => ({
        id: payload.id,
        token: payload.token,
        label: payload.label,
        protocol: payload.protocol,
        endpoint: payload.endpoint,
        status: payload.status,
        sourceExchangeId: payload.sourceExchangeId,
        sourceHost: payload.sourceHost,
        sourcePath: payload.sourcePath,
        notes: payload.notes,
        createdAt: payload.createdAt,
        lastInteractionAt: payload.lastInteractionAt,
      })));
      this.persistedPayloadCount += payloads.length;
      this.lastPayloadId = payloads[payloads.length - 1]?.id;
      this.lastError = undefined;
    } catch (error) {
      this.failedCount += 1;
      this.lastError = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  async recordInteractions(interactions: CallbackInteraction[]) {
    if (interactions.length === 0) return;
    try {
      const store = await this.openStore();
      await store.addCallbackInteractions(interactions.map((interaction) => ({
        id: interaction.id,
        payloadId: interaction.payloadId,
        protocol: interaction.protocol,
        observedAt: interaction.observedAt,
        sourceIp: interaction.sourceIp,
        sourceHost: interaction.sourceHost,
        requestLine: interaction.requestLine,
        userAgent: interaction.userAgent,
        raw: interaction.raw,
        severity: interaction.severity,
        tags: interaction.tags,
      })));
      this.persistedInteractionCount += interactions.length;
      this.lastInteractionId = interactions[interactions.length - 1]?.id;
      this.lastError = undefined;
    } catch (error) {
      this.failedCount += 1;
      this.lastError = error instanceof Error ? error.message : String(error);
      throw error;
    }
  }

  async flush() {
    await Promise.all([...this.pending]);
  }

  stats(): ProjectStoreCallbackRecorderStats {
    return {
      rootDir: this.rootDir,
      persistedPayloadCount: this.persistedPayloadCount,
      persistedInteractionCount: this.persistedInteractionCount,
      failedCount: this.failedCount,
      pendingCount: this.pending.size,
      lastPayloadId: this.lastPayloadId,
      lastInteractionId: this.lastInteractionId,
      lastError: this.lastError,
    };
  }

  async close() {
    await this.flush();
    if (!this.storePromise) return;
    const store = await this.storePromise;
    store.close();
    this.storePromise = null;
  }

  private async openStore() {
    if (!this.storePromise) {
      this.storePromise = projectStoreExists(this.rootDir)
        .then((exists) => (exists
          ? ProjectStore.open(this.rootDir)
          : ProjectStore.create(this.rootDir, this.options)));
    }
    return this.storePromise;
  }
}

export function verifyProjectStoreCallbackEvidencePackage(
  content: string | ProjectStoreCallbackEvidencePackage,
  signingSecret: string,
): ProjectStoreCallbackEvidenceVerification {
  try {
    const parsed = typeof content === 'string' ? JSON.parse(content) as Record<string, unknown> : content as unknown as Record<string, unknown>;
    const signature = isRecord(parsed.signature) ? parsed.signature : {};
    const unsigned = { ...parsed };
    delete unsigned.signature;
    delete unsigned.content;
    const canonical = canonicalize(unsigned);
    const packageDigestSha256 = sha256(canonical);
    const expectedSignature = createHmac('sha256', signingSecret).update(canonical).digest('hex');
    const suppliedSignature = String(signature.signature ?? '');
    const suppliedDigest = String(signature.packageDigestSha256 ?? '');
    const digestMatches = packageDigestSha256 === suppliedDigest;
    const signatureMatches = expectedSignature === suppliedSignature;
    return {
      valid: parsed.kind === 'proxyforge-project-store-callback-evidence-package'
        && signature.algorithm === 'HMAC-SHA256'
        && digestMatches
        && signatureMatches,
      kind: String(parsed.kind ?? ''),
      signatureMatches,
      digestMatches,
      packageDigestSha256,
      expectedSignature,
      suppliedSignature,
      keyId: String(signature.keyId ?? ''),
      signerName: String(signature.signerName ?? ''),
    };
  } catch (error) {
    return {
      valid: false,
      kind: '',
      signatureMatches: false,
      digestMatches: false,
      packageDigestSha256: '',
      expectedSignature: '',
      suppliedSignature: '',
      keyId: '',
      signerName: '',
      error: error instanceof Error ? error.message : String(error),
    };
  }
}

export function validateProjectStoreImportEntries(entries: string[]): ProjectStoreImportPlan {
  const rejectedEntries = entries.filter((entry) => !isSafeArchiveEntry(entry));
  const normalizedEntries = entries.map((entry) => entry.replace(/\\/g, '/'));
  const requiredEntriesPresent = normalizedEntries.includes('manifest.json')
    && normalizedEntries.includes('project.db')
    && normalizedEntries.some((entry) => entry.startsWith('blobs/sha256/'));
  return {
    accepted: rejectedEntries.length === 0 && requiredEntriesPresent,
    entryCount: entries.length,
    rejectedEntries,
    requiredEntriesPresent,
  };
}

export async function appendProjectStorePendingHttpExchange(
  rootDir: string,
  input: ProjectStoreHttpExchangeInput & { id: string },
) {
  await appendPendingHttpExchangeJournal(rootDir, input);
}

async function loadSqlite(): Promise<SqliteModule> {
  try {
    const dynamicImport = new Function('specifier', 'return import(specifier)') as (specifier: string) => Promise<unknown>;
    return await dynamicImport('node:sqlite') as SqliteModule;
  } catch {
    throw new Error('node:sqlite is required for Project Store v2 in this runtime.');
  }
}

async function projectStoreExists(rootDir: string) {
  try {
    await fs.access(manifestPath(rootDir));
    await fs.access(databasePath(rootDir));
    return true;
  } catch {
    return false;
  }
}

async function appendPendingHttpExchangeJournal(rootDir: string, input: ProjectStoreHttpExchangeInput & { id: string }) {
  if (!input.id.trim()) throw new Error('Recovery journal entries require stable exchange ids.');
  await ensurePrivateProjectStoreDirectory(recoveryRoot(rootDir));
  const record: ProjectStorePendingHttpExchangeJournalRecord = {
    kind: 'proxyforge-project-store-pending-http-exchange',
    schemaVersion: 1,
    recordedAt: new Date().toISOString(),
    exchange: {
      ...input,
      requestRaw: toBuffer(input.requestRaw).toString('base64'),
      responseRaw: toBuffer(input.responseRaw).toString('base64'),
    },
  };
  await appendPrivateJsonl(pendingJournalPath(rootDir), record);
}

async function appendCommittedHttpExchangeJournal(
  rootDir: string,
  id: string,
  disposition: ProjectStoreCommittedHttpExchangeJournalRecord['disposition'],
) {
  await ensurePrivateProjectStoreDirectory(recoveryRoot(rootDir));
  const record: ProjectStoreCommittedHttpExchangeJournalRecord = {
    kind: 'proxyforge-project-store-committed-http-exchange',
    schemaVersion: 1,
    id,
    committedAt: new Date().toISOString(),
    disposition,
  };
  await appendPrivateJsonl(committedJournalPath(rootDir), record);
}

async function readPendingHttpExchangeJournal(rootDir: string): Promise<ProjectStorePendingHttpExchangeJournalRecord[]> {
  const lines = await readJsonlRecords(pendingJournalPath(rootDir));
  return lines.flatMap((record) => {
    if (!isRecord(record) || record.kind !== 'proxyforge-project-store-pending-http-exchange' || !isRecord(record.exchange)) return [];
    const exchange = record.exchange as Record<string, unknown>;
    const id = String(exchange.id ?? '').trim();
    if (!id) return [];
    return [{
      kind: 'proxyforge-project-store-pending-http-exchange',
      schemaVersion: 1,
      recordedAt: String(record.recordedAt ?? ''),
      exchange: {
        ...exchange,
        id,
        method: String(exchange.method ?? 'GET'),
        url: String(exchange.url ?? 'http://invalid.local/'),
        status: Number(exchange.status ?? 0),
        requestRaw: decodeJournalRaw(exchange.requestRaw),
        responseRaw: decodeJournalRaw(exchange.responseRaw),
        host: exchange.host ? String(exchange.host) : undefined,
        path: exchange.path ? String(exchange.path) : undefined,
        protocol: exchange.protocol ? String(exchange.protocol) : undefined,
        mime: exchange.mime ? String(exchange.mime) : undefined,
        timingMs: Number(exchange.timingMs ?? 0),
        source: exchange.source ? String(exchange.source) : undefined,
        tags: Array.isArray(exchange.tags) ? exchange.tags.map(String) : [],
        notes: exchange.notes ? String(exchange.notes) : undefined,
        scopeState: exchange.scopeState ? String(exchange.scopeState) : undefined,
        createdAt: exchange.createdAt ? String(exchange.createdAt) : undefined,
      },
    } satisfies ProjectStorePendingHttpExchangeJournalRecord];
  });
}

async function readCommittedHttpExchangeJournal(rootDir: string): Promise<ProjectStoreCommittedHttpExchangeJournalRecord[]> {
  const lines = await readJsonlRecords(committedJournalPath(rootDir));
  return lines.flatMap((record) => {
    if (!isRecord(record) || record.kind !== 'proxyforge-project-store-committed-http-exchange') return [];
    const id = String(record.id ?? '').trim();
    if (!id) return [];
    const disposition = record.disposition === 'recovered' || record.disposition === 'already-in-store' ? record.disposition : 'captured';
    return [{
      kind: 'proxyforge-project-store-committed-http-exchange',
      schemaVersion: 1,
      id,
      committedAt: String(record.committedAt ?? ''),
      disposition,
    }];
  });
}

async function readJsonlRecords(filePath: string): Promise<unknown[]> {
  try {
    const raw = await fs.readFile(filePath, 'utf8');
    return raw.split(/\r?\n/).filter((line) => line.trim()).flatMap((line) => {
      try {
        return [JSON.parse(line) as unknown];
      } catch {
        return [];
      }
    });
  } catch (error) {
    if (isNotFoundError(error)) return [];
    throw error;
  }
}

function decodeJournalRaw(value: unknown) {
  if (Buffer.isBuffer(value)) return value;
  const text = String(value ?? '');
  return Buffer.from(text, 'base64');
}

async function readManifest(rootDir: string): Promise<ProjectStoreManifest> {
  const stat = await fs.stat(manifestPath(rootDir));
  if (stat.size > MAX_MANIFEST_BYTES) throw new Error('Project manifest is too large.');
  const parsed = JSON.parse(await fs.readFile(manifestPath(rootDir), 'utf8')) as unknown;
  if (!isRecord(parsed) || parsed.kind !== 'proxyforge-project-store' || parsed.schemaVersion !== CURRENT_SCHEMA_VERSION) {
    throw new Error('This is not a valid ProxyForge Project Store v2 manifest.');
  }
  return {
    kind: 'proxyforge-project-store',
    schemaVersion: CURRENT_SCHEMA_VERSION,
    projectId: String(parsed.projectId || '').trim() || randomUUID(),
    projectName: String(parsed.projectName || '').trim() || 'ProxyForge Project',
    createdAt: String(parsed.createdAt || new Date().toISOString()),
    updatedAt: String(parsed.updatedAt || new Date().toISOString()),
  };
}

async function writeJsonAtomic(filePath: string, value: unknown) {
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.${randomUUID()}.tmp`;
  await fs.mkdir(path.dirname(filePath), { recursive: true, mode: SECURE_DIR_MODE });
  await chmodIfPossible(path.dirname(filePath), SECURE_DIR_MODE);
  await fs.writeFile(tempPath, JSON.stringify(value, null, 2), { encoding: 'utf8', mode: SECURE_FILE_MODE });
  await chmodIfPossible(tempPath, SECURE_FILE_MODE);
  await fs.rename(tempPath, filePath);
  await chmodIfPossible(filePath, SECURE_FILE_MODE);
}

async function ensurePrivateProjectStoreDirectory(dirPath: string) {
  await fs.mkdir(dirPath, { recursive: true, mode: SECURE_DIR_MODE });
  await chmodIfPossible(dirPath, SECURE_DIR_MODE);
}

async function appendPrivateJsonl(filePath: string, value: unknown) {
  await ensurePrivateProjectStoreDirectory(path.dirname(filePath));
  await fs.appendFile(filePath, `${JSON.stringify(value)}\n`, { encoding: 'utf8', mode: SECURE_FILE_MODE });
  await chmodIfPossible(filePath, SECURE_FILE_MODE);
}

async function secureProjectStorePermissions(rootDir: string) {
  await chmodIfPossible(rootDir, SECURE_DIR_MODE);
  await fs.mkdir(blobRoot(rootDir), { recursive: true, mode: SECURE_DIR_MODE });
  await chmodIfPossible(blobRoot(rootDir), SECURE_DIR_MODE);
  await Promise.all([
    manifestPath(rootDir),
    databasePath(rootDir),
    `${databasePath(rootDir)}-wal`,
    `${databasePath(rootDir)}-shm`,
  ].map((filePath) => chmodIfPossible(filePath, SECURE_FILE_MODE)));
}

async function chmodIfPossible(filePath: string, mode: number) {
  if (process.platform === 'win32') return;
  try {
    await fs.chmod(filePath, mode);
  } catch (error) {
    if (!['ENOENT', 'EPERM', 'EACCES'].includes((error as NodeJS.ErrnoException).code ?? '')) throw error;
  }
}

const projectStoreSettingCategories = new Set<ProjectStoreSettingCategory>([
  'scope',
  'proxy',
  'scanner',
  'sessions',
  'oast',
  'reports',
  'network',
  'browser',
  'repeater',
  'intruder',
  'automation',
  'ai',
  'safety',
]);

function normalizeProjectSettingInput(input: ProjectStoreSettingInput, now: string): ProjectStoreSettingRecord {
  const category = normalizeProjectSettingCategory(input.category);
  const key = input.key.trim();
  if (!key) throw new Error('Project setting key is required.');
  const serialized = JSON.stringify(input.value);
  if (serialized === undefined) throw new Error(`Project setting ${category}.${key} must be JSON serializable.`);
  const value = JSON.parse(serialized) as unknown;
  const valueSha256 = sha256(canonicalize(value));
  const createdAt = input.createdAt?.trim() || now;
  return {
    id: input.id?.trim() || `project-setting-${category}-${sha256(key).slice(0, 16)}`,
    category,
    key,
    value,
    valueSha256,
    source: input.source?.trim() || 'operator',
    enabled: input.enabled ?? true,
    notes: input.notes?.trim() || '',
    createdAt,
    updatedAt: input.updatedAt?.trim() || now,
  };
}

function rowToProjectSettingRecord(row: unknown): ProjectStoreSettingRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store setting row.');
  const valueJson = String(row.value_json ?? 'null');
  return {
    id: String(row.id),
    category: normalizeProjectSettingCategory(String(row.category)),
    key: String(row.key),
    value: JSON.parse(valueJson) as unknown,
    valueSha256: String(row.value_sha256),
    source: String(row.source ?? ''),
    enabled: Boolean(Number(row.enabled ?? 0)),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

function normalizeSessionCookieInput(input: ProjectStoreSessionCookieInput, now: string): ProjectStoreSessionCookieRecord {
  const name = input.name.trim();
  const value = input.value;
  const domain = normalizeCookieDomain(input.domain);
  if (!name) throw new Error('Session cookie name is required.');
  if (!domain) throw new Error('Session cookie domain is required.');
  const pathValue = normalizeCookiePath(input.path ?? '/');
  const createdAt = input.createdAt?.trim() || now;
  return {
    name,
    value,
    domain,
    path: pathValue,
    secure: input.secure ?? false,
    httpOnly: input.httpOnly ?? false,
    hostOnly: input.hostOnly ?? true,
    sameSite: input.sameSite?.trim() || undefined,
    expiresAt: input.expiresAt?.trim() || undefined,
    source: input.source?.trim() || 'operator',
    createdAt,
    updatedAt: input.updatedAt?.trim() || now,
    lastSeenAt: input.lastSeenAt?.trim() || now,
    valueSha256: sha256(value),
  };
}

function rowToSessionCookieRecord(row: unknown): ProjectStoreSessionCookieRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store session cookie row.');
  return {
    name: String(row.name),
    value: String(row.value),
    domain: String(row.domain),
    path: String(row.path),
    secure: Boolean(Number(row.secure ?? 0)),
    httpOnly: Boolean(Number(row.http_only ?? 0)),
    hostOnly: Boolean(Number(row.host_only ?? 0)),
    sameSite: row.same_site ? String(row.same_site) : undefined,
    expiresAt: row.expires_at ? String(row.expires_at) : undefined,
    source: String(row.source ?? ''),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    lastSeenAt: String(row.last_seen_at),
    valueSha256: String(row.value_sha256),
  };
}

function normalizeCookieDomain(domain: string) {
  return domain.trim().replace(/^\./, '').toLowerCase();
}

function normalizeCookiePath(pathValue: string) {
  const trimmed = pathValue.trim();
  if (!trimmed || !trimmed.startsWith('/')) return '/';
  return trimmed;
}

function normalizeProjectSettingCategory(value: string): ProjectStoreSettingCategory {
  const normalized = value.trim().toLowerCase() as ProjectStoreSettingCategory;
  if (!projectStoreSettingCategories.has(normalized)) {
    throw new Error(`Unsupported Project Store setting category: ${value}`);
  }
  return normalized;
}

function httpExchangeToProjectStoreInput(exchange: HttpExchange, source: string, scopeState: string): ProjectStoreHttpExchangeInput {
  return {
    id: exchange.id,
    method: exchange.method,
    url: exchange.url,
    host: exchange.host,
    path: exchange.path,
    status: exchange.status,
    mime: exchange.mime,
    timingMs: exchange.timing,
    source,
    tags: exchange.tags,
    notes: exchange.notes,
    requestRaw: exchange.requestRaw,
    responseRaw: exchange.responseRaw,
    createdAt: exchange.time,
    scopeState: exchange.tags.includes('blocked-by-scope') ? 'blocked' : scopeState,
  };
}

function normalizeExchangeInput(
  input: ProjectStoreHttpExchangeInput,
  requestRaw: Buffer,
  responseRaw: Buffer,
  requestHash: string,
  responseHash: string,
) {
  const now = new Date().toISOString();
  const url = safeUrl(input.url);
  const method = input.method.trim().toUpperCase() || 'GET';
  const responseStatus = Number.isFinite(input.status) ? input.status : 0;
  return {
    id: input.id?.trim() || `hx-${requestHash.slice(0, 12)}-${responseHash.slice(0, 12)}`,
    method,
    url: url.toString(),
    host: input.host?.trim() || url.host,
    path: input.path?.trim() || `${url.pathname}${url.search}`,
    protocol: input.protocol?.trim() || url.protocol.replace(':', '') || 'http',
    status: responseStatus,
    mime: input.mime?.trim() || contentTypeFromRaw(responseRaw) || 'application/octet-stream',
    requestHash,
    responseHash,
    requestSize: requestRaw.length,
    responseSize: responseRaw.length,
    timingMs: Math.max(0, Math.trunc(input.timingMs ?? 0)),
    source: input.source?.trim() || 'proxy',
    tags: [...new Set((input.tags ?? []).map((tag) => tag.trim()).filter(Boolean))],
    notes: input.notes?.trim() || '',
    scopeState: input.scopeState?.trim() || 'unknown',
    createdAt: input.createdAt?.trim() || now,
    updatedAt: now,
    requestRaw,
    responseRaw,
    requestIndex: indexPreview(requestRaw),
    responseIndex: indexPreview(responseRaw),
  };
}

function deriveTargetInventoryFromExchange(record: ReturnType<typeof normalizeExchangeInput>) {
  const url = safeUrl(record.url);
  const scheme = normalizeInventoryScheme(record.protocol || url.protocol.replace(':', ''));
  const host = normalizeInventoryHost(url.hostname || record.host);
  const port = inferInventoryPort(url, scheme);
  const hostId = targetHostId(scheme, host, port);
  const source = normalizeTargetInventorySource(record.source);
  const routePath = url.pathname || '/';
  const normalizedPath = normalizeRoutePath(routePath);
  const routeId = targetRouteId(hostId, record.method, normalizedPath);
  const request = parseHttpRequestParts(record.requestRaw, url);
  const responseHeaders = parseHeaderMap(record.responseRaw);
  const server = responseHeaders.get('server') ?? '';
  const poweredBy = responseHeaders.get('x-powered-by') ?? '';
  const technologySummary = Object.fromEntries(Object.entries({
    server,
    poweredBy,
  }).filter(([, value]) => value !== '' && value !== undefined));
  const tags = [...new Set([...record.tags, 'target-inventory'])];
  const seenAt = record.createdAt || new Date().toISOString();
  const hostRecord: ProjectStoreTargetHostRecord = {
    id: hostId,
    host,
    scheme,
    port,
    scopeState: record.scopeState,
    technologySummary,
    source,
    exchangeCount: 1,
    routeCount: 0,
    tags,
    notes: record.notes,
    firstSeenAt: seenAt,
    lastSeenAt: seenAt,
    updatedAt: record.updatedAt,
  };
  const routeRecord: ProjectStoreTargetRouteRecord = {
    id: routeId,
    hostId,
    host,
    scheme,
    port,
    method: record.method,
    path: routePath,
    normalizedPath,
    contentType: request.headerMap.get('content-type') ?? record.mime,
    status: record.status,
    source,
    evidenceExchangeId: record.id,
    parameterCount: 0,
    issueCount: 0,
    tags,
    notes: record.notes,
    firstSeenAt: seenAt,
    lastSeenAt: seenAt,
    updatedAt: record.updatedAt,
  };
  const parameters = extractTargetParameters({
    exchangeId: record.id,
    routeId,
    host,
    method: record.method,
    path: routePath,
    url,
    request,
    source,
    tags,
    seenAt,
    updatedAt: record.updatedAt,
  });
  routeRecord.parameterCount = parameters.length;
  return { host: hostRecord, route: routeRecord, parameters };
}

function extractTargetParameters(options: {
  exchangeId: string;
  routeId: string;
  host: string;
  method: string;
  path: string;
  url: URL;
  request: ParsedHttpRequestParts;
  source: ProjectStoreTargetInventorySource;
  tags: string[];
  seenAt: string;
  updatedAt: string;
}) {
  const records = new Map<string, ProjectStoreParameterRecord>();
  const push = (
    location: ProjectStoreParameterLocation | string,
    name: string,
    value: unknown,
    insertionCandidate = true,
    extraTags: string[] = [],
  ) => {
    const normalizedLocation = normalizeParameterLocation(location);
    const normalizedName = name.trim();
    if (!normalizedName) return;
    const valueText = parameterValueToString(value);
    const id = targetParameterId(options.routeId, normalizedLocation, normalizedName);
    records.set(id, {
      id,
      routeId: options.routeId,
      exchangeId: options.exchangeId,
      host: options.host,
      method: options.method,
      path: options.path,
      location: normalizedLocation,
      name: normalizedName,
      valueHash: sha256(valueText),
      valueSample: valueText.slice(0, 8192),
      inferredType: inferParameterType(value),
      insertionCandidate,
      source: options.source,
      evidenceCount: 1,
      tags: [...new Set([...options.tags, ...extraTags, normalizedLocation])],
      notes: '',
      firstSeenAt: options.seenAt,
      lastSeenAt: options.seenAt,
      updatedAt: options.updatedAt,
    });
  };

  for (const [name, value] of options.url.searchParams) push('query', name, value);

  const cookieHeader = options.request.headerMap.get('cookie');
  if (cookieHeader) {
    for (const part of cookieHeader.split(';')) {
      const index = part.indexOf('=');
      if (index > 0) push('cookie', part.slice(0, index), part.slice(index + 1), true, ['session']);
    }
  }

  for (const [name, value] of options.request.headers) {
    const lower = name.toLowerCase();
    if (lower === 'cookie') continue;
    if (lower === 'host' || lower === 'content-length' || lower === 'connection' || lower === 'accept' || lower === 'accept-encoding') {
      push('header', name, value, false);
    } else {
      push('header', name, value, true);
    }
  }

  const body = options.request.body.trim();
  if (!body) return [...records.values()];
  const contentType = options.request.headerMap.get('content-type')?.toLowerCase() ?? '';

  if (contentType.includes('application/x-www-form-urlencoded') || looksLikeFormBody(body)) {
    for (const [name, value] of new URLSearchParams(body)) push('form', name, value);
  }

  const parsedJson = parseBodyJson(body, contentType);
  if (parsedJson !== undefined) {
    collectJsonScalarParameters(parsedJson, '$', (name, value) => push('json', name, value));
    if (isRecord(parsedJson)) {
      const query = parsedJson.query;
      if (typeof query === 'string') push('graphql', 'query', query, true, ['graphql']);
      if (typeof parsedJson.operationName === 'string') push('graphql', 'operationName', parsedJson.operationName, true, ['graphql']);
      if (isRecord(parsedJson.variables)) {
        collectJsonScalarParameters(parsedJson.variables, 'variables', (name, value) => push('graphql', name, value, true, ['graphql']));
      }
    }
  } else if (contentType.includes('graphql')) {
    push('graphql', 'query', body, true, ['graphql']);
  }

  if (contentType.includes('multipart/form-data')) {
    const boundary = contentType.match(/boundary=([^;]+)/)?.[1]?.trim().replace(/^"|"$/g, '');
    if (boundary) {
      for (const part of body.split(`--${boundary}`)) {
        const name = part.match(/content-disposition:[^\r\n]*\bname="([^"]+)"/i)?.[1];
        if (!name) continue;
        const value = part.split(/\r?\n\r?\n/).slice(1).join('\n').replace(/\r?\n--$/, '').trim();
        push('multipart', name, value);
      }
    }
  }

  if (contentType.includes('xml') || body.startsWith('<')) {
    extractXmlParameters(body, push);
  }

  if (records.size === 0 && body.length > 0) push('body', 'body', body, true);
  return [...records.values()];
}

interface ParsedHttpRequestParts {
  method: string;
  path: string;
  headers: Array<[string, string]>;
  headerMap: Map<string, string>;
  body: string;
}

function parseHttpRequestParts(raw: Buffer, target: URL): ParsedHttpRequestParts {
  const text = raw.toString('utf8');
  const separator = text.match(/\r?\n\r?\n/);
  const head = separator ? text.slice(0, separator.index) : text;
  const body = separator ? text.slice((separator.index ?? 0) + separator[0].length) : '';
  const [firstLine = '', ...headerLines] = head.split(/\r?\n/);
  const [method = 'GET', pathValue = `${target.pathname}${target.search}`] = firstLine.trim().split(/\s+/);
  const headers: Array<[string, string]> = [];
  const headerMap = new Map<string, string>();
  for (const line of headerLines) {
    const index = line.indexOf(':');
    if (index === -1) continue;
    const name = line.slice(0, index).trim();
    const value = line.slice(index + 1).trim();
    if (!name) continue;
    headers.push([name, value]);
    headerMap.set(name.toLowerCase(), value);
  }
  return {
    method: method.toUpperCase(),
    path: pathValue,
    headers,
    headerMap,
    body,
  };
}

function parseHeaderMap(raw: Buffer) {
  const headerMap = new Map<string, string>();
  for (const [name, value] of parseHeaders(raw) as Array<[string, string]>) headerMap.set(name.toLowerCase(), value);
  return headerMap;
}

function parseBodyJson(body: string, contentType: string): unknown | undefined {
  if (!contentType.includes('json') && !/^\s*[\[{]/.test(body)) return undefined;
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return undefined;
  }
}

function collectJsonScalarParameters(value: unknown, pathName: string, push: (name: string, value: unknown) => void) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => collectJsonScalarParameters(entry, `${pathName}[${index}]`, push));
    return;
  }
  if (isRecord(value)) {
    for (const [key, entry] of Object.entries(value)) {
      const separator = pathName === '$' ? '.' : '.';
      collectJsonScalarParameters(entry, `${pathName}${separator}${key}`, push);
    }
    return;
  }
  if (value !== undefined && value !== null) push(pathName, value);
}

function extractXmlParameters(body: string, push: (location: ProjectStoreParameterLocation | string, name: string, value: unknown, insertionCandidate?: boolean, extraTags?: string[]) => void) {
  const attrMatches = body.matchAll(/\s([A-Za-z_:][\w:.-]*)="([^"]*)"/g);
  for (const match of attrMatches) push('xml', `@${match[1]}`, match[2], true, ['xml']);
  const elementMatches = body.matchAll(/<([A-Za-z_][\w:.-]*)\b[^>]*>([^<]{0,4096})<\/\1>/g);
  for (const match of elementMatches) {
    const value = match[2]?.trim();
    if (value) push('xml', match[1], value, true, ['xml']);
  }
}

function looksLikeFormBody(body: string) {
  return /^[^=&\s]+=[\s\S]*&?[^=&\s]*=?/.test(body) && !body.trim().startsWith('{') && !body.trim().startsWith('<');
}

function parameterValueToString(value: unknown) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') return String(value);
  return canonicalize(value);
}

function inferParameterType(value: unknown) {
  if (typeof value === 'boolean') return 'boolean';
  if (typeof value === 'number') return Number.isInteger(value) ? 'integer' : 'number';
  const text = parameterValueToString(value).trim();
  if (!text) return 'empty';
  if (/^(true|false)$/i.test(text)) return 'boolean';
  if (/^-?\d+$/.test(text)) return 'integer';
  if (/^-?\d+\.\d+$/.test(text)) return 'number';
  if (/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(text)) return 'jwt';
  if (/^[A-Za-z0-9+/=_-]{16,}$/.test(text)) return 'token';
  if (/^https?:\/\//i.test(text)) return 'url';
  return 'string';
}

function normalizeTargetInventorySource(value: string): ProjectStoreTargetInventorySource {
  const normalized = value.trim().toLowerCase();
  if (
    normalized === 'proxy'
    || normalized === 'scanner'
    || normalized === 'crawler'
    || normalized === 'import'
    || normalized === 'repeater'
    || normalized === 'intruder'
    || normalized === 'manual'
    || normalized === 'agent'
  ) {
    return normalized;
  }
  return 'unknown';
}

function normalizeParameterLocation(value: string): ProjectStoreParameterLocation {
  const normalized = value.trim().toLowerCase();
  if (
    normalized === 'query'
    || normalized === 'form'
    || normalized === 'json'
    || normalized === 'graphql'
    || normalized === 'xml'
    || normalized === 'multipart'
    || normalized === 'cookie'
    || normalized === 'header'
  ) {
    return normalized;
  }
  return 'body';
}

function normalizeInventoryScheme(value: string) {
  const normalized = value.trim().replace(/:$/, '').toLowerCase();
  if (normalized === 'https' || normalized === 'wss') return normalized;
  if (normalized === 'ws') return 'ws';
  return 'http';
}

function normalizeInventoryHost(value: string) {
  const trimmed = value.trim();
  if (!trimmed) return 'invalid.local';
  try {
    const parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed) ? trimmed : `http://${trimmed}`);
    return parsed.hostname.toLowerCase() || 'invalid.local';
  } catch {
    return trimmed.replace(/:\d+$/, '').toLowerCase() || 'invalid.local';
  }
}

function inferInventoryPort(url: URL, scheme: string) {
  const explicit = Number(url.port);
  if (Number.isFinite(explicit) && explicit > 0) return explicit;
  if (scheme === 'https' || scheme === 'wss') return 443;
  return 80;
}

function normalizeRoutePath(pathValue: string) {
  const pathOnly = pathValue.split('?', 1)[0] || '/';
  const normalized = pathOnly.startsWith('/') ? pathOnly : `/${pathOnly}`;
  return normalized.split('/').map((segment) => {
    if (/^\d+$/.test(segment)) return '{int}';
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) return '{uuid}';
    if (/^[0-9a-f]{16,}$/i.test(segment)) return '{hex}';
    return segment;
  }).join('/') || '/';
}

function targetHostId(scheme: string, host: string, port: number) {
  return `target-host-${sha256(`${scheme}://${host}:${port}`).slice(0, 20)}`;
}

function targetRouteId(hostId: string, method: string, normalizedPath: string) {
  return `target-route-${sha256(`${hostId}|${method.toUpperCase()}|${normalizedPath}`).slice(0, 22)}`;
}

function targetParameterId(routeId: string, location: string, name: string) {
  return `target-param-${sha256(`${routeId}|${location}|${name}`).slice(0, 24)}`;
}

function normalizeRepeaterTabInput(
  input: ProjectStoreRepeaterTabInput,
  rawRequest: Buffer,
  requestHash: string,
  now: string,
) {
  const url = safeUrl(input.targetUrl);
  const requestLine = requestLineParts(rawRequest, url);
  const createdAt = input.createdAt?.trim() || now;
  const updatedAt = input.updatedAt?.trim() || now;
  const tags = [...new Set((input.tags ?? []).map((tag) => tag.trim()).filter(Boolean))];
  return {
    id: input.id?.trim() || `rt-${sha256(`${url.toString()}|${requestHash}|${createdAt}`).slice(0, 16)}`,
    name: input.name?.trim() || `${requestLine.method} ${requestLine.path}`,
    targetUrl: url.toString(),
    host: url.host,
    method: requestLine.method,
    path: requestLine.path,
    requestHash,
    requestSize: rawRequest.length,
    group: input.group?.trim() || url.host || 'Ungrouped',
    sourceExchangeId: input.sourceExchangeId?.trim() || undefined,
    lastReplayId: input.lastReplayId?.trim() || undefined,
    lastStatus: clampInteger(input.lastStatus ?? 0, 0, 999),
    dirty: input.dirty ?? false,
    tags,
    notes: input.notes?.trim() || '',
    createdAt,
    updatedAt,
    requestIndex: indexPreview(rawRequest),
  };
}

function normalizeRepeaterSendInput(
  input: ProjectStoreRepeaterSendInput,
  rawRequest: Buffer,
  responseRaw: Buffer,
  requestHash: string,
  responseHash: string,
  now: string,
) {
  const url = safeUrl(input.targetUrl);
  const requestLine = requestLineParts(rawRequest, url);
  const createdAt = input.createdAt?.trim() || now;
  const status = clampInteger(input.status ?? 0, 0, 999);
  return {
    id: input.id?.trim() || `repeater-send-${sha256(`${input.tabId ?? ''}|${url.toString()}|${requestHash}|${responseHash}|${createdAt}`).slice(0, 18)}`,
    tabId: input.tabId?.trim() || undefined,
    exchangeId: input.exchangeId?.trim() || undefined,
    targetUrl: url.toString(),
    host: input.host?.trim() || url.host,
    method: input.method?.trim().toUpperCase() || requestLine.method,
    path: input.path?.trim() || requestLine.path,
    protocol: input.protocol?.trim() || url.protocol.replace(':', '') || 'http',
    status,
    mime: input.mime?.trim() || contentTypeFromRaw(responseRaw) || 'application/octet-stream',
    requestHash,
    responseHash,
    requestSize: rawRequest.length,
    responseSize: responseRaw.length,
    timingMs: Math.max(0, Math.trunc(input.timingMs ?? 0)),
    sourceExchangeId: input.sourceExchangeId?.trim() || undefined,
    sessionProfileId: input.sessionProfileId?.trim() || undefined,
    oastPayloadIds: [...new Set((input.oastPayloadIds ?? []).map((id) => id.trim()).filter(Boolean))],
    tags: [...new Set((input.tags ?? []).map((tag) => tag.trim()).filter(Boolean))],
    notes: input.notes?.trim() || '',
    createdAt,
    rawRequest,
    responseRaw,
    requestIndex: indexPreview(rawRequest),
    responseIndex: indexPreview(responseRaw),
  };
}

function normalizeWebSocketConnectionInput(input: ProjectStoreWebSocketConnectionInput, now: string): ProjectStoreWebSocketConnectionRecord {
  const url = safeUrl(input.url);
  const createdAt = input.createdAt?.trim() || now;
  return {
    id: input.id.trim(),
    url: url.toString(),
    host: input.host?.trim() || url.host,
    path: input.path?.trim() || `${url.pathname}${url.search}` || '/',
    protocol: input.protocol?.trim() || url.protocol.replace(':', '') || 'ws',
    parentExchangeId: input.parentExchangeId?.trim() || undefined,
    firstFrameAt: undefined,
    lastFrameAt: undefined,
    frameCount: 0,
    clientFrameCount: 0,
    serverFrameCount: 0,
    tags: [...new Set((input.tags ?? []).map((tag) => tag.trim()).filter(Boolean))],
    notes: input.notes?.trim() || '',
    createdAt,
    updatedAt: input.updatedAt?.trim() || now,
  };
}

function normalizeWebSocketFrameInput(
  input: ProjectStoreWebSocketFrameInput,
  payload: Buffer,
  payloadHash: string,
  now: string,
) {
  const url = safeUrl(input.url);
  const tags = [...new Set((input.tags ?? []).map((tag) => tag.trim()).filter(Boolean))];
  const encoding = normalizeWebSocketPayloadEncoding(input.payloadEncoding ?? (input.type === 'text' ? 'text' : 'hex'));
  const payloadIndex = encoding === 'hex' ? payload.toString('hex').slice(0, 16 * 1024) : payload.toString('utf8', 0, Math.min(payload.length, 16 * 1024));
  const createdAt = input.createdAt?.trim() || now;
  return {
    id: input.id?.trim() || `wsf-${sha256(`${input.connectionId}|${input.direction}|${payloadHash}|${createdAt}`).slice(0, 18)}`,
    connectionId: input.connectionId.trim(),
    direction: normalizeWebSocketDirection(input.direction),
    host: input.host?.trim() || url.host,
    path: input.path?.trim() || `${url.pathname}${url.search}` || '/',
    url: url.toString(),
    opcode: clampInteger(input.opcode, 0, 255),
    type: normalizeWebSocketFrameType(input.type),
    payloadHash,
    payloadSize: Math.max(0, Math.trunc(input.length ?? payload.length)),
    payloadEncoding: encoding,
    intercepted: input.intercepted ?? (tags.includes('held') || tags.includes('intercepted')),
    modified: input.modified ?? (tags.includes('edited') || tags.includes('modified')),
    dropped: input.dropped ?? tags.includes('dropped'),
    replayed: input.replayed ?? tags.includes('replayed'),
    rewritten: input.rewritten ?? (tags.includes('rewritten') || tags.some((tag) => tag.startsWith('rewrite:'))),
    tags,
    source: input.source?.trim() || (tags.includes('replayed') ? 'replay' : 'proxy'),
    notes: input.notes?.trim() || '',
    createdAt,
    payloadIndex,
  };
}

function normalizeIntruderAttackInput(
  input: ProjectStoreIntruderAttackInput,
  rawRequest: Buffer,
  baseRequestHash: string,
  now: string,
) {
  const url = safeUrl(input.targetUrl);
  const startedAt = input.startedAt?.trim() || now;
  const completedAt = input.completedAt?.trim() || now;
  return {
    id: input.id?.trim() || `intruder-${sha256(`${input.targetUrl}|${baseRequestHash}|${startedAt}`).slice(0, 18)}`,
    targetUrl: url.toString(),
    host: url.host,
    path: `${url.pathname}${url.search}` || '/',
    attackMode: normalizeIntruderAttackMode(input.attackMode),
    baseRequestHash,
    baseRequestSize: rawRequest.length,
    payloadPositions: Math.max(0, Math.trunc(input.payloadPositions ?? 0)),
    totalRequests: Math.max(0, Math.trunc(input.totalRequests ?? 0)),
    retainedResultCount: input.results?.length ?? 0,
    blocked: Boolean(input.blocked),
    message: input.message.trim(),
    payloads: parseLiteralStringArray(input.payloads ?? []),
    payloadSets: normalizeStringMatrix(input.payloadSets ?? []),
    payloadProcessors: parseLiteralStringArray(input.payloadProcessors ?? []),
    payloadRules: parseLiteralStringArray(input.payloadRules ?? []),
    scopeAllowlist: parseLiteralStringArray(input.scopeAllowlist ?? []),
    startOffset: typeof input.startOffset === 'number' ? Math.max(0, Math.trunc(input.startOffset)) : undefined,
    nextOffset: typeof input.nextOffset === 'number' ? Math.max(0, Math.trunc(input.nextOffset)) : undefined,
    hasMore: Boolean(input.hasMore),
    payloadPlanCount: Math.max(0, Math.trunc(input.payloadPlanCount ?? input.totalRequests ?? 0)),
    payloadRuleCount: Math.max(0, Math.trunc(input.payloadRuleCount ?? input.payloadRules?.length ?? 0)),
    resourcePoolName: input.resourcePoolName?.trim() || 'Default sequential pool',
    resourcePoolMaxConcurrent: Math.max(1, Math.trunc(input.resourcePoolMaxConcurrent ?? 1)),
    streamSummary: input.streamSummary ?? {},
    oastSummary: input.oastSummary ?? {},
    tags: [...new Set(['intruder-attack', input.attackMode, ...(input.tags ?? [])].map((tag) => String(tag).trim()).filter(Boolean))],
    notes: input.notes?.trim() || '',
    startedAt,
    completedAt,
    createdAt: startedAt,
    updatedAt: now,
    requestIndex: indexPreview(rawRequest),
  };
}

function normalizeIntruderResultInput(
  input: ProjectStoreIntruderResultInput,
  requestRaw: Buffer,
  responseRaw: Buffer,
  requestHash: string,
  responseHash: string,
  now: string,
) {
  const result = input.result;
  const rowIndex = Math.max(0, Math.trunc(input.rowIndex ?? 0));
  return {
    id: result.id.trim() || `intruder-result-${sha256(`${input.attackId}|${rowIndex}|${requestHash}|${responseHash}`).slice(0, 18)}`,
    attackId: input.attackId.trim(),
    rowIndex,
    payload: result.payload,
    payloads: parseLiteralStringArray(result.payloads),
    attackMode: normalizeIntruderAttackMode(result.attackMode),
    status: clampInteger(result.status, 0, 999),
    length: Math.max(0, Math.trunc(result.length ?? responseRaw.length)),
    mime: result.mime?.trim() || contentTypeFromRaw(responseRaw) || 'application/octet-stream',
    timing: Math.max(0, Math.trunc(result.timing ?? 0)),
    requestHash,
    responseHash,
    requestSize: requestRaw.length,
    responseSize: responseRaw.length,
    grepMatches: parseLiteralStringArray(result.grepMatches ?? []),
    extractMatches: parseLiteralStringArray(result.extractMatches ?? []),
    oastPayloadIds: parseLiteralStringArray(result.oastPayloadIds ?? []),
    callbackInteractionIds: parseLiteralStringArray(result.callbackInteractionIds ?? []),
    tags: [...new Set((result.tags ?? []).map((tag) => tag.trim()).filter(Boolean))],
    notes: result.notes?.trim() || '',
    createdAt: input.createdAt?.trim() || now,
    requestIndex: indexPreview(requestRaw),
    responseIndex: indexPreview(responseRaw),
  };
}

function normalizeScannerTaskInput(input: ProjectStoreScannerTaskInput, exchanges: HttpExchange[], now: string): ProjectStoreScannerTaskRecord {
  const url = safeUrl(input.summary.targetUrl || input.request.targetUrl);
  const startedAt = input.summary.startedAt?.trim() || now;
  const completedAt = input.summary.completedAt?.trim() || now;
  const requestedChecks = normalizeActiveScanCheckIds(input.request.checks ?? []);
  return {
    id: input.id?.trim() || input.summary.id?.trim() || `scanner-task-${sha256(`${input.request.targetUrl}|${startedAt}|${requestedChecks.join(',')}`).slice(0, 18)}`,
    kind: normalizeScannerTaskKind(input.kind ?? 'active'),
    targetUrl: url.toString(),
    host: url.host,
    path: `${url.pathname}${url.search}` || '/',
    requestedChecks,
    scopeAllowlist: parseLiteralStringArray(input.request.scopeAllowlist ?? []),
    totalRequests: Math.max(0, Math.trunc(input.summary.totalRequests ?? exchanges.length)),
    exchangeIds: exchanges.map((exchange) => exchange.id).filter(Boolean),
    findingCount: input.summary.findings.length,
    suppressedFindingCount: input.summary.suppressedFindings.length,
    blocked: Boolean(input.summary.blocked),
    message: input.summary.message.trim(),
    tuning: input.summary.tuning as unknown as Record<string, unknown>,
    tags: [...new Set(['scanner-task', input.kind ?? 'active', ...(input.tags ?? [])].map((tag) => String(tag).trim()).filter(Boolean))],
    notes: input.notes?.trim() || input.summary.message,
    startedAt,
    completedAt,
    createdAt: startedAt,
    updatedAt: now,
  };
}

function normalizeScannerFindingInput(input: ProjectStoreScannerFindingInput, now: string): ProjectStoreScannerFindingRecord {
  const finding = input.finding;
  const suppressed = Boolean(input.suppressed);
  const active = finding as Partial<ActiveScanFinding>;
  const suppressedFinding = finding as Partial<ActiveScanSuppressedFinding>;
  const checkId = normalizeActiveScanCheckId(String(finding.checkId ?? 'security-headers'));
  const severity = suppressed ? 'info' : normalizeIssueSeverity(String(active.severity ?? 'info'));
  const confidence = suppressed ? 'tentative' : normalizeIssueConfidence(String(active.confidence ?? 'tentative'));
  const createdAt = input.createdAt?.trim() || now;
  return {
    id: finding.id?.trim() || `scanner-finding-${sha256(`${input.taskId}|${checkId}|${finding.title}|${createdAt}`).slice(0, 18)}`,
    taskId: input.taskId.trim(),
    checkId,
    title: finding.title.trim(),
    severity,
    confidence,
    host: finding.host.trim(),
    path: finding.path.trim() || '/',
    detail: suppressed ? suppressedFinding.reason?.trim() || '' : active.detail?.trim() || '',
    remediation: suppressed ? '' : active.remediation?.trim() || '',
    evidenceExchangeId: finding.evidenceExchangeId?.trim() || undefined,
    dedupeKey: finding.dedupeKey?.trim() || `${input.taskId}:${checkId}:${finding.title}`,
    confidenceReason: suppressed ? '' : active.confidenceReason?.trim() || '',
    suppressed,
    suppressionReason: input.suppressionReason?.trim() || suppressedFinding.reason?.trim() || '',
    tags: [...new Set(['scanner-finding', `check:${checkId}`, suppressed ? 'suppressed' : 'active'].filter(Boolean))],
    createdAt,
  };
}

function normalizeIssueInput(input: ProjectStoreIssueInput, now: string): ProjectStoreIssueRecord {
  const title = input.title.trim();
  if (!title) throw new Error('Issue title is required.');
  const host = input.host.trim();
  if (!host) throw new Error('Issue host is required.');
  const pathValue = input.path.trim() || '/';
  const evidenceRefs = normalizeEvidenceRefs(input.evidenceRefs ?? []);
  const createdAt = input.createdAt?.trim() || now;
  const updatedAt = input.updatedAt?.trim() || now;
  const severity = normalizeIssueSeverity(input.severity);
  const confidence = normalizeIssueConfidence(input.confidence);
  const status = normalizeIssueStatus(input.status);
  const dedupeKey = input.dedupeKey?.trim() || sha256(`${title}|${host}|${pathValue}|${severity}`).slice(0, 24);
  return {
    id: input.id?.trim() || `issue-${dedupeKey}`,
    title,
    type: input.type?.trim() || 'manual',
    severity,
    confidence,
    status,
    host,
    path: pathValue,
    detail: input.detail.trim(),
    remediation: input.remediation.trim(),
    evidenceRefs,
    dedupeKey,
    source: input.source?.trim() || 'manual',
    assignee: input.assignee?.trim() || undefined,
    triageNote: input.triageNote?.trim() || '',
    createdAt,
    updatedAt,
    lastTriagedAt: input.lastTriagedAt?.trim() || undefined,
  };
}

function reportIssueToProjectStoreIssue(issue: ReportIssue, request: ReportExportRequest, exportedAt: string): ProjectStoreIssueInput {
  return {
    id: issue.id,
    title: issue.title,
    type: issue.title.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'reported-issue',
    severity: issue.severity,
    confidence: issue.confidence,
    status: issue.status,
    host: issue.host,
    path: issue.path,
    detail: issue.detail,
    remediation: issue.remediation,
    evidenceRefs: deriveReportIssueEvidenceRefs(issue, request),
    dedupeKey: `${issue.host}:${issue.path}:${issue.title}`.toLowerCase(),
    source: 'report-export',
    assignee: issue.assignee,
    triageNote: issue.triageNote,
    createdAt: exportedAt,
    updatedAt: exportedAt,
    lastTriagedAt: issue.lastTriagedAt,
  };
}

function deriveReportIssueEvidenceRefs(issue: ReportIssue, request: ReportExportRequest): ProjectStoreEvidenceRef[] {
  const exchangeRefs = request.exchanges
    .filter((exchange) => exchange.host === issue.host || exchange.path === issue.path)
    .slice(0, 25)
    .map((exchange) => ({
      kind: 'http-exchange',
      id: exchange.id,
      label: `${exchange.method} ${exchange.path}`,
      source: exchange.source,
      hash: sha256(`${exchange.requestRaw}\n${exchange.responseRaw}`),
    }));
  const crossToolRefs = (request.crossToolEvidenceAttachments ?? [])
    .filter((attachment) => !attachment.issueId || attachment.issueId === issue.id)
    .slice(0, 25)
    .map((attachment) => ({
      kind: attachment.kind || attachment.tool || 'evidence-attachment',
      id: attachment.id,
      label: attachment.title,
      source: attachment.tool,
      hash: attachment.sha256,
    }));
  return normalizeEvidenceRefs([...exchangeRefs, ...crossToolRefs]);
}

function reportSignatureMetadata(content: string) {
  try {
    const parsed = JSON.parse(content) as Record<string, unknown>;
    const signature = isRecord(parsed.signature) ? parsed.signature : undefined;
    return {
      status: typeof signature?.status === 'string' ? signature.status : signature ? 'signed' : 'unsigned',
      signerName: typeof signature?.signerName === 'string' ? signature.signerName : '',
      keyId: typeof signature?.keyId === 'string' ? signature.keyId : '',
      bundleHash: typeof signature?.bundleDigestSha256 === 'string' ? signature.bundleDigestSha256 : sha256(content),
    };
  } catch {
    return {
      status: 'unsigned',
      signerName: '',
      keyId: '',
      bundleHash: sha256(content),
    };
  }
}

function reportArtifactLooksRedacted(content: string, request: ReportExportRequest) {
  const markers = new Set<string>();
  for (const exchange of request.exchanges) {
    for (const value of [exchange.requestRaw, exchange.responseRaw, exchange.notes]) {
      for (const match of value.matchAll(/(?:Bearer\s+|session=|token=|secret=|api[_-]?key=)([A-Za-z0-9._~+/-]{4,})/gi)) {
        markers.add(match[1]);
      }
      for (const match of value.matchAll(/(?:Authorization|Cookie|Set-Cookie|X-API-Key):\s*([^\r\n]+)/gi)) {
        markers.add(match[1]);
      }
    }
  }
  markers.delete('[redacted]');
  return [...markers].filter((marker) => marker.length >= 4).every((marker) => !content.includes(marker));
}

function normalizeReportExportInput(
  input: ProjectStoreReportExportInput,
  content: Buffer,
  contentHash: string,
  now: string,
) {
  const format = normalizeReportFormat(input.format);
  const createdAt = input.createdAt?.trim() || now;
  return {
    id: input.id?.trim() || `report-${format}-${contentHash.slice(0, 18)}`,
    format,
    fileName: input.fileName.trim() || `proxyforge-report-${createdAt}.${format}`,
    path: input.path.trim(),
    contentHash,
    contentSize: content.length,
    issueIds: [...new Set((input.issueIds ?? []).map((id) => id.trim()).filter(Boolean))],
    exchangeIds: [...new Set((input.exchangeIds ?? []).map((id) => id.trim()).filter(Boolean))],
    templateId: input.templateId?.trim() || '',
    sections: normalizeReportSections(input.sections ?? []),
    preparedFor: input.preparedFor?.trim() || '',
    engagementId: input.engagementId?.trim() || '',
    bundleHash: input.bundleHash?.trim() || undefined,
    signatureStatus: input.signatureStatus?.trim() || 'unsigned',
    signerName: input.signerName?.trim() || '',
    keyId: input.keyId?.trim() || '',
    redacted: input.redacted ?? true,
    notes: input.notes?.trim() || '',
    createdAt,
    contentIndex: indexPreview(content),
  };
}

function normalizeAutomationRunInput(input: ProjectStoreAutomationRunInput, now: string): ProjectStoreAutomationRunRecord {
  const workflowId = input.workflowId.trim();
  const workflowName = input.workflowName.trim() || workflowId;
  if (!workflowId) throw new Error('Automation run workflow id is required.');
  const startedAt = input.startedAt?.trim() || now;
  const completedAt = input.completedAt?.trim() || startedAt;
  const createdAt = input.createdAt?.trim() || startedAt;
  const exchangeId = input.exchange?.id?.trim();
  const issueId = input.issue?.id?.trim();
  return {
    id: input.id?.trim() || `automation-run-${sha256(`${workflowId}|${startedAt}`).slice(0, 18)}`,
    workflowId,
    workflowName,
    status: normalizeAutomationRunStatus(input.status),
    trigger: input.trigger?.trim() || 'manual',
    startedAt,
    completedAt,
    durationMs: Math.max(0, Math.trunc(input.durationMs ?? (Math.max(0, Date.parse(completedAt) - Date.parse(startedAt)) || 0))),
    totalRequests: Math.max(0, Math.trunc(input.totalRequests ?? 0)),
    exchangeId: exchangeId || undefined,
    issueId: issueId || undefined,
    schedulerJobId: input.schedulerJobId?.trim() || undefined,
    schedulerLeaseId: input.schedulerLeaseId?.trim() || undefined,
    ciProvider: input.ciProvider?.trim() || undefined,
    ciConfig: input.ciConfig?.trim() || '',
    logs: parseLiteralStringArray(input.logs ?? []),
    operationalRawMaterial: input.operationalRawMaterial ?? {},
    tags: [...new Set((input.tags ?? []).map((tag) => tag.trim()).filter(Boolean))],
    notes: input.notes?.trim() || '',
    createdAt,
    updatedAt: input.updatedAt?.trim() || now,
  };
}

function normalizeAiRunInput(
  input: ProjectStoreAiRunInput,
  output: Buffer,
  prompt: Buffer | undefined,
  outputHash: string,
  promptHash: string | undefined,
  now: string,
): ProjectStoreAiRunRecord {
  const startedAt = input.startedAt?.trim() || now;
  const completedAt = input.completedAt?.trim() || startedAt;
  const createdAt = input.createdAt?.trim() || startedAt;
  const providerId = input.providerId.trim() || 'local';
  const task = input.task.trim() || 'triage';
  return {
    id: input.id?.trim() || `ai-run-${sha256(`${providerId}|${task}|${startedAt}|${outputHash}`).slice(0, 18)}`,
    providerId,
    task,
    status: normalizeAiRunStatus(input.status),
    model: input.model.trim() || 'configured-default',
    startedAt,
    completedAt,
    summary: input.summary.trim(),
    outputHash,
    outputSize: output.length,
    promptHash,
    promptSize: prompt?.length ?? 0,
    evidenceCount: Math.max(0, Math.trunc(input.evidenceCount ?? 0)),
    command: input.command?.trim() || undefined,
    providerLabel: input.providerLabel?.trim() || undefined,
    contextDigest: input.contextDigest?.trim() || undefined,
    usage: input.usage ?? {},
    streamEvents: (input.streamEvents ?? []).filter(isRecord),
    promptEvaluation: input.promptEvaluation ?? {},
    suggestedActions: (input.suggestedActions ?? []).filter(isRecord),
    tags: [...new Set((input.tags ?? []).map((tag) => tag.trim()).filter(Boolean))],
    notes: input.notes?.trim() || '',
    createdAt,
    updatedAt: input.updatedAt?.trim() || now,
  };
}

function normalizeExtensionRunInput(input: ProjectStoreExtensionRunInput, now: string): ProjectStoreExtensionRunRecord {
  const extensionId = input.extensionId.trim();
  const extensionName = input.extensionName.trim() || extensionId;
  const hook = input.hook.trim();
  if (!extensionId) throw new Error('Extension run extension id is required.');
  if (!hook) throw new Error('Extension run hook is required.');
  const startedAt = input.startedAt?.trim() || now;
  const completedAt = input.completedAt?.trim() || startedAt;
  const createdAt = input.createdAt?.trim() || startedAt;
  const exchangeId = input.exchange?.id?.trim();
  const issueId = input.issue?.id?.trim();
  return {
    id: input.id?.trim() || `extension-run-${sha256(`${extensionId}|${hook}|${startedAt}`).slice(0, 18)}`,
    extensionId,
    extensionName,
    hook,
    status: normalizeExtensionRunStatus(input.status),
    target: input.target.trim(),
    startedAt,
    completedAt,
    summary: input.summary.trim(),
    logs: parseLiteralStringArray(input.logs ?? []),
    issueId: issueId || undefined,
    exchangeId: exchangeId || undefined,
    tags: [...new Set((input.tags ?? []).map((tag) => tag.trim()).filter(Boolean))],
    notes: input.notes?.trim() || '',
    createdAt,
    updatedAt: input.updatedAt?.trim() || now,
  };
}

function automationRunSearchIndex(record: ProjectStoreAutomationRunRecord) {
  return [
    record.id,
    record.workflowId,
    record.workflowName,
    record.status,
    record.trigger,
    record.ciProvider ?? '',
    record.ciConfig,
    record.notes,
    ...record.logs,
    JSON.stringify(record.operationalRawMaterial),
    JSON.stringify(record.tags),
  ].join('\n').slice(0, 128 * 1024);
}

function aiRunSearchIndex(record: ProjectStoreAiRunRecord, prompt: Buffer | undefined, output: Buffer) {
  return [
    record.id,
    record.providerId,
    record.providerLabel ?? '',
    record.task,
    record.status,
    record.model,
    record.summary,
    record.command ?? '',
    record.contextDigest ?? '',
    record.notes,
    prompt ? indexPreview(prompt) : '',
    indexPreview(output),
    JSON.stringify(record.usage),
    JSON.stringify(record.streamEvents),
    JSON.stringify(record.promptEvaluation),
    JSON.stringify(record.suggestedActions),
    JSON.stringify(record.tags),
  ].join('\n').slice(0, 128 * 1024);
}

function extensionRunSearchIndex(record: ProjectStoreExtensionRunRecord) {
  return [
    record.id,
    record.extensionId,
    record.extensionName,
    record.hook,
    record.status,
    record.target,
    record.summary,
    record.notes,
    ...record.logs,
    JSON.stringify(record.tags),
  ].join('\n').slice(0, 128 * 1024);
}

function normalizeCallbackPayloadInput(input: ProjectStoreCallbackPayloadInput, now: string): ProjectStoreCallbackPayloadRecord {
  const token = input.token.trim();
  if (!token) throw new Error('Callback payload token is required.');
  const protocol = normalizeCallbackProtocol(input.protocol);
  const createdAt = input.createdAt?.trim() || now;
  return {
    id: input.id?.trim() || `cb-payload-${sha256(`${protocol}|${token}|${input.endpoint}`).slice(0, 16)}`,
    token,
    label: input.label.trim() || `${protocol.toUpperCase()} callback payload`,
    protocol,
    endpoint: input.endpoint.trim() || token,
    status: input.status?.trim() || 'waiting',
    sourceExchangeId: input.sourceExchangeId?.trim() || undefined,
    sourceHost: input.sourceHost?.trim() || '',
    sourcePath: input.sourcePath?.trim() || '',
    notes: input.notes?.trim() || '',
    createdAt,
    updatedAt: now,
    lastInteractionAt: input.lastInteractionAt?.trim() || undefined,
    interactionCount: 0,
  };
}

function normalizeCallbackInteractionInput(
  input: ProjectStoreCallbackInteractionInput,
  raw: Buffer,
  rawHash: string,
  now: string,
) {
  const protocol = normalizeCallbackProtocol(input.protocol);
  const observedAt = input.observedAt?.trim() || now;
  return {
    id: input.id?.trim() || `cb-interaction-${protocol}-${sha256(`${input.payloadId}|${observedAt}|${rawHash}`).slice(0, 16)}`,
    payloadId: input.payloadId.trim() || 'unmatched',
    protocol,
    observedAt,
    sourceIp: input.sourceIp?.trim() || '',
    sourceHost: input.sourceHost?.trim() || '',
    requestLine: input.requestLine?.trim() || `${protocol.toUpperCase()} callback`,
    userAgent: input.userAgent?.trim() || '',
    rawHash,
    rawSize: raw.length,
    severity: input.severity?.trim() || (protocol === 'dns' ? 'medium' : 'high'),
    tags: [...new Set((input.tags ?? []).map((tag) => tag.trim()).filter(Boolean))],
    createdAt: now,
    rawIndex: indexPreview(raw),
  };
}

function rowToExchangeRecord(row: unknown): ProjectStoreHttpExchangeRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store exchange row.');
  return {
    id: String(row.id),
    method: String(row.method),
    url: String(row.url),
    host: String(row.host),
    path: String(row.path),
    protocol: String(row.protocol),
    status: Number(row.status),
    mime: String(row.mime),
    requestHash: String(row.request_hash),
    responseHash: String(row.response_hash),
    requestSize: Number(row.request_size),
    responseSize: Number(row.response_size),
    timingMs: Number(row.timing_ms),
    source: String(row.source),
    tags: parseTags(row.tags_json),
    notes: String(row.notes),
    scopeState: String(row.scope_state),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
  };
}

function rowToTargetHostRecord(row: unknown): ProjectStoreTargetHostRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store target host row.');
  return {
    id: String(row.id ?? ''),
    host: String(row.host ?? ''),
    scheme: String(row.scheme ?? 'http'),
    port: Number(row.port ?? 80),
    scopeState: String(row.scope_state ?? 'unknown'),
    technologySummary: parseJsonRecord(row.technology_summary_json),
    source: normalizeTargetInventorySource(String(row.source ?? 'unknown')),
    exchangeCount: Number(row.exchange_count ?? 0),
    routeCount: Number(row.route_count ?? 0),
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    firstSeenAt: String(row.first_seen_at ?? ''),
    lastSeenAt: String(row.last_seen_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
  };
}

function rowToTargetRouteRecord(row: unknown): ProjectStoreTargetRouteRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store target route row.');
  return {
    id: String(row.id ?? ''),
    hostId: String(row.host_id ?? ''),
    host: String(row.host ?? ''),
    scheme: String(row.scheme ?? 'http'),
    port: Number(row.port ?? 80),
    method: String(row.method ?? 'GET'),
    path: String(row.path ?? '/'),
    normalizedPath: String(row.normalized_path ?? '/'),
    contentType: String(row.content_type ?? 'application/octet-stream'),
    status: Number(row.status ?? 0),
    source: normalizeTargetInventorySource(String(row.source ?? 'unknown')),
    evidenceExchangeId: row.evidence_exchange_id ? String(row.evidence_exchange_id) : undefined,
    parameterCount: Number(row.parameter_count ?? 0),
    issueCount: Number(row.issue_count ?? 0),
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    firstSeenAt: String(row.first_seen_at ?? ''),
    lastSeenAt: String(row.last_seen_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
  };
}

function rowToParameterRecord(row: unknown): ProjectStoreParameterRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store parameter row.');
  return {
    id: String(row.id ?? ''),
    routeId: String(row.route_id ?? ''),
    exchangeId: row.exchange_id ? String(row.exchange_id) : undefined,
    host: String(row.host ?? ''),
    method: String(row.method ?? 'GET'),
    path: String(row.path ?? '/'),
    location: normalizeParameterLocation(String(row.location ?? 'body')),
    name: String(row.name ?? ''),
    valueHash: String(row.value_hash ?? ''),
    valueSample: String(row.value_sample ?? ''),
    inferredType: String(row.inferred_type ?? 'string'),
    insertionCandidate: Number(row.insertion_candidate ?? 0) === 1,
    source: normalizeTargetInventorySource(String(row.source ?? 'unknown')),
    evidenceCount: Number(row.evidence_count ?? 0),
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    firstSeenAt: String(row.first_seen_at ?? ''),
    lastSeenAt: String(row.last_seen_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
  };
}

function rowToCallbackPayloadRecord(row: unknown): ProjectStoreCallbackPayloadRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store callback payload row.');
  return {
    id: String(row.id),
    token: String(row.token),
    label: String(row.label),
    protocol: normalizeCallbackProtocol(String(row.protocol)),
    endpoint: String(row.endpoint),
    status: String(row.status),
    sourceExchangeId: row.source_exchange_id ? String(row.source_exchange_id) : undefined,
    sourceHost: String(row.source_host ?? ''),
    sourcePath: String(row.source_path ?? ''),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at),
    updatedAt: String(row.updated_at),
    lastInteractionAt: row.last_interaction_at ? String(row.last_interaction_at) : undefined,
    interactionCount: Number(row.interaction_count ?? 0),
  };
}

function rowToCallbackInteractionRecord(row: unknown): ProjectStoreCallbackInteractionRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store callback interaction row.');
  return {
    id: String(row.id),
    payloadId: String(row.payload_id),
    protocol: normalizeCallbackProtocol(String(row.protocol)),
    observedAt: String(row.observed_at),
    sourceIp: String(row.source_ip ?? ''),
    sourceHost: String(row.source_host ?? ''),
    requestLine: String(row.request_line ?? ''),
    userAgent: String(row.user_agent ?? ''),
    rawHash: String(row.raw_hash),
    rawSize: Number(row.raw_size ?? 0),
    severity: String(row.severity ?? 'info'),
    tags: parseTags(row.tags_json),
    createdAt: String(row.created_at),
  };
}

function rowToRepeaterTabRecord(row: unknown): ProjectStoreRepeaterTabRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store Repeater tab row.');
  return {
    id: String(row.id),
    name: String(row.name ?? ''),
    targetUrl: String(row.target_url ?? ''),
    host: String(row.host ?? ''),
    method: String(row.method ?? 'GET'),
    path: String(row.path ?? '/'),
    requestHash: String(row.request_hash ?? ''),
    requestSize: Number(row.request_size ?? 0),
    group: String(row.group_name ?? 'Ungrouped'),
    sourceExchangeId: row.source_exchange_id ? String(row.source_exchange_id) : undefined,
    lastReplayId: row.last_replay_id ? String(row.last_replay_id) : undefined,
    lastStatus: Number(row.last_status ?? 0),
    dirty: Number(row.dirty ?? 0) === 1,
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
  };
}

function rowToRepeaterSendRecord(row: unknown): ProjectStoreRepeaterSendRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store Repeater send row.');
  return {
    id: String(row.id),
    tabId: row.tab_id ? String(row.tab_id) : undefined,
    exchangeId: row.exchange_id ? String(row.exchange_id) : undefined,
    targetUrl: String(row.target_url ?? ''),
    host: String(row.host ?? ''),
    method: String(row.method ?? 'GET'),
    path: String(row.path ?? '/'),
    protocol: String(row.protocol ?? 'http'),
    status: Number(row.status ?? 0),
    mime: String(row.mime ?? 'application/octet-stream'),
    requestHash: String(row.request_hash ?? ''),
    responseHash: String(row.response_hash ?? ''),
    requestSize: Number(row.request_size ?? 0),
    responseSize: Number(row.response_size ?? 0),
    timingMs: Number(row.timing_ms ?? 0),
    sourceExchangeId: row.source_exchange_id ? String(row.source_exchange_id) : undefined,
    sessionProfileId: row.session_profile_id ? String(row.session_profile_id) : undefined,
    oastPayloadIds: parseTags(row.oast_payload_ids_json),
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at ?? ''),
  };
}

function rowToWebSocketConnectionRecord(row: unknown): ProjectStoreWebSocketConnectionRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store WebSocket connection row.');
  return {
    id: String(row.id ?? ''),
    url: String(row.url ?? ''),
    host: String(row.host ?? ''),
    path: String(row.path ?? '/'),
    protocol: String(row.protocol ?? 'ws'),
    parentExchangeId: row.parent_exchange_id ? String(row.parent_exchange_id) : undefined,
    firstFrameAt: row.first_frame_at ? String(row.first_frame_at) : undefined,
    lastFrameAt: row.last_frame_at ? String(row.last_frame_at) : undefined,
    frameCount: Number(row.frame_count ?? 0),
    clientFrameCount: Number(row.client_frame_count ?? 0),
    serverFrameCount: Number(row.server_frame_count ?? 0),
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
  };
}

function rowToWebSocketFrameRecord(row: unknown): ProjectStoreWebSocketFrameRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store WebSocket frame row.');
  return {
    id: String(row.id ?? ''),
    connectionId: String(row.connection_id ?? ''),
    direction: normalizeWebSocketDirection(String(row.direction ?? 'client')),
    host: String(row.host ?? ''),
    path: String(row.path ?? '/'),
    url: String(row.url ?? ''),
    opcode: Number(row.opcode ?? 0),
    type: normalizeWebSocketFrameType(String(row.type ?? 'other')),
    payloadHash: String(row.payload_hash ?? ''),
    payloadSize: Number(row.payload_size ?? 0),
    payloadEncoding: normalizeWebSocketPayloadEncoding(String(row.payload_encoding ?? 'text')),
    intercepted: Number(row.intercepted ?? 0) === 1,
    modified: Number(row.modified ?? 0) === 1,
    dropped: Number(row.dropped ?? 0) === 1,
    replayed: Number(row.replayed ?? 0) === 1,
    rewritten: Number(row.rewritten ?? 0) === 1,
    tags: parseTags(row.tags_json),
    source: String(row.source ?? 'proxy'),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at ?? ''),
  };
}

function rowToIntruderAttackRecord(row: unknown): ProjectStoreIntruderAttackRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store Intruder attack row.');
  return {
    id: String(row.id ?? ''),
    targetUrl: String(row.target_url ?? ''),
    host: String(row.host ?? ''),
    path: String(row.path ?? '/'),
    attackMode: normalizeIntruderAttackMode(String(row.attack_mode ?? 'sniper')),
    baseRequestHash: String(row.base_request_hash ?? ''),
    baseRequestSize: Number(row.base_request_size ?? 0),
    payloadPositions: Number(row.payload_positions ?? 0),
    totalRequests: Number(row.total_requests ?? 0),
    retainedResultCount: Number(row.retained_result_count ?? 0),
    blocked: Number(row.blocked ?? 0) === 1,
    message: String(row.message ?? ''),
    payloads: parseStringArray(row.payloads_json),
    payloadSets: parseStringMatrix(row.payload_sets_json),
    payloadProcessors: parseStringArray(row.payload_processors_json),
    payloadRules: parseStringArray(row.payload_rules_json),
    scopeAllowlist: parseStringArray(row.scope_allowlist_json),
    startOffset: row.start_offset === null || row.start_offset === undefined ? undefined : Number(row.start_offset),
    nextOffset: row.next_offset === null || row.next_offset === undefined ? undefined : Number(row.next_offset),
    hasMore: Number(row.has_more ?? 0) === 1,
    payloadPlanCount: Number(row.payload_plan_count ?? 0),
    payloadRuleCount: Number(row.payload_rule_count ?? 0),
    resourcePoolName: String(row.resource_pool_name ?? 'Default sequential pool'),
    resourcePoolMaxConcurrent: Number(row.resource_pool_max_concurrent ?? 1),
    streamSummary: parseJsonRecord(row.stream_summary_json),
    oastSummary: parseJsonRecord(row.oast_summary_json),
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    startedAt: String(row.started_at ?? ''),
    completedAt: String(row.completed_at ?? ''),
    createdAt: String(row.created_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
  };
}

function rowToIntruderResultRecord(row: unknown): ProjectStoreIntruderResultRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store Intruder result row.');
  return {
    id: String(row.id ?? ''),
    attackId: String(row.attack_id ?? ''),
    rowIndex: Number(row.row_index ?? 0),
    payload: String(row.payload ?? ''),
    payloads: parseStringArray(row.payloads_json),
    attackMode: normalizeIntruderAttackMode(String(row.attack_mode ?? 'sniper')),
    status: Number(row.status ?? 0),
    length: Number(row.length ?? 0),
    mime: String(row.mime ?? 'application/octet-stream'),
    timing: Number(row.timing_ms ?? 0),
    requestHash: String(row.request_hash ?? ''),
    responseHash: String(row.response_hash ?? ''),
    requestSize: Number(row.request_size ?? 0),
    responseSize: Number(row.response_size ?? 0),
    grepMatches: parseStringArray(row.grep_matches_json),
    extractMatches: parseStringArray(row.extract_matches_json),
    oastPayloadIds: parseStringArray(row.oast_payload_ids_json),
    callbackInteractionIds: parseStringArray(row.callback_interaction_ids_json),
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at ?? ''),
  };
}

function rowToScannerTaskRecord(row: unknown): ProjectStoreScannerTaskRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store scanner task row.');
  return {
    id: String(row.id ?? ''),
    kind: normalizeScannerTaskKind(String(row.kind ?? 'active')),
    targetUrl: String(row.target_url ?? ''),
    host: String(row.host ?? ''),
    path: String(row.path ?? '/'),
    requestedChecks: normalizeActiveScanCheckIds(parseStringArray(row.requested_checks_json)),
    scopeAllowlist: parseStringArray(row.scope_allowlist_json),
    totalRequests: Number(row.total_requests ?? 0),
    exchangeIds: parseStringArray(row.exchange_ids_json),
    findingCount: Number(row.finding_count ?? 0),
    suppressedFindingCount: Number(row.suppressed_finding_count ?? 0),
    blocked: Number(row.blocked ?? 0) === 1,
    message: String(row.message ?? ''),
    tuning: parseJsonRecord(row.tuning_json),
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    startedAt: String(row.started_at ?? ''),
    completedAt: String(row.completed_at ?? ''),
    createdAt: String(row.created_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
  };
}

function rowToScannerFindingRecord(row: unknown): ProjectStoreScannerFindingRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store scanner finding row.');
  return {
    id: String(row.id ?? ''),
    taskId: String(row.task_id ?? ''),
    checkId: normalizeActiveScanCheckId(String(row.check_id ?? 'security-headers')),
    title: String(row.title ?? ''),
    severity: normalizeIssueSeverity(String(row.severity ?? 'info')),
    confidence: normalizeIssueConfidence(String(row.confidence ?? 'tentative')),
    host: String(row.host ?? ''),
    path: String(row.path ?? '/'),
    detail: String(row.detail ?? ''),
    remediation: String(row.remediation ?? ''),
    evidenceExchangeId: row.evidence_exchange_id ? String(row.evidence_exchange_id) : undefined,
    dedupeKey: String(row.dedupe_key ?? ''),
    confidenceReason: String(row.confidence_reason ?? ''),
    suppressed: Number(row.suppressed ?? 0) === 1,
    suppressionReason: String(row.suppression_reason ?? ''),
    tags: parseTags(row.tags_json),
    createdAt: String(row.created_at ?? ''),
  };
}

function rowToIssueRecord(row: unknown): ProjectStoreIssueRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store issue row.');
  return {
    id: String(row.id ?? ''),
    title: String(row.title ?? ''),
    type: String(row.type ?? 'manual'),
    severity: normalizeIssueSeverity(String(row.severity ?? 'info')),
    confidence: normalizeIssueConfidence(String(row.confidence ?? 'tentative')),
    status: normalizeIssueStatus(String(row.status ?? 'open')),
    host: String(row.host ?? ''),
    path: String(row.path ?? '/'),
    detail: String(row.detail ?? ''),
    remediation: String(row.remediation ?? ''),
    evidenceRefs: parseEvidenceRefs(row.evidence_refs_json),
    dedupeKey: String(row.dedupe_key ?? ''),
    source: String(row.source ?? 'manual'),
    assignee: row.assignee ? String(row.assignee) : undefined,
    triageNote: String(row.triage_note ?? ''),
    createdAt: String(row.created_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
    lastTriagedAt: row.last_triaged_at ? String(row.last_triaged_at) : undefined,
  };
}

function rowToReportExportRecord(row: unknown): ProjectStoreReportExportRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store report row.');
  return {
    id: String(row.id ?? ''),
    format: normalizeReportFormat(String(row.format ?? 'json')),
    fileName: String(row.file_name ?? ''),
    path: String(row.path ?? ''),
    contentHash: String(row.content_hash ?? ''),
    contentSize: Number(row.content_size ?? 0),
    issueIds: parseStringArray(row.issue_ids_json),
    exchangeIds: parseStringArray(row.exchange_ids_json),
    templateId: String(row.template_id ?? ''),
    sections: normalizeReportSections(parseStringArray(row.sections_json)),
    preparedFor: String(row.prepared_for ?? ''),
    engagementId: String(row.engagement_id ?? ''),
    bundleHash: row.bundle_hash ? String(row.bundle_hash) : undefined,
    signatureStatus: String(row.signature_status ?? 'unsigned'),
    signerName: String(row.signer_name ?? ''),
    keyId: String(row.key_id ?? ''),
    redacted: Number(row.redacted ?? 1) === 1,
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at ?? ''),
  };
}

function rowToAutomationRunRecord(row: unknown): ProjectStoreAutomationRunRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store automation run row.');
  return {
    id: String(row.id ?? ''),
    workflowId: String(row.workflow_id ?? ''),
    workflowName: String(row.workflow_name ?? ''),
    status: normalizeAutomationRunStatus(String(row.status ?? 'blocked')),
    trigger: String(row.trigger ?? 'manual'),
    startedAt: String(row.started_at ?? ''),
    completedAt: String(row.completed_at ?? ''),
    durationMs: Number(row.duration_ms ?? 0),
    totalRequests: Number(row.total_requests ?? 0),
    exchangeId: row.exchange_id ? String(row.exchange_id) : undefined,
    issueId: row.issue_id ? String(row.issue_id) : undefined,
    schedulerJobId: row.scheduler_job_id ? String(row.scheduler_job_id) : undefined,
    schedulerLeaseId: row.scheduler_lease_id ? String(row.scheduler_lease_id) : undefined,
    ciProvider: row.ci_provider ? String(row.ci_provider) : undefined,
    ciConfig: String(row.ci_config ?? ''),
    logs: parseStringArray(row.logs_json),
    operationalRawMaterial: parseJsonRecord(row.raw_material_json),
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
  };
}

function rowToAiRunRecord(row: unknown): ProjectStoreAiRunRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store AI run row.');
  return {
    id: String(row.id ?? ''),
    providerId: String(row.provider_id ?? ''),
    task: String(row.task ?? ''),
    status: normalizeAiRunStatus(String(row.status ?? 'error')),
    model: String(row.model ?? ''),
    startedAt: String(row.started_at ?? ''),
    completedAt: String(row.completed_at ?? ''),
    summary: String(row.summary ?? ''),
    outputHash: String(row.output_hash ?? ''),
    outputSize: Number(row.output_size ?? 0),
    promptHash: row.prompt_hash ? String(row.prompt_hash) : undefined,
    promptSize: Number(row.prompt_size ?? 0),
    evidenceCount: Number(row.evidence_count ?? 0),
    command: row.command ? String(row.command) : undefined,
    providerLabel: row.provider_label ? String(row.provider_label) : undefined,
    contextDigest: row.context_digest ? String(row.context_digest) : undefined,
    usage: parseJsonRecord(row.usage_json),
    streamEvents: parseRecordArray(row.stream_events_json),
    promptEvaluation: parseJsonRecord(row.prompt_evaluation_json),
    suggestedActions: parseRecordArray(row.suggested_actions_json),
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
  };
}

function rowToExtensionRunRecord(row: unknown): ProjectStoreExtensionRunRecord {
  if (!isRecord(row)) throw new Error('Malformed Project Store extension run row.');
  return {
    id: String(row.id ?? ''),
    extensionId: String(row.extension_id ?? ''),
    extensionName: String(row.extension_name ?? ''),
    hook: String(row.hook ?? ''),
    status: normalizeExtensionRunStatus(String(row.status ?? 'error')),
    target: String(row.target ?? ''),
    startedAt: String(row.started_at ?? ''),
    completedAt: String(row.completed_at ?? ''),
    summary: String(row.summary ?? ''),
    logs: parseStringArray(row.logs_json),
    issueId: row.issue_id ? String(row.issue_id) : undefined,
    exchangeId: row.exchange_id ? String(row.exchange_id) : undefined,
    tags: parseTags(row.tags_json),
    notes: String(row.notes ?? ''),
    createdAt: String(row.created_at ?? ''),
    updatedAt: String(row.updated_at ?? ''),
  };
}

function rowToAuditEventRecord(row: Record<string, unknown>): ProjectStoreAuditEventRecord {
  return {
    id: String(row.id ?? ''),
    actor: String(row.actor ?? ''),
    action: String(row.action ?? ''),
    targetRef: String(row.target_ref ?? ''),
    decision: normalizeAuditDecision(String(row.decision ?? 'completed')),
    detail: String(row.detail ?? ''),
    createdAt: String(row.created_at ?? ''),
    previousHash: typeof row.previous_hash === 'string' && row.previous_hash ? row.previous_hash : undefined,
    hash: String(row.hash ?? ''),
  };
}

function normalizeCallbackProtocol(value: string): ProjectStoreCallbackProtocol {
  return value === 'dns' || value === 'smtp' ? value : 'http';
}

function normalizeAuditDecision(value: string): ProjectStoreAuditDecision {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'allowed' || normalized === 'blocked' || normalized === 'completed' || normalized === 'updated') {
    return normalized;
  }
  throw new Error(`Unsupported audit decision: ${value}`);
}

function normalizeIssueSeverity(value: string): ProjectStoreIssueSeverity {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'critical' || normalized === 'high' || normalized === 'medium' || normalized === 'low' || normalized === 'info') {
    return normalized;
  }
  return 'info';
}

function normalizeIssueConfidence(value: string): ProjectStoreIssueConfidence {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'certain' || normalized === 'firm' || normalized === 'tentative') {
    return normalized;
  }
  return 'tentative';
}

function normalizeIssueStatus(value: string): ProjectStoreIssueStatus {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'open' || normalized === 'triaged' || normalized === 'false-positive' || normalized === 'fixed') {
    return normalized;
  }
  return 'open';
}

function normalizeAutomationRunStatus(value: string): ProjectStoreAutomationRunStatus {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'ready' || normalized === 'running' || normalized === 'complete') return normalized;
  return 'blocked';
}

function normalizeAiRunStatus(value: string): ProjectStoreAiRunStatus {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'complete' || normalized === 'unavailable') return normalized;
  return 'error';
}

function normalizeExtensionRunStatus(value: string): ProjectStoreExtensionRunStatus {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'complete' || normalized === 'blocked') return normalized;
  return 'error';
}

function normalizeReportFormat(value: string): ReportFormat {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'markdown' || normalized === 'html' || normalized === 'json' || normalized === 'bundle' || normalized === 'pdf') {
    return normalized;
  }
  return 'json';
}

function normalizeWebSocketDirection(value: string): ProjectStoreWebSocketDirection {
  return value.trim().toLowerCase() === 'server' ? 'server' : 'client';
}

function normalizeWebSocketFrameType(value: string): ProjectStoreWebSocketFrameType {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'text' || normalized === 'binary' || normalized === 'close' || normalized === 'ping' || normalized === 'pong' || normalized === 'other') {
    return normalized;
  }
  return 'other';
}

function normalizeWebSocketPayloadEncoding(value: string): ProjectStoreWebSocketPayloadEncoding {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'hex' || normalized === 'base64') return normalized;
  return 'text';
}

function normalizeIntruderAttackMode(value: string): IntruderAttackMode {
  const normalized = value.trim().toLowerCase();
  if (normalized === 'battering-ram' || normalized === 'pitchfork' || normalized === 'cluster-bomb') {
    return normalized;
  }
  return 'sniper';
}

function normalizeScannerTaskKind(value: string): ProjectStoreScannerTaskKind {
  return value.trim().toLowerCase() === 'crawl-audit' ? 'crawl-audit' : 'active';
}

function normalizeActiveScanCheckIds(values: string[]): ActiveScanCheckId[] {
  return [...new Set(values.map(normalizeActiveScanCheckId))];
}

function normalizeActiveScanCheckId(value: string): ActiveScanCheckId {
  const normalized = value.trim().toLowerCase();
  const allowed: ActiveScanCheckId[] = [
    'security-headers',
    'cors-origin',
    'cache-key',
    'method-options',
    'authz-diff',
    'jwt-claims',
    'graphql-introspection',
    'oast-ssrf',
    'reflected-xss',
    'sql-injection',
    'path-traversal',
    'open-redirect',
    'command-injection',
  ];
  return allowed.includes(normalized as ActiveScanCheckId) ? normalized as ActiveScanCheckId : 'security-headers';
}

function normalizeReportSections(values: string[]): ReportSection[] {
  const allowed = new Set<ReportSection>(['executive', 'technical', 'remediation', 'evidence', 'appendix']);
  return [...new Set(values.map((value) => value.trim().toLowerCase()).filter((value): value is ReportSection => allowed.has(value as ReportSection)))];
}

function normalizeEvidenceRefs(values: ProjectStoreEvidenceRef[]): ProjectStoreEvidenceRef[] {
  const seen = new Set<string>();
  const refs: ProjectStoreEvidenceRef[] = [];
  for (const value of values) {
    const kind = value.kind.trim();
    const id = value.id.trim();
    if (!kind || !id) continue;
    const key = `${kind}:${id}`;
    if (seen.has(key)) continue;
    seen.add(key);
    refs.push({
      kind,
      id,
      label: value.label?.trim() || undefined,
      source: value.source?.trim() || undefined,
      hash: value.hash?.trim() || undefined,
    });
  }
  return refs;
}

function parseEvidenceRefs(value: unknown): ProjectStoreEvidenceRef[] {
  try {
    const parsed = JSON.parse(String(value));
    return Array.isArray(parsed) ? normalizeEvidenceRefs(parsed.filter(isRecord).map((entry) => ({
      kind: String(entry.kind ?? ''),
      id: String(entry.id ?? ''),
      label: typeof entry.label === 'string' ? entry.label : undefined,
      source: typeof entry.source === 'string' ? entry.source : undefined,
      hash: typeof entry.hash === 'string' ? entry.hash : undefined,
    }))) : [];
  } catch {
    return [];
  }
}

function parseStringArray(value: unknown) {
  try {
    const parsed = JSON.parse(String(value));
    return Array.isArray(parsed) ? parsed.map(String).filter(Boolean) : [];
  } catch {
    return [];
  }
}

function parseRecordArray(value: unknown): Record<string, unknown>[] {
  try {
    const parsed = JSON.parse(String(value));
    return Array.isArray(parsed) ? parsed.filter(isRecord) : [];
  } catch {
    return [];
  }
}

function parseJsonRecord(value: unknown): Record<string, unknown> {
  try {
    const parsed = JSON.parse(String(value));
    return isRecord(parsed) ? parsed : {};
  } catch {
    return {};
  }
}

function parseStringMatrix(value: unknown) {
  try {
    const parsed = JSON.parse(String(value));
    return Array.isArray(parsed) ? normalizeStringMatrix(parsed) : [];
  } catch {
    return [];
  }
}

function parseLiteralStringArray(values: unknown[]) {
  return values.map((value) => String(value)).filter(Boolean);
}

function normalizeStringMatrix(values: unknown[]) {
  return values
    .filter(Array.isArray)
    .map((entry) => entry.map((value) => String(value)).filter(Boolean))
    .filter((entry) => entry.length > 0);
}

function parseTags(value: unknown) {
  try {
    const parsed = JSON.parse(String(value));
    return Array.isArray(parsed) ? parsed.map(String) : [];
  } catch {
    return [];
  }
}

function parseHeaders(raw: Buffer) {
  const text = raw.toString('utf8', 0, Math.min(raw.length, 64 * 1024));
  const [head] = text.split(/\r?\n\r?\n/, 1);
  const lines = head.split(/\r?\n/).slice(1);
  return lines
    .map((line) => {
      const index = line.indexOf(':');
      return index === -1 ? null : [line.slice(0, index).trim(), line.slice(index + 1).trim()];
    })
    .filter(Boolean);
}

function contentTypeFromRaw(raw: Buffer) {
  return raw.toString('utf8', 0, Math.min(raw.length, 8192)).match(/^content-type:\s*(.+)$/im)?.[1]?.trim();
}

function requestLineParts(raw: Buffer, target: URL) {
  const firstLine = raw.toString('utf8', 0, Math.min(raw.length, 8192)).split(/\r?\n/, 1)[0] ?? '';
  const [rawMethod = 'GET', rawPath = `${target.pathname}${target.search}`] = firstLine.trim().split(/\s+/);
  return {
    method: rawMethod.trim().toUpperCase() || 'GET',
    path: rawPath.trim() || `${target.pathname}${target.search}` || '/',
  };
}

function indexPreview(raw: Buffer) {
  return raw.toString('utf8', 0, Math.min(raw.length, 16 * 1024));
}

function toBuffer(value: string | Buffer) {
  return Buffer.isBuffer(value) ? value : Buffer.from(value, 'utf8');
}

function webSocketPayloadToBuffer(value: string | Buffer, encoding: ProjectStoreWebSocketPayloadEncoding = 'text') {
  if (Buffer.isBuffer(value)) return value;
  if (encoding === 'hex') {
    const cleaned = value.replace(/[^a-fA-F0-9]/g, '');
    return Buffer.from(cleaned.length % 2 === 0 ? cleaned : `0${cleaned}`, 'hex');
  }
  if (encoding === 'base64') return Buffer.from(value, 'base64');
  return Buffer.from(value, 'utf8');
}

function sha256(value: string | Buffer) {
  return createHash('sha256').update(value).digest('hex');
}

function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value as Record<string, unknown>).filter((key) => (value as Record<string, unknown>)[key] !== undefined).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalize((value as Record<string, unknown>)[key])}`
    )).join(',')}}`;
  }
  return JSON.stringify(value) ?? 'null';
}

function safeUrl(value: string) {
  try {
    return new URL(value);
  } catch {
    return new URL('http://invalid.local/');
  }
}

function clampInteger(value: number, min: number, max: number) {
  if (!Number.isFinite(value)) return min;
  return Math.min(max, Math.max(min, Math.trunc(value)));
}

function likeClause(column: string) {
  return `${column} like ? escape '~'`;
}

function likeAnyClause(columns: string[]) {
  return `(${columns.map(likeClause).join(' or ')})`;
}

function escapeLike(value: string) {
  return value.replace(/[~%_]/g, (character) => `~${character}`);
}

function isSafeArchiveEntry(entry: string) {
  const normalized = entry.replace(/\\/g, '/');
  if (!normalized || normalized.startsWith('/') || /^[a-z]:\//i.test(normalized)) return false;
  return !normalized.split('/').some((part) => part === '..' || part === '');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function isFileExistsError(error: unknown) {
  return isRecord(error) && error.code === 'EEXIST';
}

function isNotFoundError(error: unknown) {
  return isRecord(error) && error.code === 'ENOENT';
}

async function fileExists(filePath: string) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

async function copyIfExists(sourcePath: string, destinationPath: string) {
  if (!await fileExists(sourcePath)) return;
  await fs.mkdir(path.dirname(destinationPath), { recursive: true });
  await fs.copyFile(sourcePath, destinationPath);
}

async function copyDirectoryIfExists(sourcePath: string, destinationPath: string) {
  if (!await fileExists(sourcePath)) return;
  await fs.mkdir(path.dirname(destinationPath), { recursive: true });
  await fs.cp(sourcePath, destinationPath, { recursive: true });
}

function sanitizeBackupLabel(value: string) {
  return value.trim().replace(/[^a-z0-9_.-]+/gi, '-').replace(/^-+|-+$/g, '').slice(0, 80) || 'project-store';
}

function manifestPath(rootDir: string) {
  return path.join(rootDir, 'manifest.json');
}

function databasePath(rootDir: string) {
  return path.join(rootDir, 'project.db');
}

function blobRoot(rootDir: string) {
  return path.join(rootDir, 'blobs', 'sha256');
}

function blobPath(rootDir: string, hash: string) {
  return path.join(blobRoot(rootDir), hash.slice(0, 2), hash.slice(2, 4), `${hash}.bin`);
}

function recoveryRoot(rootDir: string) {
  return path.join(rootDir, 'recovery');
}

function pendingJournalPath(rootDir: string) {
  return path.join(recoveryRoot(rootDir), 'http-exchanges.pending.jsonl');
}

function committedJournalPath(rootDir: string) {
  return path.join(recoveryRoot(rootDir), 'http-exchanges.committed.jsonl');
}
