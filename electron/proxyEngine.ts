import http from 'node:http';
import https from 'node:https';
import { randomBytes } from 'node:crypto';
import net from 'node:net';
import tls from 'node:tls';
import { URL } from 'node:url';
import { CertificateAuthorityManager } from './certManager';
import { applySessionProfileToRawRequest, type RuntimeSessionProfile, type SessionApplyOptions } from './sessionEngine';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export interface HttpExchange {
  id: string;
  method: string;
  host: string;
  path: string;
  url: string;
  status: number;
  length: number;
  mime: string;
  risk: Severity;
  timing: number;
  notes: string;
  source: 'proxy' | 'repeater' | 'scanner' | 'crawler' | 'demo';
  time: string;
  requestRaw: string;
  responseRaw: string;
  tags: string[];
}

interface ProxyStatus {
  running: boolean;
  port: number;
  mode: 'electron' | 'browser';
  message: string;
}

export interface ReplayRequest {
  rawRequest: string;
  targetUrl: string;
  scopeAllowlist: string[];
  settings?: ReplayTransportSettings;
  sessionProfile?: RuntimeSessionProfile;
  sessionOptions?: SessionApplyOptions;
  oastPayloads?: ReplayOastPayloadReference[];
  repeaterTabId?: string;
  repeaterTabName?: string;
  repeaterTabGroup?: string;
  repeaterSendId?: string;
  sourceExchangeId?: string;
  operator?: string;
  tags?: string[];
  notes?: string;
}

export interface ReplayOastPayloadReference {
  id: string;
  token: string;
  endpoint: string;
  protocol?: 'http' | 'dns' | 'smtp';
}

export type ReplayRedirectMode = 'manual' | 'follow';
export type ReplayConnectionMode = 'default' | 'close' | 'keep-alive';

export interface ReplayTransportSettings {
  redirectMode: ReplayRedirectMode;
  maxRedirects: number;
  connectionMode: ReplayConnectionMode;
  timeoutMs: number;
}

export type IntruderAttackMode = 'sniper' | 'battering-ram' | 'pitchfork' | 'cluster-bomb';
export type IntruderPayloadProcessor =
  | 'url-encode'
  | 'double-url-encode'
  | 'base64'
  | 'html-encode'
  | 'json-escape'
  | 'hex-encode'
  | 'uppercase'
  | 'lowercase';
export type IntruderPayloadRuleId =
  | 'case-variants'
  | 'url-recursive'
  | 'path-depth'
  | 'delimiter-variants'
  | 'extension-bypass'
  | 'null-byte';

export interface IntruderOastPayloadReference {
  id: string;
  token: string;
  endpoint: string;
  label?: string;
  protocol?: 'http' | 'dns' | 'smtp';
}

export interface IntruderOastInteractionReference {
  id: string;
  payloadId: string;
  protocol: string;
  observedAt?: string;
  requestLine?: string;
  raw: string | Buffer;
}

export interface IntruderOastCorrelationSummary {
  payloadCount: number;
  interactionCount: number;
  correlatedResultCount: number;
  correlatedInteractionCount: number;
  pendingPayloadIds: string[];
}

export interface IntruderAttackRequest {
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

export interface IntruderAttackResult {
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

export interface IntruderAttackSummary {
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

export interface IntruderStreamingSummary {
  chunkSize: number;
  chunkCount: number;
  completedChunks: number;
  maxConcurrency: number;
  maxInFlight: number;
  durationMs: number;
  requestRatePerSecond: number;
  resultWindowSize: number;
  retainedResultCount: number;
  droppedResultCount: number;
  firstRetainedOffset: number;
  lastRetainedOffset: number;
  estimatedMemoryBytes: number;
  memoryBudgetBytes?: number;
  memoryPressure: 'low' | 'medium' | 'high';
}

export interface IntruderAttackModeMatrixEntry {
  mode: IntruderAttackMode;
  payloadPositions: number;
  payloadSetCount: number;
  payloadCounts: number[];
  requestCount: number;
  samplePayloads: string[][];
  sampleRequests: string[];
  semantics: string;
  warnings: string[];
}

export interface IntruderPayloadTransformationMatrix {
  processors: IntruderPayloadProcessor[];
  rules: IntruderPayloadRuleId[];
  inputSetCount: number;
  inputPayloadCounts: number[];
  expandedPayloadCounts: number[];
  sampleExpandedPayloads: string[][];
  warnings: string[];
}

export interface IntruderAttackModeMatrixPackage {
  kind: 'proxyforge-intruder-attack-mode-matrix';
  schemaVersion: 1;
  generatedAt: string;
  payloadPositions: number;
  payloadSetCount: number;
  payloadTransformations: IntruderPayloadTransformationMatrix;
  modes: IntruderAttackModeMatrixEntry[];
  selectedMode?: IntruderAttackMode;
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  summary: string;
  content: string;
}

export interface IntruderCheckpointQueueEvidence {
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

export interface IntruderCheckpointResumePackage {
  kind: 'proxyforge-intruder-checkpoint-resume-package';
  schemaVersion: 1;
  generatedAt: string;
  targetUrl: string;
  attackMode: IntruderAttackMode;
  summaryIds: string[];
  payloadPlanCount: number;
  totalRequestsSent: number;
  finalOffset: number;
  checkpointCount: number;
  pausedCheckpointCount: number;
  resumedCheckpointCount: number;
  queue: IntruderCheckpointQueueEvidence[];
  checkpointChain: Array<{
    summaryId: string;
    startOffset: number;
    nextOffset: number;
    hasMore: boolean;
    totalRequests: number;
    retainedResultCount: number;
    droppedResultCount: number;
    resourcePoolName: string;
    resourcePoolMaxConcurrent: number;
    payloadRuleCount: number;
    resultIds: string[];
    rawRequestSamples: string[];
  }>;
  resumeLinks: Array<{
    fromSummaryId: string;
    toSummaryId: string;
    expectedOffset: number;
    actualStartOffset: number;
    linked: boolean;
  }>;
  resourcePools: Array<{
    name: string;
    maxConcurrent: number;
    summaryIds: string[];
  }>;
  operationalSecretSignals: string[];
  requirements: {
    checkpointPauseCovered: boolean;
    resumeCovered: boolean;
    queueStateCovered: boolean;
    resourcePoolStateCovered: boolean;
    payloadRuleStateCovered: boolean;
    resultWindowStateCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: true;
  summary: string;
  content: string;
}

export interface IntruderGrepExtractComparisonPackage {
  kind: 'proxyforge-intruder-grep-extract-comparison-package';
  schemaVersion: 1;
  generatedAt: string;
  summaryId: string;
  targetUrl: string;
  attackMode: IntruderAttackMode;
  resultCount: number;
  grepMatchCount: number;
  extractMatchCount: number;
  comparisonCount: number;
  clusterCount: number;
  rankingCount: number;
  resultSamples: Array<{
    id: string;
    payload: string;
    payloads: string[];
    status: number;
    length: number;
    timing: number;
    grepMatches: string[];
    extractMatches: string[];
    requestRaw: string;
    responseRaw: string;
    tags: string[];
  }>;
  comparisons: Array<{
    id: string;
    baselineResultId: string;
    candidateResultId: string;
    baselinePayload: string;
    candidatePayload: string;
    statusDelta: number;
    lengthDelta: number;
    timingDelta: number;
    grepDelta: string[];
    extractDelta: string[];
    verdict: 'interesting' | 'similar' | 'regression';
    notes: string;
  }>;
  clusters: Array<{
    id: string;
    title: string;
    signature: string;
    verdict: 'interesting' | 'similar' | 'regression';
    status: number;
    mime: string;
    resultCount: number;
    representativeResultId: string;
    payloads: string[];
    averageLength: number;
    averageTiming: number;
    grepSignals: string[];
    extractSignals: string[];
    notes: string;
  }>;
  rankings: Array<{
    id: string;
    resultId: string;
    payload: string;
    rank: number;
    score: number;
    verdict: 'interesting' | 'similar' | 'regression';
    status: number;
    length: number;
    timing: number;
    lengthZScore: number;
    timingZScore: number;
    statusRarity: number;
    grepSignalCount: number;
    extractSignalCount: number;
    reasons: string[];
  }>;
  promotedIssue?: {
    id: string;
    title: string;
    severity: Severity;
    confidence: 'certain' | 'firm' | 'tentative';
    detail: string;
    remediation: string;
  };
  operationalSecretSignals: string[];
  requirements: {
    grepMatchCovered: boolean;
    extractRegexCovered: boolean;
    baselineComparisonCovered: boolean;
    clusteringCovered: boolean;
    statisticalRankingCovered: boolean;
    scannerPromotionCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: true;
  summary: string;
  content: string;
}

export interface IntruderLiveTargetProfilePackage {
  kind: 'proxyforge-intruder-live-target-profile-package';
  schemaVersion: 1;
  generatedAt: string;
  targetUrlCount: number;
  attackModeCount: number;
  totalRequestsSent: number;
  retainedResultCount: number;
  droppedResultCount: number;
  maxInFlight: number;
  requestRatePerSecond: number;
  statusClasses: string[];
  targetProfiles: Array<{
    summaryId: string;
    targetUrl: string;
    path: string;
    attackMode: IntruderAttackMode;
    totalRequests: number;
    statusCodes: number[];
    grepMatchCount: number;
    extractMatchCount: number;
    retainedResultCount: number;
    droppedResultCount: number;
    maxInFlight: number;
    requestRatePerSecond: number;
    rawRequestSamples: string[];
  }>;
  packageRefreshProof: {
    refreshedAt: string;
    summaryDigests: string[];
    profileDigest: string;
    linkedPackageKinds: string[];
    staleSummaryIds: string[];
  };
  operationalSecretSignals: string[];
  requirements: {
    liveTargetDiversityCovered: boolean;
    attackModeDiversityCovered: boolean;
    highVolumeStreamingCovered: boolean;
    resourcePoolConcurrencyCovered: boolean;
    checkpointResumeCovered: boolean;
    grepExtractTriageCovered: boolean;
    authzDifferentialCovered: boolean;
    payloadTransformCoverageCovered: boolean;
    packageRefreshCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: true;
  summary: string;
  content: string;
}

export interface IntruderOastCorrelationPackage {
  kind: 'proxyforge-intruder-oast-correlation-package';
  schemaVersion: 1;
  generatedAt: string;
  summaryId: string;
  targetUrl: string;
  attackMode: IntruderAttackMode;
  payloadCount: number;
  interactionCount: number;
  correlatedResultCount: number;
  correlatedInteractionCount: number;
  resultRows: Array<{
    id: string;
    payload: string;
    status: number;
    oastPayloadIds: string[];
    callbackInteractionIds: string[];
    tags: string[];
    requestRaw: string;
    responseRaw: string;
  }>;
  requirements: {
    payloadRowsCovered: boolean;
    callbackInteractionsCovered: boolean;
    rowCorrelationCovered: boolean;
    rawExecutorMaterialPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

const INTRUDER_MAX_PAYLOAD_VALUES = 1000;
const INTRUDER_MAX_PAYLOAD_PLANS = 5000;
const INTRUDER_MAX_PAYLOAD_REQUESTS = 5000;
const INTRUDER_DEFAULT_STREAM_CHUNK_SIZE = 50;
const INTRUDER_MAX_MEMORY_BUDGET_BYTES = 512 * 1024 * 1024;

export type ActiveScanCheckId =
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

export const ACTIVE_SCAN_BUILT_IN_CHECKS: ActiveScanCheckId[] = [
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

export interface ActiveScanRequest {
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

export interface ActiveScanFinding {
  id: string;
  checkId: ActiveScanCheckId;
  title: string;
  severity: Severity;
  confidence: 'certain' | 'firm' | 'tentative';
  host: string;
  path: string;
  detail: string;
  remediation: string;
  evidenceExchangeId?: string;
  dedupeKey?: string;
  confidenceReason?: string;
}

export interface ActiveScanSuppressedFinding {
  id: string;
  checkId: ActiveScanCheckId;
  title: string;
  host: string;
  path: string;
  evidenceExchangeId?: string;
  dedupeKey?: string;
  reason: string;
}

export interface ActiveScanTuningMetadata {
  profile: 'browser-app-calibration';
  falsePositiveControls: string[];
  suppressedFindingCount: number;
  dedupedFindingCount: number;
  findingDedupeKeys: string[];
  calibrationNotes: string[];
}

export interface ActiveScanSummary {
  id: string;
  targetUrl: string;
  startedAt: string;
  completedAt: string;
  totalRequests: number;
  blocked: boolean;
  message: string;
  findings: ActiveScanFinding[];
  suppressedFindings: ActiveScanSuppressedFinding[];
  tuning: ActiveScanTuningMetadata;
  exchanges: HttpExchange[];
}

export interface ActiveScanCheckPackDefinition {
  id: string;
  name: string;
  checks: string[];
  description?: string;
  source?: string;
}

export interface ActiveScanCheckPackEvidencePackage {
  kind: 'proxyforge-active-scan-check-pack-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  targetUrl: string;
  scopeAllowlist: string[];
  throttleMs: number;
  maxRequests: number;
  requestedChecks: ActiveScanCheckId[];
  executedChecks: ActiveScanCheckId[];
  checkPackMatrix: Array<{
    id: string;
    name: string;
    source: string;
    requestedChecks: string[];
    supportedChecks: ActiveScanCheckId[];
    unsupportedChecks: string[];
    selectedSupportedChecks: ActiveScanCheckId[];
  }>;
  checkCoverage: Array<{
    checkId: ActiveScanCheckId;
    label: string;
    requested: boolean;
    executed: boolean;
    exchangeIds: string[];
    findingIds: string[];
    suppressedFindingIds: string[];
  }>;
  scopeGate: {
    blockedOutOfScope: boolean;
    blockedMessage?: string;
  };
  rawProbeSamples: Array<{
    id: string;
    method: string;
    host: string;
    path: string;
    status: number;
    requestRaw: string;
    responseRaw: string;
    tags: string[];
  }>;
  operationalSecretSignals: string[];
  requirements: {
    scopeGateBlocksOutOfScope: boolean;
    allBuiltInChecksCovered: boolean;
    checkPackExpansionCovered: boolean;
    rateAndCapControlsRecorded: boolean;
    authzTwoLegComparisonCovered: boolean;
    findingDedupeConfidenceCovered: boolean;
    falsePositiveTuningCovered: boolean;
    rawProbeExchangesPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export interface CrawlAuditInsertionPoint {
  id: string;
  routeId: string;
  type: 'query' | 'form' | 'path' | 'cookie' | 'header' | 'body' | 'json' | 'xml' | 'multipart' | 'graphql';
  name: string;
  method: string;
  url: string;
  evidence: string;
}

export interface CrawlAuditRequest {
  scopeAllowlist: string[];
  checks: ActiveScanCheckId[];
  insertionPoints: CrawlAuditInsertionPoint[];
  sessionHeaders?: Record<string, string>;
  throttleMs: number;
  maxInsertionPoints: number;
}

export interface CrawlAuditSummary extends ActiveScanSummary {
  auditedInsertionPoints: number;
}

export interface CrawlAuditInsertionEvidencePackage {
  kind: 'proxyforge-crawl-audit-insertion-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  requestedInsertionPointCount: number;
  scopedInsertionPointCount: number;
  auditedInsertionPointCount: number;
  duplicateMergedCount: number;
  outOfScopeSkippedCount: number;
  insertionTypeCounts: Record<string, number>;
  auditedInsertionPoints: Array<{
    type: CrawlAuditInsertionPoint['type'];
    name: string;
    method: string;
    url: string;
    evidence: string;
    exchangeIds: string[];
    findingIds: string[];
  }>;
  checkCoverage: Array<{
    checkId: ActiveScanCheckId;
    exchangeIds: string[];
    findingIds: string[];
    suppressedFindingIds: string[];
  }>;
  scopeGate: {
    blockedOutOfScope: boolean;
    blockedMessage?: string;
  };
  rawProbeSamples: Array<{
    id: string;
    method: string;
    host: string;
    path: string;
    status: number;
    requestRaw: string;
    responseRaw: string;
    tags: string[];
  }>;
  operationalSecretSignals: string[];
  requirements: {
    crawlerInsertionPointsLinked: boolean;
    scopeGateBlocksOutOfScope: boolean;
    queryFormPathCoverage: boolean;
    duplicateAndOutOfScopeReviewCovered: boolean;
    activeScannerHandoffCovered: boolean;
    rateAndCapControlsRecorded: boolean;
    findingDedupeConfidenceCovered: boolean;
    falsePositiveTuningCovered: boolean;
    rawProbeExchangesPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export interface InterceptedRequest {
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

export interface InterceptDecision {
  id: string;
  action: 'forward' | 'drop';
  rawRequest?: string;
}

export interface ProxyInterceptEvidencePackage {
  kind: 'proxyforge-proxy-intercept-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  exchangeCount: number;
  requestForwardedCount: number;
  requestEditedCount: number;
  requestDroppedCount: number;
  responseForwardedCount: number;
  responseEditedCount: number;
  responseDroppedCount: number;
  matchReplaceCount: number;
  paths: string[];
  decisions: Array<{
    exchangeId: string;
    direction: 'request' | 'response';
    action: 'forward' | 'drop';
    edited: boolean;
    path: string;
    status: number;
    tags: string[];
  }>;
  requirements: {
    requestForwardCovered: boolean;
    requestEditCovered: boolean;
    requestDropCovered: boolean;
    responseForwardCovered: boolean;
    responseEditCovered: boolean;
    responseDropCovered: boolean;
    matchReplaceCovered: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export interface MatchReplaceRule {
  id: string;
  name: string;
  enabled: boolean;
  direction: 'request' | 'response' | 'both';
  match: string;
  replace: string;
  isRegex: boolean;
  caseSensitive: boolean;
}

export interface ProxyMatchReplaceRuleLibraryPackage {
  kind: 'proxyforge-proxy-match-replace-rule-library';
  schemaVersion: 1;
  generatedAt: string;
  ruleCount: number;
  enabledRuleCount: number;
  directionCounts: Record<'request' | 'response' | 'both', number>;
  regexRuleCount: number;
  caseSensitiveRuleCount: number;
  largeRuleSet: {
    threshold: number;
    exceeded: boolean;
    totalRules: number;
  };
  appliedRuleTags: string[];
  sampleMatches: Array<{
    ruleId: string;
    ruleName: string;
    exchangeId: string;
    direction: 'request' | 'response';
    beforeSnippet: string;
    afterSnippet: string;
  }>;
  rules: MatchReplaceRule[];
  warnings: string[];
  requirements: {
    importExportCovered: boolean;
    requestRewriteCovered: boolean;
    responseRewriteCovered: boolean;
    largeRuleSetCovered: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export interface WebSocketMessage {
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

export interface WebSocketCaptureEvidencePackage {
  kind: 'proxyforge-websocket-capture-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  upgradeExchangeIds: string[];
  connectionCount: number;
  frameCount: number;
  clientFrameCount: number;
  serverFrameCount: number;
  textFrameCount: number;
  binaryFrameCount: number;
  controlFrameCount: number;
  totalPayloadBytes: number;
  hostCounts: Record<string, number>;
  pathCounts: Record<string, number>;
  connectionSummaries: Array<{
    connectionId: string;
    host: string;
    path: string;
    url: string;
    firstFrameId: string;
    lastFrameId: string;
    frameCount: number;
    clientFrameCount: number;
    serverFrameCount: number;
    typeCounts: Record<string, number>;
    totalPayloadBytes: number;
    fullPayloadSamples: Array<{
      id: string;
      direction: WebSocketMessage['direction'];
      type: WebSocketMessage['type'];
      payload: string;
      payloadEncoding?: WebSocketMessage['payloadEncoding'];
      length: number;
      tags: string[];
    }>;
    operationalSecretSignals: string[];
  }>;
  sampleFrames: Array<Pick<WebSocketMessage, 'id' | 'connectionId' | 'direction' | 'host' | 'path' | 'url' | 'opcode' | 'type' | 'payload' | 'payloadEncoding' | 'length' | 'tags'>>;
  operationalSecretSignals: string[];
  requirements: {
    upgradeCaptureCovered: boolean;
    bidirectionalFramesCovered: boolean;
    textAndBinaryFramesCovered: boolean;
    payloadBytesAccounted: boolean;
    connectionGroupingCovered: boolean;
    fullFidelityPayloadsPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export interface WebSocketCaptureEvidenceOptions {
  generatedAt?: string;
  exchanges?: HttpExchange[];
}

export interface WebSocketSavedReplayEvidence {
  id: string;
  name: string;
  connectionId: string;
  direction: WebSocketMessage['direction'];
  host: string;
  path: string;
  url: string;
  opcode: number;
  type: WebSocketMessage['type'];
  payload: string;
  payloadEncoding?: WebSocketMessage['payloadEncoding'];
  createdAt?: string;
  tags: string[];
}

export interface WebSocketInterceptReplayEvidencePackage {
  kind: 'proxyforge-websocket-intercept-rewrite-replay-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  frameCount: number;
  interceptedFrameCount: number;
  editedFrameCount: number;
  droppedFrameCount: number;
  replayedFrameCount: number;
  rewrittenFrameCount: number;
  savedReplayCount: number;
  rewriteRuleCount: number;
  activeRewriteRuleCount: number;
  directionCounts: Record<string, number>;
  actionCounts: Record<string, number>;
  decisions: Array<{
    frameId: string;
    connectionId: string;
    direction: WebSocketMessage['direction'];
    action: 'forward' | 'drop' | 'replay';
    edited: boolean;
    replayed: boolean;
    rewritten: boolean;
    type: WebSocketMessage['type'];
    payload: string;
    payloadEncoding?: WebSocketMessage['payloadEncoding'];
    length: number;
    tags: string[];
  }>;
  rewriteRules: WebSocketFrameRewriteRule[];
  savedReplays: WebSocketSavedReplayEvidence[];
  fullPayloadSamples: Array<{
    source: 'decision' | 'saved-replay';
    id: string;
    direction: WebSocketMessage['direction'];
    payload: string;
    payloadEncoding?: WebSocketMessage['payloadEncoding'];
    tags: string[];
  }>;
  operationalSecretSignals: string[];
  requirements: {
    clientInterceptCovered: boolean;
    serverInterceptCovered: boolean;
    editForwardCovered: boolean;
    dropCovered: boolean;
    liveReplayCovered: boolean;
    savedReplayCovered: boolean;
    rewriteRulesCovered: boolean;
    rewrittenReplayCovered: boolean;
    fullFidelityPayloadsPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export interface WebSocketInterceptReplayEvidenceOptions {
  generatedAt?: string;
  rewriteRules?: WebSocketFrameRewriteRule[];
  savedReplays?: WebSocketSavedReplayEvidence[];
}

export interface WebSocketStateGraphNodeEvidence {
  id: string;
  label: string;
  kind: 'baseline' | 'observed' | 'privileged' | 'close';
  count: number;
  frameIds: string[];
}

export interface WebSocketStateGraphEdgeEvidence {
  id: string;
  from: string;
  to: string;
  label: string;
  kind: 'baseline' | 'added' | 'missing' | 'privileged';
  count: number;
  frameIds: string[];
}

export interface WebSocketStateGraphEvidence {
  id: string;
  connectionId: string;
  host: string;
  path: string;
  nodes: WebSocketStateGraphNodeEvidence[];
  edges: WebSocketStateGraphEdgeEvidence[];
  totalNodeCount: number;
  totalEdgeCount: number;
  truncatedNodeCount: number;
  truncatedEdgeCount: number;
  summary: string;
}

export interface WebSocketStateGraphExportEvidence {
  id: string;
  title: string;
  fileName: string;
  filePath: string;
  createdAt: string;
  graphId: string;
  connectionId: string;
  host: string;
  path: string;
  format: 'png' | 'svg';
  nodeCount: number;
  edgeCount: number;
  totalNodeCount?: number;
  totalEdgeCount?: number;
  truncatedNodeCount?: number;
  truncatedEdgeCount?: number;
  frameCount: number;
  sizeBytes: number;
  content?: string;
}

export interface WebSocketConnectionClusterEvidence {
  id: string;
  createdAt: string;
  title: string;
  severity: Severity;
  confidence: 'certain' | 'firm' | 'tentative';
  hosts: string[];
  paths: string[];
  connectionIds: string[];
  frameIds: string[];
  connectionCount: number;
  frameCount: number;
  clientFrames: number;
  serverFrames: number;
  binaryFrames: number;
  replayFrames: number;
  rewrittenFrames: number;
  closeFrames: number;
  privilegedHints: string[];
  sharedStates: string[];
  summary: string;
  recommendation: string;
}

export interface WebSocketTranscriptEvidence {
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

export interface WebSocketRestoredTranscriptFrameEvidence extends WebSocketMessage {
  transcriptId: string;
  originalFrameId?: string;
  restoredAt: string;
  sourceFormat: WebSocketTranscriptEvidence['format'];
}

export interface WebSocketStateTranscriptEvidencePackage {
  kind: 'proxyforge-websocket-state-transcript-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  graphCount: number;
  graphExportCount: number;
  clusterCount: number;
  transcriptExportCount: number;
  restoredFrameCount: number;
  largeTranscriptFrameCount: number;
  filtersApplied: string[];
  stateGraphSummaries: Array<{
    graphId: string;
    connectionId: string;
    host: string;
    path: string;
    nodeCount: number;
    edgeCount: number;
    totalNodeCount: number;
    totalEdgeCount: number;
    truncatedNodeCount: number;
    truncatedEdgeCount: number;
    privilegedNodeCount: number;
    closeNodeCount: number;
    privilegedEdgeCount: number;
    summary: string;
  }>;
  graphExports: WebSocketStateGraphExportEvidence[];
  connectionClusters: WebSocketConnectionClusterEvidence[];
  transcriptExports: WebSocketTranscriptEvidence[];
  restoredFrames: WebSocketRestoredTranscriptFrameEvidence[];
  fullPayloadSamples: Array<{
    source: 'transcript' | 'restored-frame';
    id: string;
    payload: string;
    payloadEncoding?: WebSocketMessage['payloadEncoding'];
    tags: string[];
  }>;
  operationalSecretSignals: string[];
  requirements: {
    stateGraphCovered: boolean;
    graphFilterCovered: boolean;
    graphExportCovered: boolean;
    truncationMetadataCovered: boolean;
    connectionClusteringCovered: boolean;
    transcriptJsonExportCovered: boolean;
    transcriptMarkdownExportCovered: boolean;
    transcriptImportRestoreCovered: boolean;
    largeTranscriptRestoreCovered: boolean;
    fullFidelityPayloadsPreserved: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export interface WebSocketStateTranscriptEvidenceOptions {
  generatedAt?: string;
  graphs?: WebSocketStateGraphEvidence[];
  graphExports?: WebSocketStateGraphExportEvidence[];
  clusters?: WebSocketConnectionClusterEvidence[];
  transcripts?: WebSocketTranscriptEvidence[];
  restoredFrames?: WebSocketRestoredTranscriptFrameEvidence[];
  filtersApplied?: string[];
  largeTranscriptFrameThreshold?: number;
}

export interface WebSocketInterceptStatus {
  enabled: boolean;
  clientEnabled?: boolean;
  serverEnabled?: boolean;
  pendingCount: number;
  message: string;
}

export interface WebSocketInterceptSettings {
  enabled: boolean;
  clientEnabled: boolean;
  serverEnabled: boolean;
}

export interface WebSocketFrameDecision {
  id: string;
  action: 'forward' | 'drop';
  payload?: string;
  payloadEncoding?: 'text' | 'hex' | 'base64';
  opcode?: number;
}

export interface WebSocketReplayRequest {
  connectionId: string;
  direction: 'client' | 'server';
  payload: string;
  payloadEncoding?: 'text' | 'hex' | 'base64';
  opcode?: number;
}

export interface WebSocketFrameRewriteRule {
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

interface PendingIntercept {
  request: InterceptedRequest;
  resolve: (decision: InterceptDecision) => void;
}

interface PendingWebSocketIntercept {
  frame: WebSocketMessage;
  resolve: (decision: WebSocketFrameDecision) => void;
}

interface ActiveWebSocketConnection {
  target: URL;
  protocolTag: string;
  clientSocket: net.Socket;
  upstreamSocket: net.Socket;
}

type ExchangeSink = (exchange: HttpExchange) => void;
type InterceptSink = (pending: InterceptedRequest[]) => void;
type WebSocketSink = (message: WebSocketMessage) => void;
type WebSocketInterceptSink = (pending: WebSocketMessage[]) => void;
export type UpstreamTlsMode = 'strict' | 'relaxed';

export interface UpstreamProxyConfig {
  enabled?: boolean;
  url?: string;
  authorization?: string;
  noProxy?: string[];
}

export interface UpstreamProxyStatus {
  enabled: boolean;
  url?: string;
  noProxy: string[];
  message: string;
}

interface NormalizedUpstreamProxyConfig {
  url: URL;
  authorization?: string;
  noProxy: string[];
}

export interface HttpsMitmEvidenceOptions {
  generatedAt?: string;
  certificate?: {
    ready?: boolean;
    projectId?: string;
    fingerprintSha256?: string;
    validUntil?: string;
    hostCertificateCount?: number;
    rootCertificatePath?: string;
  };
  trustMode?: 'project-ca' | 'browser-trust-store' | 'ignore-errors-flag' | 'unknown';
}

export interface HttpsMitmEvidencePackage {
  kind: 'proxyforge-https-mitm-evidence-package';
  schemaVersion: 1;
  generatedAt: string;
  exchangeCount: number;
  capturedHttpsExchangeCount: number;
  mitmTunnelCount: number;
  strictUpstreamFailureCount: number;
  hosts: string[];
  paths: string[];
  certificate: {
    ready: boolean;
    projectId?: string;
    fingerprintSha256?: string;
    validUntil?: string;
    hostCertificateCount: number;
    rootCertificatePath?: string;
    trustMode: 'project-ca' | 'browser-trust-store' | 'ignore-errors-flag' | 'unknown';
  };
  modes: {
    relaxedCaptured: boolean;
    strictFailureCaptured: boolean;
    inspectionTunnelCaptured: boolean;
  };
  requirements: {
    projectCaGenerated: boolean;
    hostCertificateReused: boolean;
    decryptedTrafficCaptured: boolean;
    strictUpstreamFailureCaptured: boolean;
  };
  samples: Array<Pick<HttpExchange, 'id' | 'method' | 'url' | 'status' | 'notes' | 'requestRaw' | 'responseRaw' | 'tags'>>;
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

export interface ProxyHttpListenerCapturePackage {
  kind: 'proxyforge-proxy-http-listener-capture-package';
  schemaVersion: 1;
  generatedAt: string;
  exchangeCount: number;
  proxyExchangeCount: number;
  methodCounts: Record<string, number>;
  statusFamilies: Record<'2xx' | '3xx' | '4xx' | '5xx' | 'other', number>;
  hosts: string[];
  paths: string[];
  bodyCaptureCount: number;
  rawRequestBytes: number;
  rawResponseBytes: number;
  operationalSecretSignals: string[];
  samples: Array<Pick<HttpExchange, 'id' | 'method' | 'url' | 'status' | 'mime' | 'notes' | 'requestRaw' | 'responseRaw' | 'tags'>>;
  requirements: {
    loopbackProxyListenerCovered: boolean;
    historyRowsCaptured: boolean;
    multiMethodCaptureCovered: boolean;
    requestBodyCaptureCovered: boolean;
    responseBodyCaptureCovered: boolean;
    fullFidelityRawCovered: boolean;
    operationalSecretsPreserved: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  summary: string;
  content: string;
}

const MAX_CAPTURE_BYTES = 256 * 1024;

export class ProxyEngine {
  private server: http.Server | null = null;
  private readonly mitmServer: http.Server;
  private port = 8080;
  private running = false;
  private httpsInspectionEnabled = true;
  private upstreamTlsMode: UpstreamTlsMode = 'strict';
  private upstreamProxy: NormalizedUpstreamProxyConfig | null = null;
  private interceptEnabled = false;
  private responseInterceptEnabled = false;
  private webSocketInterceptSettings: WebSocketInterceptSettings = {
    enabled: false,
    clientEnabled: true,
    serverEnabled: true,
  };
  private matchReplaceRules: MatchReplaceRule[] = [];
  private webSocketFrameRewriteRules: WebSocketFrameRewriteRule[] = [];
  private readonly pendingIntercepts = new Map<string, PendingIntercept>();
  private readonly pendingWebSocketIntercepts = new Map<string, PendingWebSocketIntercept>();
  private readonly activeSockets = new Set<net.Socket>();
  private readonly activeWebSockets = new Map<string, ActiveWebSocketConnection>();

  constructor(
    private readonly sink: ExchangeSink,
    private readonly caManager: CertificateAuthorityManager,
    private readonly interceptSink: InterceptSink = () => undefined,
    private readonly webSocketSink: WebSocketSink = () => undefined,
    private readonly webSocketInterceptSink: WebSocketInterceptSink = () => undefined,
  ) {
    this.mitmServer = http.createServer((request, response) => {
      const target = (request.socket as net.Socket & { proxyForgeTarget?: { host: string; port: number } }).proxyForgeTarget;
      const host = request.headers.host ?? target?.host;
      const path = request.url ?? '/';
      const targetUrl = new URL(/^https?:\/\//i.test(path) ? path : `https://${host}${path}`);
      this.handleHttpRequest(request, response, targetUrl, 'Captured by HTTPS inspection').catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        response.writeHead(502, { 'content-type': 'text/plain' });
        response.end(`ProxyForge HTTPS inspection error: ${message}`);
      });
    });
    this.mitmServer.on('upgrade', (request, socket, head) => {
      const target = (request.socket as net.Socket & { proxyForgeTarget?: { host: string; port: number } }).proxyForgeTarget;
      const host = request.headers.host ?? target?.host;
      const path = request.url ?? '/';
      const targetUrl = new URL(/^wss?:\/\//i.test(path) ? path : `wss://${host}${path}`);
      this.handleWebSocketUpgrade(request, socket as net.Socket, head, targetUrl).catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        socket.end(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nProxyForge WebSocket inspection error: ${message}`);
      });
    });
  }

  async start(port = 8080): Promise<ProxyStatus> {
    if (this.running && this.server) {
      return this.status(`Proxy already listening on ${this.port}`);
    }

    this.port = port;
    this.server = http.createServer((request, response) => {
      this.handleHttpRequest(request, response).catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        response.writeHead(502, { 'content-type': 'text/plain' });
        response.end(`ProxyForge upstream error: ${message}`);
      });
    });

    this.server.on('connect', (request, clientSocket, head) => {
      this.handleConnect(request, clientSocket as net.Socket, head);
    });
    this.server.on('upgrade', (request, socket, head) => {
      const targetUrl = resolveWebSocketTargetUrl(request);
      this.handleWebSocketUpgrade(request, socket as net.Socket, head, targetUrl).catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        socket.end(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nProxyForge WebSocket proxy error: ${message}`);
      });
    });

    await new Promise<void>((resolve, reject) => {
      this.server?.once('error', reject);
      this.server?.listen(port, '127.0.0.1', () => resolve());
    });

    this.running = true;
    return this.status(`Proxy listening on 127.0.0.1:${this.port}`);
  }

  async stop(): Promise<ProxyStatus> {
    for (const pending of this.pendingWebSocketIntercepts.values()) {
      pending.resolve({ id: pending.frame.id, action: 'drop' });
    }
    this.pendingWebSocketIntercepts.clear();
    this.emitWebSocketIntercepts();

    for (const socket of this.activeSockets) {
      socket.destroy();
    }
    this.activeSockets.clear();
    this.activeWebSockets.clear();

    if (!this.server) {
      this.running = false;
      return this.status('Proxy stopped');
    }

    await new Promise<void>((resolve, reject) => {
      this.server?.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });

    this.server = null;
    this.running = false;
    return this.status('Proxy stopped');
  }

  status(message = this.running ? `Proxy listening on 127.0.0.1:${this.port}` : 'Proxy stopped'): ProxyStatus {
    return {
      running: this.running,
      port: this.port,
      mode: 'electron',
      message,
    };
  }

  setHttpsInspection(enabled: boolean) {
    this.httpsInspectionEnabled = enabled;
    return {
      enabled: this.httpsInspectionEnabled,
      upstreamTlsMode: this.upstreamTlsMode,
      message: this.httpsInspectionMessage(),
    };
  }

  httpsInspectionStatus() {
    return {
      enabled: this.httpsInspectionEnabled,
      upstreamTlsMode: this.upstreamTlsMode,
      upstreamProxy: this.upstreamProxyStatus(),
      message: this.httpsInspectionMessage(),
    };
  }

  setUpstreamTlsValidation(mode: UpstreamTlsMode) {
    this.upstreamTlsMode = mode === 'strict' ? 'strict' : 'relaxed';
    return this.httpsInspectionStatus();
  }

  getUpstreamTlsValidation(): UpstreamTlsMode {
    return this.upstreamTlsMode;
  }

  setUpstreamProxy(config?: UpstreamProxyConfig | null): UpstreamProxyStatus {
    this.upstreamProxy = normalizeUpstreamProxyConfig(config);
    return this.upstreamProxyStatus();
  }

  upstreamProxyStatus(): UpstreamProxyStatus {
    if (!this.upstreamProxy) {
      return {
        enabled: false,
        noProxy: [],
        message: 'Upstream proxy chaining disabled',
      };
    }

    return {
      enabled: true,
      url: this.upstreamProxy.url.toString(),
      noProxy: this.upstreamProxy.noProxy,
      message: `Upstream proxy chaining through ${this.upstreamProxy.url.host}`,
    };
  }

  setIntercept(enabled: boolean) {
    this.interceptEnabled = enabled;
    return this.interceptStatus(enabled ? 'Intercept enabled; requests will pause before upstream forwarding' : 'Intercept disabled');
  }

  setResponseIntercept(enabled: boolean) {
    this.responseInterceptEnabled = enabled;
    return this.interceptStatus(enabled ? 'Response intercept enabled; upstream responses will pause before client delivery' : 'Response intercept disabled');
  }

  interceptStatus(message = this.interceptStatusMessage()) {
    return {
      enabled: this.interceptEnabled,
      responseEnabled: this.responseInterceptEnabled,
      pendingCount: this.pendingIntercepts.size,
      message,
    };
  }

  listIntercepts() {
    return this.pendingInterceptList();
  }

  resolveIntercept(decision: InterceptDecision) {
    const pending = this.pendingIntercepts.get(decision.id);
    if (!pending) {
      return this.interceptStatus(`No pending intercepted request for ${decision.id}`);
    }

    this.pendingIntercepts.delete(decision.id);
    pending.resolve(decision);
    this.emitIntercepts();
    const target = pending.request.direction === 'response' ? `response ${pending.request.status ?? ''} ${pending.request.path}` : `${pending.request.method} ${pending.request.path}`;
    return this.interceptStatus(`${decision.action === 'drop' ? 'Dropped' : 'Forwarded'} ${target}`);
  }

  setWebSocketIntercept(settings: boolean | WebSocketInterceptSettings) {
    const next = typeof settings === 'boolean'
      ? { ...this.webSocketInterceptSettings, enabled: settings, clientEnabled: true, serverEnabled: true }
      : {
          enabled: settings.enabled,
          clientEnabled: settings.clientEnabled,
          serverEnabled: settings.serverEnabled,
        };
    this.webSocketInterceptSettings = next;
    return this.webSocketInterceptStatus(next.enabled ? this.webSocketInterceptStatusMessage() : 'WebSocket intercept disabled');
  }

  webSocketInterceptStatus(message = this.webSocketInterceptStatusMessage()): WebSocketInterceptStatus {
    return {
      enabled: this.webSocketInterceptSettings.enabled,
      clientEnabled: this.webSocketInterceptSettings.clientEnabled,
      serverEnabled: this.webSocketInterceptSettings.serverEnabled,
      pendingCount: this.pendingWebSocketIntercepts.size,
      message,
    };
  }

  listWebSocketIntercepts() {
    return this.pendingWebSocketInterceptList();
  }

  resolveWebSocketIntercept(decision: WebSocketFrameDecision) {
    const pending = this.pendingWebSocketIntercepts.get(decision.id);
    if (!pending) {
      return this.webSocketInterceptStatus(`No pending WebSocket frame for ${decision.id}`);
    }

    this.pendingWebSocketIntercepts.delete(decision.id);
    pending.resolve(decision);
    this.emitWebSocketIntercepts();
    return this.webSocketInterceptStatus(`${decision.action === 'drop' ? 'Dropped' : 'Forwarded'} WebSocket ${pending.frame.type} frame`);
  }

  replayWebSocketFrame(request: WebSocketReplayRequest): WebSocketMessage {
    const connection = this.activeWebSockets.get(request.connectionId);
    const opcode = request.opcode ?? 1;
    const payload = editableWebSocketPayloadToBuffer(request.payload, request.payloadEncoding);

    if (!connection) {
      const message = {
        id: `wsm-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        connectionId: request.connectionId,
        time: new Date().toLocaleTimeString([], { hour12: false }),
        direction: request.direction,
        host: 'closed connection',
        path: '-',
        url: request.connectionId,
        opcode,
        type: webSocketOpcodeType(opcode),
        payload: request.payload,
        length: payload.length,
        tags: ['websocket', 'replay-failed', 'closed-connection'],
      } satisfies WebSocketMessage;
      this.webSocketSink(message);
      return message;
    }

    const replayFrame = this.applyWebSocketFrameRewriteRules({
      opcode,
      payload,
      rawFrame: encodeWebSocketFrame(payload, opcode, request.direction === 'client'),
    }, request.direction);
    if (request.direction === 'client') {
      connection.upstreamSocket.write(replayFrame.frame.rawFrame);
    } else {
      connection.clientSocket.write(replayFrame.frame.rawFrame);
    }

    return this.emitWebSocketMessage(
      request.connectionId,
      connection.target,
      replayFrame.frame,
      request.direction,
      connection.protocolTag,
      ['replayed', ...replayFrame.applied.map((rule) => `rewrite:${rule}`), ...(replayFrame.applied.length ? ['rewritten'] : [])],
    );
  }

  getMatchReplaceRules() {
    return this.matchReplaceRules;
  }

  setMatchReplaceRules(rules: MatchReplaceRule[]) {
    this.matchReplaceRules = sanitizeMatchReplaceRules(rules);
    return this.matchReplaceRules;
  }

  getWebSocketFrameRewriteRules() {
    return this.webSocketFrameRewriteRules;
  }

  setWebSocketFrameRewriteRules(rules: WebSocketFrameRewriteRule[]) {
    this.webSocketFrameRewriteRules = sanitizeWebSocketFrameRewriteRules(rules);
    return this.webSocketFrameRewriteRules;
  }

  async replay(request: ReplayRequest): Promise<HttpExchange> {
    const startedAt = Date.now();
    const settings = normalizeReplayTransportSettings(request.settings);
    const sessionApplication = applySessionProfileToRawRequest(request.rawRequest, request.sessionProfile, request.sessionOptions);
    const effectiveRawRequest = sessionApplication.rawRequest;
    const sessionTags = sessionApplication.trace.applied ? ['session-profile'] : [];
    const sessionNote = sessionApplication.trace.applied
      ? `; session ${sessionApplication.trace.profileName ?? sessionApplication.trace.profileId ?? 'profile'} ${sessionApplication.trace.mode} ${sessionApplication.trace.target}`
      : '';
    const oastPayloadTags = replayOastPayloadTags(effectiveRawRequest, request.oastPayloads);
    const oastNote = oastPayloadTags.length ? `; OAST ${oastPayloadTags.filter((tag) => tag.startsWith('callback-payload:')).length} payload(s)` : '';

    const send = (target: URL, redirectsFollowed: number): Promise<HttpExchange> => new Promise((resolve) => {
      const parsed = parseRawRequest(effectiveRawRequest, target, redirectsFollowed > 0);

      if (!isAllowedHost(target.hostname, request.scopeAllowlist)) {
        resolve({
          id: `replay-${Date.now()}-${Math.random().toString(16).slice(2)}`,
          method: parsed.method,
          host: target.host,
          path: `${target.pathname}${target.search}`,
          url: target.toString(),
          status: 0,
          length: 0,
          mime: 'blocked',
          risk: 'info',
          timing: Date.now() - startedAt,
          notes: `Replay blocked by project scope: ${target.hostname}${sessionNote}${oastNote}`,
          source: 'repeater',
          time: new Date().toLocaleTimeString([], { hour12: false }),
          requestRaw: effectiveRawRequest,
          responseRaw: 'ProxyForge scope gate blocked this replay before network traffic was sent.',
          tags: ['replayed', 'blocked-by-scope', ...sessionTags, ...oastPayloadTags],
        });
        return;
      }

      if (settings.connectionMode !== 'default') parsed.headers.connection = settings.connectionMode;
      const transport = target.protocol === 'https:' ? https : http;
      const upstreamRequest = transport.request(
        {
          protocol: target.protocol,
          hostname: target.hostname,
          port: target.port || (target.protocol === 'https:' ? 443 : 80),
          method: parsed.method,
          path: parsed.path,
          headers: parsed.headers,
          ...(target.protocol === 'https:' ? { rejectUnauthorized: this.upstreamTlsMode === 'strict' } : {}),
        },
        (upstreamResponse) => {
          const responseChunks: Buffer[] = [];
          upstreamResponse.on('data', (chunk: Buffer) => {
            if (totalLength(responseChunks) < MAX_CAPTURE_BYTES) responseChunks.push(chunk);
          });
          upstreamResponse.on('end', () => {
            const captured = Buffer.concat(responseChunks);
            const location = upstreamResponse.headers.location;
            const status = upstreamResponse.statusCode ?? 0;
            if (
              settings.redirectMode === 'follow'
              && redirectsFollowed < settings.maxRedirects
              && status >= 300
              && status < 400
              && typeof location === 'string'
            ) {
              send(new URL(location, target), redirectsFollowed + 1).then(resolve);
              return;
            }
            resolve({
              id: `replay-${Date.now()}-${Math.random().toString(16).slice(2)}`,
              method: parsed.method,
              host: target.host,
              path: parsed.path,
              url: target.toString(),
              status,
              length: Number(upstreamResponse.headers['content-length'] ?? captured.length),
              mime: contentType(upstreamResponse.headers['content-type']),
              risk: passiveRisk(upstreamResponse.headers),
              timing: Date.now() - startedAt,
              notes: `Replayed from Repeater; redirects ${settings.redirectMode}${redirectsFollowed ? ` (${redirectsFollowed} followed)` : ''}; connection ${settings.connectionMode}; upstream TLS ${this.upstreamTlsMode}${sessionNote}${oastNote}`,
              source: 'repeater',
              time: new Date().toLocaleTimeString([], { hour12: false }),
              requestRaw: effectiveRawRequest,
              responseRaw: renderResponse(upstreamResponse, captured),
              tags: ['replayed', target.protocol.replace(':', ''), `redirect:${settings.redirectMode}`, `connection:${settings.connectionMode}`, ...sessionTags, ...oastPayloadTags],
            });
          });
        },
      );

      upstreamRequest.setTimeout(settings.timeoutMs, () => {
        upstreamRequest.destroy(new Error(`Replay timed out after ${settings.timeoutMs} ms`));
      });

      upstreamRequest.on('error', (error) => {
        resolve({
          id: `replay-${Date.now()}-${Math.random().toString(16).slice(2)}`,
          method: parsed.method,
          host: target.host,
          path: parsed.path,
          url: target.toString(),
          status: 0,
          length: 0,
          mime: 'error',
          risk: 'info',
          timing: Date.now() - startedAt,
          notes: `Replay error: ${error.message}${sessionNote}${oastNote}`,
          source: 'repeater',
          time: new Date().toLocaleTimeString([], { hour12: false }),
          requestRaw: effectiveRawRequest,
          responseRaw: `ProxyForge replay error\n\n${error.message}`,
          tags: ['replayed', 'network-error', ...sessionTags, ...oastPayloadTags],
        });
      });

      if (parsed.body.length > 0) upstreamRequest.write(parsed.body);
      upstreamRequest.end();
    });

    return send(new URL(request.targetUrl), 0);
  }

  async runIntruderAttack(request: IntruderAttackRequest): Promise<IntruderAttackSummary> {
    const startedAt = new Date();
    const target = new URL(request.targetUrl);
    const attackMode = sanitizeIntruderAttackMode(request.attackMode);
    const payloadRules = sanitizeIntruderPayloadRules(request.payloadRules);
    const sessionApplication = applySessionProfileToRawRequest(request.rawRequest, request.sessionProfile, request.sessionOptions);
    const effectiveRawRequest = sessionApplication.rawRequest;
    const payloadPlans = buildIntruderPayloadPlans(effectiveRawRequest, { ...request, rawRequest: effectiveRawRequest, payloadRules }, attackMode);
    const startOffset = clampIntruderOffset(request.startOffset, payloadPlans.length);
    const maxPayloadRequests = request.maxPayloadRequests === undefined
      ? payloadPlans.length
      : Math.min(Math.max(Math.round(request.maxPayloadRequests), 1), INTRUDER_MAX_PAYLOAD_REQUESTS);
    const selectedPayloadPlans = payloadPlans.slice(startOffset, startOffset + maxPayloadRequests);
    const nextOffset = Math.min(payloadPlans.length, startOffset + selectedPayloadPlans.length);
    const hasMore = nextOffset < payloadPlans.length;
    const payloadPositions = countIntruderMarkers(effectiveRawRequest);
    const throttleMs = Math.min(Math.max(request.throttleMs, 0), 5000);
    const grepTerms = request.grepTerms.map((term) => term.trim()).filter(Boolean);
    const extractRegexes = request.extractRegexes?.map((term) => term.trim()).filter(Boolean).slice(0, 12) ?? [];
    const oastPayloads = sanitizeIntruderOastPayloads(request.oastPayloads);
    const resourcePoolMaxConcurrent = Math.min(Math.max(Math.round(request.resourcePoolMaxConcurrent ?? 1), 1), 10);
    const resourcePoolName = request.resourcePoolName?.trim() || 'Default sequential pool';
    const streamChunkSize = sanitizeIntruderStreamChunkSize(request.streamChunkSize, selectedPayloadPlans.length);
    const resultWindowSize = sanitizeIntruderResultWindowSize(request.resultWindowSize, selectedPayloadPlans.length);
    const memoryBudgetBytes = sanitizeIntruderMemoryBudgetBytes(request.memoryBudgetBytes);
    const results: IntruderAttackResult[] = [];
    let completedChunks = 0;
    let droppedResultCount = 0;
    let retainedMemoryBytes = 0;
    let sentRequestCount = 0;
    let inFlight = 0;
    let maxInFlight = 0;
    const runStartedAt = Date.now();

    if (payloadPlans.length === 0) {
      return {
        id: `intruder-${startedAt.getTime()}-${Math.random().toString(16).slice(2)}`,
        targetUrl: target.toString(),
        startedAt: startedAt.toISOString(),
        completedAt: new Date().toISOString(),
        attackMode,
        payloadPositions,
        totalRequests: 0,
        blocked: true,
        message: 'Intruder attack blocked: no payloads supplied',
        results,
        startOffset,
        nextOffset: startOffset,
        hasMore: false,
        payloadPlanCount: payloadPlans.length,
        payloadRuleCount: payloadRules.length,
        resourcePoolName,
        resourcePoolMaxConcurrent,
        oast: buildIntruderOastSummary(oastPayloads, [], []),
        streaming: buildIntruderStreamingSummary({
          selectedRequestCount: 0,
          streamChunkSize,
          completedChunks: 0,
          resultWindowSize,
          retainedResultCount: 0,
          droppedResultCount: 0,
          startOffset,
          sentRequestCount: 0,
          estimatedMemoryBytes: 0,
          memoryBudgetBytes,
        }),
      };
    }

    if (!isAllowedHost(target.hostname, request.scopeAllowlist)) {
      return {
        id: `intruder-${startedAt.getTime()}-${Math.random().toString(16).slice(2)}`,
        targetUrl: target.toString(),
        startedAt: startedAt.toISOString(),
        completedAt: new Date().toISOString(),
        attackMode,
        payloadPositions,
        totalRequests: 0,
        blocked: true,
        message: `Intruder attack blocked by project scope: ${target.hostname}`,
        results,
        startOffset,
        nextOffset: startOffset,
        hasMore: false,
        payloadPlanCount: payloadPlans.length,
        payloadRuleCount: payloadRules.length,
        resourcePoolName,
        resourcePoolMaxConcurrent,
        oast: buildIntruderOastSummary(oastPayloads, [], []),
        streaming: buildIntruderStreamingSummary({
          selectedRequestCount: 0,
          streamChunkSize,
          completedChunks: 0,
          resultWindowSize,
          retainedResultCount: 0,
          droppedResultCount: 0,
          startOffset,
          sentRequestCount: 0,
          estimatedMemoryBytes: 0,
          memoryBudgetBytes,
        }),
      };
    }

    for (let chunkStart = 0; chunkStart < selectedPayloadPlans.length; chunkStart += Math.max(streamChunkSize, 1)) {
      const chunk = selectedPayloadPlans.slice(chunkStart, chunkStart + Math.max(streamChunkSize, 1));
      for (let waveStart = 0; waveStart < chunk.length; waveStart += resourcePoolMaxConcurrent) {
        if (sentRequestCount > 0 && throttleMs > 0) await delay(throttleMs);
        const wave = chunk.slice(waveStart, waveStart + resourcePoolMaxConcurrent);
        const waveResults = await Promise.all(wave.map(async (plan, waveIndex) => {
          const index = chunkStart + waveStart + waveIndex;
          inFlight += 1;
          maxInFlight = Math.max(maxInFlight, inFlight);
          try {
            const exchange = await this.replay({
              rawRequest: plan.rawRequest,
              targetUrl: target.toString(),
              scopeAllowlist: request.scopeAllowlist,
              sessionProfile: request.sessionProfile,
              sessionOptions: request.sessionOptions,
            });
            const responseHaystack = `${exchange.responseRaw}\n${exchange.requestRaw}`.toLowerCase();
            const grepMatches = grepTerms.filter((term) => responseHaystack.includes(term.toLowerCase()));
            const extractMatches = extractIntruderMatches(`${exchange.responseRaw}\n${exchange.requestRaw}`, extractRegexes);
            const oastPayloadIds = matchIntruderOastPayloads(plan.rawRequest, oastPayloads).map((payload) => payload.id);
            const result: IntruderAttackResult = {
              id: `intruder-result-${Date.now()}-${index}-${Math.random().toString(16).slice(2)}`,
              payload: plan.label,
              payloads: plan.payloads,
              attackMode,
              status: exchange.status,
              length: exchange.length,
              mime: exchange.mime,
              timing: exchange.timing,
              grepMatches,
              extractMatches,
              notes: `${exchange.notes}; resource pool ${resourcePoolName} (${resourcePoolMaxConcurrent} slot${resourcePoolMaxConcurrent === 1 ? '' : 's'}); payload offset ${startOffset + index + 1}/${payloadPlans.length}`,
              requestRaw: plan.rawRequest,
              responseRaw: exchange.responseRaw,
              tags: ['intruder', attackMode, ...exchange.tags, sessionApplication.trace.applied ? 'session-profile' : '', `pool:${resourcePoolName}`, ...payloadRules.map((rule) => `payload-rule:${rule}`), grepMatches.length > 0 ? 'grep-match' : 'no-grep-match', extractMatches.length > 0 ? 'extract-match' : 'no-extract-match', oastPayloadIds.length > 0 ? 'oast-payload' : '']
                .filter((tag) => tag && !tag.startsWith('no-')),
              oastPayloadIds,
              callbackInteractionIds: [],
            };
            return { index, result };
          } finally {
            inFlight = Math.max(0, inFlight - 1);
          }
        }));

        for (const { result } of waveResults.sort((left, right) => left.index - right.index)) {
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
      }
      completedChunks += 1;
    }
    const durationMs = Math.max(1, Date.now() - runStartedAt);

    return {
      id: `intruder-${startedAt.getTime()}-${Math.random().toString(16).slice(2)}`,
      targetUrl: target.toString(),
      startedAt: startedAt.toISOString(),
      completedAt: new Date().toISOString(),
      attackMode,
      payloadPositions,
      totalRequests: sentRequestCount,
      blocked: false,
      message: hasMore
        ? `Intruder ${attackMode} checkpoint paused: ${sentRequestCount} of ${payloadPlans.length} payload request${payloadPlans.length === 1 ? '' : 's'} sent at ${throttleMs} ms throttle; resume at offset ${nextOffset}`
        : `Intruder ${attackMode} complete: ${sentRequestCount} payload request${sentRequestCount === 1 ? '' : 's'} sent at ${throttleMs} ms throttle`,
      results,
      startOffset,
      nextOffset,
      hasMore,
      payloadPlanCount: payloadPlans.length,
      payloadRuleCount: payloadRules.length,
      resourcePoolName,
      resourcePoolMaxConcurrent,
      oast: buildIntruderOastSummary(oastPayloads, [], results),
      streaming: buildIntruderStreamingSummary({
        selectedRequestCount: selectedPayloadPlans.length,
        streamChunkSize,
        completedChunks,
        resultWindowSize,
        retainedResultCount: results.length,
        droppedResultCount,
        startOffset,
        sentRequestCount,
        estimatedMemoryBytes: retainedMemoryBytes,
        memoryBudgetBytes,
        maxConcurrency: resourcePoolMaxConcurrent,
        maxInFlight,
        durationMs,
      }),
    };
  }

  async runActiveScan(request: ActiveScanRequest): Promise<ActiveScanSummary> {
    const startedAt = new Date();
    const target = new URL(request.targetUrl);
    const checks = sanitizeActiveScanChecks(request.checks);
    const throttleMs = Math.min(Math.max(request.throttleMs, 0), 5000);
    const maxRequests = Math.min(Math.max(request.maxRequests, 1), 25);
    const sessionApplication = applySessionProfileToRawRequest(request.rawRequest, request.sessionProfile, request.sessionOptions);
    const effectiveRawRequest = sessionApplication.rawRequest;
    const findings: ActiveScanFinding[] = [];
    const exchanges: HttpExchange[] = [];

    if (checks.length === 0) {
      return activeScanSummary(request, startedAt, true, 'Active scan blocked: no checks selected', findings, exchanges);
    }

    if (!isAllowedHost(target.hostname, request.scopeAllowlist)) {
      return activeScanSummary(request, startedAt, true, `Active scan blocked by project scope: ${target.hostname}`, findings, exchanges);
    }

    const selectedChecks = checks.slice(0, maxRequests);
    for (const [index, check] of selectedChecks.entries()) {
      if (index > 0 && throttleMs > 0) await delay(throttleMs);
      if (check === 'authz-diff') {
        const baseline = await this.replay({
          rawRequest: effectiveRawRequest,
          targetUrl: target.toString(),
          scopeAllowlist: request.scopeAllowlist,
          sessionProfile: request.sessionProfile,
          sessionOptions: request.sessionOptions,
        });
        const downgraded = await this.replay({
          rawRequest: mutateActiveScanRequest(effectiveRawRequest, target, check, request),
          targetUrl: target.toString(),
          scopeAllowlist: request.scopeAllowlist,
        });
        const baselineExchange = {
          ...baseline,
          id: `scan-${Date.now()}-${index}-auth-base-${Math.random().toString(16).slice(2)}`,
          source: 'scanner' as const,
          notes: 'Active scanner auth state baseline probe',
          tags: Array.from(new Set([...baseline.tags, 'active-scan', 'check:authz-diff', 'auth-state:baseline'])),
        };
        const downgradedExchange = {
          ...downgraded,
          id: `scan-${Date.now()}-${index}-auth-low-${Math.random().toString(16).slice(2)}`,
          source: 'scanner' as const,
          notes: 'Active scanner auth state low-privilege comparison probe',
          tags: Array.from(new Set([...downgraded.tags, 'active-scan', 'check:authz-diff', 'auth-state:low-privilege'])),
        };
        exchanges.push(baselineExchange, downgradedExchange);
        findings.push(...buildAuthStateFindings(baselineExchange, downgradedExchange));
        continue;
      }
      const rawRequest = mutateActiveScanRequest(effectiveRawRequest, target, check, request);
      const exchange = await this.replay({
        rawRequest,
        targetUrl: target.toString(),
        scopeAllowlist: request.scopeAllowlist,
        sessionProfile: request.sessionProfile,
        sessionOptions: request.sessionOptions,
      });
      const scannerExchange = {
        ...exchange,
        id: `scan-${Date.now()}-${index}-${Math.random().toString(16).slice(2)}`,
        source: 'scanner' as const,
        notes: `Active scanner ${activeScanCheckLabel(check)} probe`,
        tags: Array.from(new Set([...exchange.tags, 'active-scan', `check:${check}`])),
      };
      exchanges.push(scannerExchange);
      findings.push(...buildActiveScanFindings(check, scannerExchange));
    }

    const tuned = tuneActiveScanFindings(findings, exchanges);
    return activeScanSummary(
      request,
      startedAt,
      false,
      `Active scan complete: ${exchanges.length} scoped probe${exchanges.length === 1 ? '' : 's'}, ${tuned.findings.length} finding${tuned.findings.length === 1 ? '' : 's'}, ${tuned.suppressedFindings.length} suppressed noisy signal${tuned.suppressedFindings.length === 1 ? '' : 's'}`,
      tuned.findings,
      exchanges,
      tuned.suppressedFindings,
      tuned.tuning,
    );
  }

  async runCrawlAudit(request: CrawlAuditRequest): Promise<CrawlAuditSummary> {
    const startedAt = new Date();
    const checks = sanitizeActiveScanChecks(request.checks);
    const throttleMs = Math.min(Math.max(request.throttleMs, 0), 5000);
    const maxInsertionPoints = Math.min(Math.max(request.maxInsertionPoints, 1), 50);
    const findings: ActiveScanFinding[] = [];
    const suppressedFindings: ActiveScanSuppressedFinding[] = [];
    const exchanges: HttpExchange[] = [];
    let dedupedFindingCount = 0;

    if (checks.length === 0) {
      return crawlAuditSummary(request, startedAt, true, 'Crawl insertion audit blocked: no checks selected', findings, exchanges, 0);
    }

    const scopedInsertionPoints = uniqueInsertionPoints(request.insertionPoints)
      .filter((point) => {
        const target = safeParseUrl(point.url);
        return Boolean(target && isAllowedHost(target.hostname, request.scopeAllowlist));
      })
      .slice(0, maxInsertionPoints);

    if (scopedInsertionPoints.length === 0) {
      return crawlAuditSummary(request, startedAt, true, 'Crawl insertion audit blocked: no in-scope insertion points', findings, exchanges, 0);
    }

    for (const [pointIndex, point] of scopedInsertionPoints.entries()) {
      if (pointIndex > 0 && throttleMs > 0) await delay(throttleMs);
      const target = new URL(point.url);
      const rawRequest = renderInsertionPointRequest(point, target, request.sessionHeaders);
      const summary = await this.runActiveScan({
        rawRequest,
        targetUrl: target.toString(),
        scopeAllowlist: request.scopeAllowlist,
        checks,
        throttleMs: 0,
        maxRequests: checks.length,
      });
      dedupedFindingCount += summary.tuning.dedupedFindingCount;

      const exchangeIdMap = new Map<string, string>();
      for (const exchange of summary.exchanges) {
        const nextExchange = {
          ...exchange,
          id: `crawl-audit-${Date.now()}-${pointIndex}-${Math.random().toString(16).slice(2)}`,
          notes: `Crawl insertion audit ${point.type}:${point.name} ${exchange.notes}`,
          tags: Array.from(new Set([...exchange.tags, 'crawl-audit', `insertion:${point.type}`, `insertion-name:${point.name}`])),
        };
        exchangeIdMap.set(exchange.id, nextExchange.id);
        exchanges.push(nextExchange);
      }

      for (const finding of summary.findings) {
        findings.push({
          ...finding,
          id: `crawl-audit-finding-${Date.now()}-${pointIndex}-${Math.random().toString(16).slice(2)}`,
          detail: `${finding.detail} Crawler insertion point: ${point.type} "${point.name}" from ${point.evidence}.`,
          evidenceExchangeId: finding.evidenceExchangeId ? exchangeIdMap.get(finding.evidenceExchangeId) : undefined,
        });
      }

      for (const finding of summary.suppressedFindings) {
        suppressedFindings.push({
          ...finding,
          id: `crawl-audit-suppressed-${Date.now()}-${pointIndex}-${Math.random().toString(16).slice(2)}`,
          evidenceExchangeId: finding.evidenceExchangeId ? exchangeIdMap.get(finding.evidenceExchangeId) : undefined,
        });
      }
    }

    return crawlAuditSummary(
      request,
      startedAt,
      false,
      `Crawl insertion audit complete: ${scopedInsertionPoints.length} insertion point${scopedInsertionPoints.length === 1 ? '' : 's'}, ${exchanges.length} probe${exchanges.length === 1 ? '' : 's'}, ${findings.length} finding${findings.length === 1 ? '' : 's'}, ${suppressedFindings.length} suppressed noisy signal${suppressedFindings.length === 1 ? '' : 's'}`,
      findings,
      exchanges,
      scopedInsertionPoints.length,
      suppressedFindings,
      defaultActiveScanTuning(findings, suppressedFindings, dedupedFindingCount),
    );
  }

  private async handleHttpRequest(
    clientRequest: http.IncomingMessage,
    clientResponse: http.ServerResponse,
    explicitTarget?: URL,
    captureNote = 'Captured by local proxy listener',
  ) {
    const startedAt = Date.now();
    const requestBody = await readBody(clientRequest);
    const target = explicitTarget ?? resolveTargetUrl(clientRequest);
    const protocolTag = target.protocol.replace(':', '');
    const originalRequestRaw = renderRequest(clientRequest, target, requestBody);
    const requestRuleResult = this.applyMatchReplaceRules(originalRequestRaw, 'request');
    let requestRaw = requestRuleResult.raw;
    let parsedRequest = {
      method: clientRequest.method ?? 'GET',
      path: `${target.pathname}${target.search}`,
      headers: normalizeProxyHeaders(clientRequest.headers, target),
      body: requestBody,
    };

    if (requestRaw !== originalRequestRaw) {
      parsedRequest = parseRawRequest(requestRaw, target);
    }

    const decision = await this.interceptRequest({
      method: parsedRequest.method,
      host: target.host,
      path: parsedRequest.path,
      url: target.toString(),
      rawRequest: requestRaw,
      source: target.protocol === 'https:' ? 'https' : 'http',
      tags: ['intercepted', protocolTag, ...requestRuleResult.applied.map((name) => `rule:${name}`)],
    });

    if (decision.action === 'drop') {
      clientResponse.writeHead(444, { 'content-type': 'text/plain' });
      clientResponse.end('ProxyForge dropped this intercepted request before upstream forwarding.');
      this.sink({
        id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        method: parsedRequest.method,
        host: target.host,
        path: parsedRequest.path,
        url: target.toString(),
        status: 444,
        length: 0,
        mime: 'dropped',
        risk: 'info',
        timing: Date.now() - startedAt,
        notes: 'Dropped by intercept',
        source: 'proxy',
        time: new Date().toLocaleTimeString([], { hour12: false }),
        requestRaw,
        responseRaw: 'ProxyForge dropped this intercepted request before upstream forwarding.',
        tags: ['intercepted', 'dropped', protocolTag],
      });
      return;
    }

    if (decision.rawRequest && decision.rawRequest !== requestRaw) {
      requestRaw = decision.rawRequest;
      parsedRequest = parseRawRequest(decision.rawRequest, target);
    }

    const upstreamProxy = this.upstreamProxyForTarget(target);
    const transport = upstreamProxy ? upstreamProxyTransport(upstreamProxy) : target.protocol === 'https:' ? https : http;
    const requestOptions = upstreamProxy
      ? upstreamProxyHttpRequestOptions(target, parsedRequest, upstreamProxy)
      : {
          protocol: target.protocol,
          hostname: target.hostname,
          port: target.port || (target.protocol === 'https:' ? 443 : 80),
          method: parsedRequest.method,
          path: parsedRequest.path,
          headers: parsedRequest.headers,
          ...(target.protocol === 'https:' ? { rejectUnauthorized: this.upstreamTlsMode === 'strict' } : {}),
        };
    const proxyChainTags = upstreamProxy ? ['proxy-chain', `upstream-proxy:${upstreamProxy.url.host}`] : [];
    const proxyChainNote = upstreamProxy ? `; upstream proxy ${upstreamProxy.url.host}` : '';

    const upstreamRequest = transport.request(
      requestOptions,
      (upstreamResponse) => {
        const requestEdited = requestRaw !== originalRequestRaw || (decision.rawRequest && decision.rawRequest !== requestRaw);
        const canStreamResponse = !this.responseInterceptEnabled && !hasActiveResponseRules(this.matchReplaceRules);
        if (canStreamResponse) {
          let totalResponseBytes = 0;
          const capturedChunks: Buffer[] = [];
          clientResponse.writeHead(upstreamResponse.statusCode ?? 0, upstreamResponse.statusMessage, upstreamResponse.headers);

          upstreamResponse.on('data', (chunk: Buffer) => {
            totalResponseBytes += chunk.length;
            const remainingCaptureBytes = Math.max(0, MAX_CAPTURE_BYTES - totalLength(capturedChunks));
            if (remainingCaptureBytes > 0) {
              capturedChunks.push(remainingCaptureBytes >= chunk.length ? chunk : chunk.subarray(0, remainingCaptureBytes));
            }
            clientResponse.write(chunk);
          });

          upstreamResponse.on('end', () => {
            clientResponse.end();
            const captured = Buffer.concat(capturedChunks);
            const captureTruncated = totalResponseBytes > captured.length;
            this.sink({
              id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
              method: parsedRequest.method,
              host: target.host,
              path: parsedRequest.path,
              url: target.toString(),
              status: upstreamResponse.statusCode ?? 0,
              length: Number(upstreamResponse.headers['content-length'] ?? totalResponseBytes),
              mime: contentType(upstreamResponse.headers['content-type']),
              risk: passiveRisk(upstreamResponse.headers),
              timing: Date.now() - startedAt,
              notes: `${captureNote}; streamed response capture; upstream TLS ${this.upstreamTlsMode}${proxyChainNote}${captureTruncated ? `; body capture truncated to ${captured.length}/${totalResponseBytes} bytes` : ''}`,
              source: 'proxy',
              time: new Date().toLocaleTimeString([], { hour12: false }),
              requestRaw: upstreamProxy ? renderUpstreamProxyRequest(requestRaw, target, upstreamProxy) : requestRaw,
              responseRaw: renderResponse(upstreamResponse, captured),
              tags: [
                'captured',
                protocolTag,
                'streamed-response',
                isChunkedResponse(upstreamResponse) ? 'chunked-response' : '',
                captureTruncated ? 'capture-truncated' : '',
                ...proxyChainTags,
                requestEdited ? 'edited' : 'forwarded',
              ].filter(Boolean),
            });
          });
          return;
        }

        const responseChunks: Buffer[] = [];

        upstreamResponse.on('data', (chunk: Buffer) => {
          responseChunks.push(chunk);
        });

        upstreamResponse.on('end', async () => {
          const captured = Buffer.concat(responseChunks);
          const originalResponseRaw = renderResponse(upstreamResponse, captured);
          const responseRuleResult = this.applyMatchReplaceRules(originalResponseRaw, 'response');
          const responseDecision = await this.interceptResponse({
            method: parsedRequest.method,
            host: target.host,
            path: parsedRequest.path,
            url: target.toString(),
            status: upstreamResponse.statusCode ?? 0,
            rawRequest: responseRuleResult.raw,
            source: target.protocol === 'https:' ? 'https' : 'http',
            tags: ['intercepted', 'response', protocolTag, ...responseRuleResult.applied.map((name) => `rule:${name}`)],
          });

          if (responseDecision.action === 'drop') {
            const droppedBody = 'ProxyForge dropped this intercepted response before client delivery.';
            clientResponse.writeHead(444, { 'content-type': 'text/plain', 'content-length': Buffer.byteLength(droppedBody) });
            clientResponse.end(droppedBody);
            this.sink({
              id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
              method: parsedRequest.method,
              host: target.host,
              path: parsedRequest.path,
              url: target.toString(),
              status: 444,
              length: 0,
              mime: 'dropped',
              risk: 'info',
              timing: Date.now() - startedAt,
              notes: 'Dropped by response intercept',
              source: 'proxy',
              time: new Date().toLocaleTimeString([], { hour12: false }),
              requestRaw,
              responseRaw: droppedBody,
              tags: [
                'captured',
                'intercepted',
                'response-dropped',
                protocolTag,
                requestEdited ? 'edited' : 'forwarded',
                requestRuleResult.applied.length > 0 || responseRuleResult.applied.length > 0 ? 'match-replace' : 'no-rule',
              ].filter((tag) => tag !== 'no-rule'),
            });
            return;
          }

          const responseRaw = responseDecision.rawRequest ?? responseRuleResult.raw;
          const responseEdited = responseRaw !== originalResponseRaw;
          const parsedResponse = parseRawResponse(responseRaw, responseEdited);
          clientResponse.writeHead(parsedResponse.statusCode, parsedResponse.statusMessage, parsedResponse.headers);
          clientResponse.end(parsedResponse.body);
          const exchange: HttpExchange = {
            id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
            method: parsedRequest.method,
            host: target.host,
            path: parsedRequest.path,
            url: target.toString(),
            status: parsedResponse.statusCode,
            length: Number(parsedResponse.headers['content-length'] ?? parsedResponse.body.length),
            mime: contentType(parsedResponse.headers['content-type']),
            risk: passiveRisk(parsedResponse.headers),
            timing: Date.now() - startedAt,
            notes: `${captureNote}; upstream TLS ${this.upstreamTlsMode}${proxyChainNote}`,
            source: 'proxy',
            time: new Date().toLocaleTimeString([], { hour12: false }),
            requestRaw: upstreamProxy ? renderUpstreamProxyRequest(requestRaw, target, upstreamProxy) : requestRaw,
            responseRaw,
            tags: [
              'captured',
              protocolTag,
              ...proxyChainTags,
              requestEdited ? 'edited' : 'forwarded',
              responseEdited ? 'response-edited' : 'response-forwarded',
              requestRuleResult.applied.length > 0 || responseRuleResult.applied.length > 0 ? 'match-replace' : 'no-rule',
              ...requestRuleResult.applied.map((name) => `request-rule:${name}`),
              ...responseRuleResult.applied.map((name) => `response-rule:${name}`),
            ].filter((tag) => tag !== 'no-rule'),
          };
          this.sink(exchange);
        });
      },
    );

    upstreamRequest.on('error', (error) => {
      const errorBody = `ProxyForge upstream error: ${error.message}`;
      clientResponse.writeHead(502, { 'content-type': 'text/plain', 'content-length': Buffer.byteLength(errorBody) });
      clientResponse.end(errorBody);
      this.sink({
        id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        method: parsedRequest.method,
        host: target.host,
        path: parsedRequest.path,
        url: target.toString(),
        status: 502,
        length: Buffer.byteLength(errorBody),
        mime: 'text/plain',
        risk: 'low',
        timing: Date.now() - startedAt,
        notes: `${captureNote}; upstream TLS ${this.upstreamTlsMode}${proxyChainNote}; upstream error ${error.message}`,
        source: 'proxy',
        time: new Date().toLocaleTimeString([], { hour12: false }),
        requestRaw: upstreamProxy ? renderUpstreamProxyRequest(requestRaw, target, upstreamProxy) : requestRaw,
        responseRaw: renderSyntheticHttpResponse(502, 'Bad Gateway', errorBody, { 'content-type': 'text/plain' }),
        tags: [
          'captured',
          protocolTag,
          ...proxyChainTags,
          'upstream-error',
          this.upstreamTlsMode === 'strict' ? 'strict-upstream-tls' : 'relaxed-upstream-tls',
        ],
      });
    });

    if (parsedRequest.body.length > 0) upstreamRequest.write(parsedRequest.body);
    upstreamRequest.end();
  }

  private handleConnect(request: http.IncomingMessage, clientSocket: net.Socket, head: Buffer) {
    const startedAt = Date.now();
    const [host, rawPort] = (request.url ?? '').split(':');
    const port = Number(rawPort) || 443;
    if (this.httpsInspectionEnabled) {
      this.handleMitmConnect(request, clientSocket, head, host, port, startedAt).catch((error: unknown) => {
        const message = error instanceof Error ? error.message : String(error);
        clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nProxyForge HTTPS inspection error: ${message}`);
      });
      return;
    }

    const upstreamProxy = this.upstreamProxyForHost(host, port);
    if (upstreamProxy) {
      this.handleChainedConnect(request, clientSocket, head, host, port, startedAt, upstreamProxy);
      return;
    }

    let tunnelEstablished = false;
    const upstreamSocket = net.connect(port, host, () => {
      tunnelEstablished = true;
      let clientToServerBytes = head.length;
      let serverToClientBytes = 0;
      let finalized = false;
      const connectionEstablishedAt = Date.now();
      const onClientData = (chunk: Buffer) => {
        clientToServerBytes += chunk.length;
      };
      const onUpstreamData = (chunk: Buffer) => {
        serverToClientBytes += chunk.length;
      };
      const finalizeTunnel = (reason: string) => {
        if (finalized) return;
        finalized = true;
        const durationMs = Date.now() - connectionEstablishedAt;
        const totalBytes = clientToServerBytes + serverToClientBytes;
        clientSocket.off('data', onClientData);
        upstreamSocket.off('data', onUpstreamData);
        this.sink({
          id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
          method: 'CONNECT',
          host: `${host}:${port}`,
          path: `${host}:${port}`,
          url: `https://${host}`,
          status: 200,
          length: totalBytes,
          mime: 'tunnel',
          risk: 'info',
          timing: Date.now() - startedAt,
          notes: `CONNECT tunnel metadata captured with pass-through byte accounting. clientToServerBytes=${clientToServerBytes}; serverToClientBytes=${serverToClientBytes}; totalTunnelBytes=${totalBytes}; tunnelDurationMs=${durationMs}; closeReason=${reason}. HTTPS body inspection requires local CA support.`,
          source: 'proxy',
          time: new Date().toLocaleTimeString([], { hour12: false }),
          requestRaw: `CONNECT ${host}:${port} HTTP/1.1\nHost: ${host}:${port}\n\n`,
          responseRaw: [
            'HTTP/1.1 200 Connection Established',
            `ProxyForge-Tunnel-Client-Bytes: ${clientToServerBytes}`,
            `ProxyForge-Tunnel-Server-Bytes: ${serverToClientBytes}`,
            `ProxyForge-Tunnel-Total-Bytes: ${totalBytes}`,
            `ProxyForge-Tunnel-Duration-Ms: ${durationMs}`,
            '',
            '',
          ].join('\n'),
          tags: ['tunnel', 'https', 'byte-accounting', reason === 'client-close' ? 'client-closed' : 'upstream-closed'],
        });
      };
      clientSocket.on('data', onClientData);
      upstreamSocket.on('data', onUpstreamData);
      clientSocket.once('close', () => finalizeTunnel('client-close'));
      upstreamSocket.once('close', () => finalizeTunnel('upstream-close'));
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head.length > 0) upstreamSocket.write(head);
      upstreamSocket.pipe(clientSocket);
      clientSocket.pipe(upstreamSocket);
    });

    upstreamSocket.on('error', (error) => {
      if (tunnelEstablished) {
        clientSocket.destroy();
        return;
      }
      const errorBody = `ProxyForge CONNECT tunnel error: ${error.message}`;
      clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(errorBody)}\r\n\r\n${errorBody}`);
      this.sink({
        id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        method: 'CONNECT',
        host: `${host}:${port}`,
        path: `${host}:${port}`,
        url: `https://${host}`,
        status: 502,
        length: Buffer.byteLength(errorBody),
        mime: 'text/plain',
        risk: 'low',
        timing: Date.now() - startedAt,
        notes: `CONNECT tunnel failed while HTTPS inspection was disabled: ${error.message}`,
        source: 'proxy',
        time: new Date().toLocaleTimeString([], { hour12: false }),
        requestRaw: `CONNECT ${host}:${port} HTTP/1.1\nHost: ${host}:${port}\n\n`,
        responseRaw: renderSyntheticHttpResponse(502, 'Bad Gateway', errorBody, { 'content-type': 'text/plain' }),
        tags: ['tunnel', 'https', 'upstream-error'],
      });
    });
  }

  private handleChainedConnect(
    request: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer,
    host: string,
    port: number,
    startedAt: number,
    upstreamProxy: NormalizedUpstreamProxyConfig,
  ) {
    let upstreamSocket: net.Socket | null = null;
    let finalized = false;
    let clientToServerBytes = head.length;
    let serverToClientBytes = 0;
    let connectionEstablishedAt = 0;
    const proxyConnectRequest = renderUpstreamProxyConnectRequest(host, port, upstreamProxy);

    const failTunnel = (error: Error) => {
      if (finalized) return;
      finalized = true;
      upstreamSocket?.destroy();
      const errorBody = `ProxyForge CONNECT tunnel error through upstream proxy ${upstreamProxy.url.host}: ${error.message}`;
      clientSocket.end(`HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nContent-Length: ${Buffer.byteLength(errorBody)}\r\n\r\n${errorBody}`);
      this.sink({
        id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        method: 'CONNECT',
        host: `${host}:${port}`,
        path: `${host}:${port}`,
        url: `https://${host}`,
        status: 502,
        length: Buffer.byteLength(errorBody),
        mime: 'text/plain',
        risk: 'low',
        timing: Date.now() - startedAt,
        notes: `CONNECT tunnel failed through upstream proxy ${upstreamProxy.url.host}: ${error.message}`,
        source: 'proxy',
        time: new Date().toLocaleTimeString([], { hour12: false }),
        requestRaw: proxyConnectRequest.replace(/\r\n/g, '\n'),
        responseRaw: renderSyntheticHttpResponse(502, 'Bad Gateway', errorBody, { 'content-type': 'text/plain' }),
        tags: ['tunnel', 'https', 'proxy-chain', `upstream-proxy:${upstreamProxy.url.host}`, 'upstream-error'],
      });
    };

    const finalizeTunnel = (reason: string) => {
      if (finalized) return;
      finalized = true;
      const durationMs = connectionEstablishedAt ? Date.now() - connectionEstablishedAt : 0;
      const totalBytes = clientToServerBytes + serverToClientBytes;
      this.sink({
        id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
        method: 'CONNECT',
        host: `${host}:${port}`,
        path: `${host}:${port}`,
        url: `https://${host}`,
        status: 200,
        length: totalBytes,
        mime: 'tunnel',
        risk: 'info',
        timing: Date.now() - startedAt,
        notes: `CONNECT tunnel metadata captured through upstream proxy ${upstreamProxy.url.host} with pass-through byte accounting. clientToServerBytes=${clientToServerBytes}; serverToClientBytes=${serverToClientBytes}; totalTunnelBytes=${totalBytes}; tunnelDurationMs=${durationMs}; closeReason=${reason}. HTTPS body inspection requires local CA support.`,
        source: 'proxy',
        time: new Date().toLocaleTimeString([], { hour12: false }),
        requestRaw: proxyConnectRequest.replace(/\r\n/g, '\n'),
        responseRaw: [
          'HTTP/1.1 200 Connection Established',
          `ProxyForge-Upstream-Proxy: ${upstreamProxy.url.host}`,
          `ProxyForge-Tunnel-Client-Bytes: ${clientToServerBytes}`,
          `ProxyForge-Tunnel-Server-Bytes: ${serverToClientBytes}`,
          `ProxyForge-Tunnel-Total-Bytes: ${totalBytes}`,
          `ProxyForge-Tunnel-Duration-Ms: ${durationMs}`,
          '',
          '',
        ].join('\n'),
        tags: ['tunnel', 'https', 'byte-accounting', 'proxy-chain', `upstream-proxy:${upstreamProxy.url.host}`, reason === 'client-close' ? 'client-closed' : 'upstream-closed'],
      });
    };

    connectToUpstreamProxy(upstreamProxy, this.upstreamTlsMode).then((socket) => {
      upstreamSocket = socket;
      this.trackSocket(socket);
      let proxyResponseBuffer = Buffer.alloc(0);
      let tunnelEstablished = false;
      const cleanupHandshake = () => {
        socket.off('data', onProxyData);
        socket.off('error', onProxyError);
      };
      const onProxyError = (error: Error) => {
        cleanupHandshake();
        if (tunnelEstablished) {
          clientSocket.destroy();
        } else {
          failTunnel(error);
        }
      };
      const onProxyData = (chunk: Buffer) => {
        proxyResponseBuffer = Buffer.concat([proxyResponseBuffer, chunk]);
        const headerEnd = proxyResponseBuffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) return;

        cleanupHandshake();
        const responseHead = proxyResponseBuffer.subarray(0, headerEnd + 4).toString('utf8');
        const rest = proxyResponseBuffer.subarray(headerEnd + 4);
        const status = Number(/^HTTP\/\d(?:\.\d)?\s+(\d+)/i.exec(responseHead)?.[1] ?? 0);
        if (status < 200 || status >= 300) {
          failTunnel(new Error(`upstream proxy CONNECT returned ${status || 'unknown status'}`));
          return;
        }

        tunnelEstablished = true;
        connectionEstablishedAt = Date.now();
        clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (head.length > 0) socket.write(head);
        if (rest.length > 0) {
          serverToClientBytes += rest.length;
          clientSocket.write(rest);
        }

        clientSocket.on('data', (data) => {
          clientToServerBytes += data.length;
        });
        socket.on('data', (data) => {
          serverToClientBytes += data.length;
        });
        clientSocket.once('close', () => finalizeTunnel('client-close'));
        socket.once('close', () => finalizeTunnel('upstream-close'));
        socket.on('error', () => clientSocket.destroy());
        clientSocket.on('error', () => socket.destroy());
        socket.pipe(clientSocket);
        clientSocket.pipe(socket);
      };

      socket.on('data', onProxyData);
      socket.once('error', onProxyError);
      socket.write(proxyConnectRequest);
    }).catch((error: Error) => {
      failTunnel(error);
    });
  }

  private upstreamProxyForTarget(target: URL) {
    if (!this.upstreamProxy || target.protocol !== 'http:') return null;
    if (isUpstreamProxyBypassed(target.hostname, target.host, this.upstreamProxy.noProxy)) return null;
    return this.upstreamProxy;
  }

  private upstreamProxyForHost(host: string, port: number) {
    if (!this.upstreamProxy) return null;
    if (isUpstreamProxyBypassed(host, `${host}:${port}`, this.upstreamProxy.noProxy)) return null;
    return this.upstreamProxy;
  }

  private async handleWebSocketUpgrade(
    clientRequest: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer,
    target: URL,
  ) {
    const startedAt = Date.now();
    const connectionId = `ws-${startedAt}-${Math.random().toString(16).slice(2)}`;
    const protocolTag = target.protocol.replace(':', '');
    const upstreamSocket = await connectWebSocketUpstream(target, this.upstreamTlsMode);
    this.trackSocket(clientSocket);
    this.trackSocket(upstreamSocket);
    this.activeWebSockets.set(connectionId, {
      target,
      protocolTag,
      clientSocket,
      upstreamSocket,
    });

    let clientFrameQueue = Promise.resolve();
    let serverFrameQueue = Promise.resolve();
    const closeBoth = () => {
      clientSocket.destroy();
      upstreamSocket.destroy();
    };
    const clientRouter = new WebSocketFrameRouter((frame) => {
      clientFrameQueue = clientFrameQueue
        .then(() => this.processWebSocketFrame(connectionId, target, frame, 'client', protocolTag, upstreamSocket))
        .catch(closeBoth);
    });
    const serverRouter = new WebSocketFrameRouter((frame) => {
      serverFrameQueue = serverFrameQueue
        .then(() => this.processWebSocketFrame(connectionId, target, frame, 'server', protocolTag, clientSocket))
        .catch(closeBoth);
    });
    const forwardClientData = (chunk: Buffer) => {
      clientRouter.push(chunk);
    };
    const forwardServerData = (chunk: Buffer) => {
      serverRouter.push(chunk);
    };

    await new Promise<void>((resolve, reject) => {
      let buffer = Buffer.alloc(0);
      let settled = false;
      const cleanup = () => {
        upstreamSocket.off('data', onData);
        upstreamSocket.off('error', onError);
      };
      const onError = (error: Error) => {
        if (!settled) {
          settled = true;
          cleanup();
          reject(error);
        }
      };
      const onData = (chunk: Buffer) => {
        buffer = Buffer.concat([buffer, chunk]);
        const headerEnd = buffer.indexOf('\r\n\r\n');
        if (headerEnd === -1) return;

        settled = true;
        cleanup();
        const responseHead = buffer.subarray(0, headerEnd + 4);
        const rest = buffer.subarray(headerEnd + 4);
        clientSocket.on('data', forwardClientData);
        upstreamSocket.on('data', forwardServerData);
        clientSocket.resume();
        upstreamSocket.resume();
        clientSocket.write(responseHead);
        if (rest.length > 0) {
          serverRouter.push(rest);
        }
        resolve();
      };

      upstreamSocket.on('data', onData);
      upstreamSocket.on('error', onError);
      upstreamSocket.write(renderWebSocketRequest(clientRequest, target));
      if (head.length > 0) {
        clientRouter.push(head);
      }
    });

    const cleanupConnection = () => {
      this.activeWebSockets.delete(connectionId);
    };
    clientSocket.on('error', closeBoth);
    upstreamSocket.on('error', closeBoth);
    clientSocket.on('close', () => {
      cleanupConnection();
      upstreamSocket.destroy();
    });
    upstreamSocket.on('close', () => {
      cleanupConnection();
      clientSocket.destroy();
    });

    this.sink({
      id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      method: 'WEBSOCKET',
      host: target.host,
      path: `${target.pathname}${target.search}`,
      url: target.toString(),
      status: 101,
      length: 0,
      mime: 'websocket',
      risk: 'info',
      timing: Date.now() - startedAt,
      notes: 'WebSocket upgrade tunneled with bidirectional frame history capture and optional frame intercept',
      source: 'proxy',
      time: new Date().toLocaleTimeString([], { hour12: false }),
      requestRaw: renderWebSocketRequest(clientRequest, target).replace(/\r\n/g, '\n'),
      responseRaw: 'HTTP/1.1 101 Switching Protocols\nUpgrade: websocket\nConnection: Upgrade\n\n',
      tags: ['websocket', protocolTag],
    });
  }

  private async processWebSocketFrame(
    connectionId: string,
    target: URL,
    frame: ParsedWebSocketFrame,
    direction: WebSocketMessage['direction'],
    protocolTag: string,
    destination: net.Socket,
  ) {
    const rewriteResult = this.applyWebSocketFrameRewriteRules(frame, direction);
    const workingFrame = rewriteResult.frame;
    const rewriteTags = rewriteResult.applied.map((rule) => `rewrite:${rule}`);

    if (!this.shouldInterceptWebSocketFrame(direction)) {
      destination.write(workingFrame.rawFrame);
      this.emitWebSocketMessage(connectionId, target, workingFrame, direction, protocolTag, [...rewriteTags, ...(rewriteResult.applied.length ? ['rewritten'] : []), 'forwarded']);
      return;
    }

    const pending = this.createWebSocketMessage(connectionId, target, workingFrame, direction, protocolTag, ['held', ...rewriteTags, ...(rewriteResult.applied.length ? ['rewritten'] : [])]);
    const decision = await this.queueWebSocketIntercept(pending);

    if (decision.action === 'drop') {
      this.webSocketSink({ ...pending, tags: [...pending.tags.filter((tag) => tag !== 'held'), 'dropped'] });
      return;
    }

    const opcode = decision.opcode ?? workingFrame.opcode;
    const payload = decision.payload === undefined
      ? workingFrame.payload
      : editableWebSocketPayloadToBuffer(decision.payload, decision.payloadEncoding);
    const edited = opcode !== workingFrame.opcode || !payload.equals(workingFrame.payload);
    const outbound = edited ? encodeWebSocketFrame(payload, opcode, direction === 'client') : workingFrame.rawFrame;
    destination.write(outbound);
    this.emitWebSocketMessage(
      connectionId,
      target,
      { opcode, payload, rawFrame: outbound },
      direction,
      protocolTag,
      [edited ? 'edited' : 'intercepted', 'forwarded'],
    );
  }

  private emitWebSocketMessage(
    connectionId: string,
    target: URL,
    frame: ParsedWebSocketFrame,
    direction: WebSocketMessage['direction'],
    protocolTag: string,
    extraTags: string[] = [],
  ) {
    const message = this.createWebSocketMessage(connectionId, target, frame, direction, protocolTag, extraTags);
    this.webSocketSink(message);
    return message;
  }

  private createWebSocketMessage(
    connectionId: string,
    target: URL,
    frame: ParsedWebSocketFrame,
    direction: WebSocketMessage['direction'],
    protocolTag: string,
    extraTags: string[] = [],
  ): WebSocketMessage {
    return {
      id: `wsm-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      connectionId,
      time: new Date().toLocaleTimeString([], { hour12: false }),
      direction,
      host: target.host,
      path: `${target.pathname}${target.search}`,
      url: target.toString(),
      opcode: frame.opcode,
      type: webSocketOpcodeType(frame.opcode),
      payload: webSocketPayloadPreview(frame),
      payloadEncoding: webSocketPayloadEncoding(frame),
      length: frame.payload.length,
      tags: ['websocket', protocolTag, direction, ...extraTags],
    };
  }

  private shouldInterceptWebSocketFrame(direction: WebSocketMessage['direction']) {
    if (!this.webSocketInterceptSettings.enabled) return false;
    return direction === 'client'
      ? this.webSocketInterceptSettings.clientEnabled
      : this.webSocketInterceptSettings.serverEnabled;
  }

  private async handleMitmConnect(
    request: http.IncomingMessage,
    clientSocket: net.Socket,
    head: Buffer,
    host: string,
    port: number,
    startedAt: number,
  ) {
    const secureContext = await this.caManager.secureContextForHost(host);
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');

    const tlsSocket = new tls.TLSSocket(clientSocket, {
      isServer: true,
      secureContext,
    }) as tls.TLSSocket & { proxyForgeTarget?: { host: string; port: number } };

    tlsSocket.proxyForgeTarget = { host, port };
    tlsSocket.on('error', () => undefined);
    if (head.length > 0) tlsSocket.unshift(head);
    this.mitmServer.emit('connection', tlsSocket);

    this.sink({
      id: `hx-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      method: 'CONNECT',
      host: `${host}:${port}`,
      path: `${host}:${port}`,
      url: `https://${host}`,
      status: 200,
      length: 0,
      mime: 'mitm-tunnel',
      risk: 'info',
      timing: Date.now() - startedAt,
      notes: 'CONNECT upgraded to HTTPS inspection. Install the ProxyForge root CA in the browser trust store.',
      source: 'proxy',
      time: new Date().toLocaleTimeString([], { hour12: false }),
      requestRaw: `CONNECT ${request.url ?? `${host}:${port}`} HTTP/${request.httpVersion}\nHost: ${host}:${port}\n\n`,
      responseRaw: 'HTTP/1.1 200 Connection Established\nProxyForge-Inspection: enabled\n\n',
      tags: ['tunnel', 'https', 'mitm'],
    });
  }

  private interceptRequest(request: Omit<InterceptedRequest, 'id' | 'time' | 'direction' | 'status'>): Promise<InterceptDecision> {
    if (!this.interceptEnabled) {
      return Promise.resolve({ id: '', action: 'forward', rawRequest: request.rawRequest });
    }

    return this.queueIntercept({ ...request, direction: 'request' });
  }

  private interceptResponse(response: Omit<InterceptedRequest, 'id' | 'time' | 'direction'>): Promise<InterceptDecision> {
    if (!this.responseInterceptEnabled) {
      return Promise.resolve({ id: '', action: 'forward', rawRequest: response.rawRequest });
    }

    return this.queueIntercept({ ...response, direction: 'response' });
  }

  private queueIntercept(request: Omit<InterceptedRequest, 'id' | 'time'>): Promise<InterceptDecision> {
    const intercepted: InterceptedRequest = {
      ...request,
      id: `int-${Date.now()}-${Math.random().toString(16).slice(2)}`,
      time: new Date().toLocaleTimeString([], { hour12: false }),
    };

    return new Promise((resolve) => {
      this.pendingIntercepts.set(intercepted.id, {
        request: intercepted,
        resolve: (decision) => resolve({ ...decision, rawRequest: decision.rawRequest ?? intercepted.rawRequest }),
      });
      this.emitIntercepts();
    });
  }

  private interceptStatusMessage() {
    if (this.interceptEnabled && this.responseInterceptEnabled) return 'Request and response intercept enabled';
    if (this.interceptEnabled) return 'Request intercept enabled';
    if (this.responseInterceptEnabled) return 'Response intercept enabled';
    return 'Intercept disabled';
  }

  private pendingInterceptList() {
    return Array.from(this.pendingIntercepts.values()).map((pending) => pending.request);
  }

  private emitIntercepts() {
    this.interceptSink(this.pendingInterceptList());
  }

  private queueWebSocketIntercept(frame: WebSocketMessage): Promise<WebSocketFrameDecision> {
    return new Promise((resolve) => {
      this.pendingWebSocketIntercepts.set(frame.id, {
        frame,
        resolve: (decision) => resolve({ ...decision, payload: decision.payload ?? frame.payload, opcode: decision.opcode ?? frame.opcode }),
      });
      this.emitWebSocketIntercepts();
    });
  }

  private webSocketInterceptStatusMessage() {
    if (!this.webSocketInterceptSettings.enabled) return 'WebSocket intercept disabled';
    if (this.webSocketInterceptSettings.clientEnabled && this.webSocketInterceptSettings.serverEnabled) {
      return 'WebSocket intercept enabled for client and server frames';
    }
    if (this.webSocketInterceptSettings.clientEnabled) return 'WebSocket intercept enabled for client frames';
    if (this.webSocketInterceptSettings.serverEnabled) return 'WebSocket intercept enabled for server frames';
    return 'WebSocket intercept enabled with no frame directions selected';
  }

  private httpsInspectionMessage() {
    const inspection = this.httpsInspectionEnabled ? 'HTTPS inspection enabled' : 'HTTPS inspection disabled; CONNECT tunnels pass through';
    const validation = this.upstreamTlsMode === 'strict'
      ? 'strict upstream certificate validation'
      : 'relaxed upstream certificate validation for lab and self-signed targets';
    return `${inspection}; ${validation}.`;
  }

  private pendingWebSocketInterceptList() {
    return Array.from(this.pendingWebSocketIntercepts.values()).map((pending) => pending.frame);
  }

  private emitWebSocketIntercepts() {
    this.webSocketInterceptSink(this.pendingWebSocketInterceptList());
  }

  private trackSocket(socket: net.Socket) {
    this.activeSockets.add(socket);
    socket.once('close', () => {
      this.activeSockets.delete(socket);
    });
  }

  private applyMatchReplaceRules(raw: string, direction: MatchReplaceRule['direction']) {
    let next = raw;
    const applied: string[] = [];

    for (const rule of this.matchReplaceRules) {
      if (!rule.enabled || !rule.match) continue;
      if (rule.direction !== 'both' && rule.direction !== direction) continue;

      const updated = applyMatchReplaceRule(next, rule);
      if (updated !== next) {
        next = updated;
        applied.push(rule.name || rule.id);
      }
    }

    return { raw: next, applied };
  }

  private applyWebSocketFrameRewriteRules(frame: ParsedWebSocketFrame, direction: WebSocketMessage['direction']) {
    let payloadText = frame.payload.toString('utf8');
    const frameType = webSocketOpcodeType(frame.opcode);
    const applied: string[] = [];

    for (const rule of this.webSocketFrameRewriteRules) {
      if (!rule.enabled || !rule.match) continue;
      if (rule.direction !== 'both' && rule.direction !== direction) continue;
      if (rule.frameType !== 'both' && rule.frameType !== frameType) continue;
      const updated = applyWebSocketFrameRewriteRule(payloadText, rule);
      if (updated !== payloadText) {
        payloadText = updated;
        applied.push(rule.name || rule.id);
      }
    }

    if (applied.length === 0) return { frame, applied };
    const payload = Buffer.from(payloadText, 'utf8');
    return {
      frame: {
        opcode: frame.opcode,
        payload,
        rawFrame: encodeWebSocketFrame(payload, frame.opcode, direction === 'client'),
      } satisfies ParsedWebSocketFrame,
      applied,
    };
  }
}

function resolveTargetUrl(request: http.IncomingMessage) {
  const requestUrl = request.url ?? '/';
  if (/^https?:\/\//i.test(requestUrl)) {
    return new URL(requestUrl);
  }

  const host = request.headers.host;
  if (!host) {
    throw new Error('Missing Host header');
  }

  return new URL(`http://${host}${requestUrl}`);
}

function resolveWebSocketTargetUrl(request: http.IncomingMessage) {
  const requestUrl = request.url ?? '/';
  if (/^wss?:\/\//i.test(requestUrl)) {
    return new URL(requestUrl);
  }
  if (/^https?:\/\//i.test(requestUrl)) {
    const parsed = new URL(requestUrl);
    parsed.protocol = parsed.protocol === 'https:' ? 'wss:' : 'ws:';
    return parsed;
  }

  const host = request.headers.host;
  if (!host) {
    throw new Error('Missing Host header');
  }

  return new URL(`ws://${host}${requestUrl}`);
}

function renderWebSocketRequest(request: http.IncomingMessage, target: URL) {
  const lines = [`GET ${target.pathname}${target.search} HTTP/${request.httpVersion}`];
  const headers: http.IncomingHttpHeaders = { ...request.headers, host: target.host };
  delete headers['proxy-connection'];
  delete headers['proxy-authorization'];

  for (const [key, value] of Object.entries(headers)) {
    lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : value ?? ''}`);
  }

  return `${lines.join('\r\n')}\r\n\r\n`;
}

function connectWebSocketUpstream(target: URL, upstreamTlsMode: UpstreamTlsMode) {
  const port = Number(target.port) || (target.protocol === 'wss:' ? 443 : 80);
  return new Promise<net.Socket>((resolve, reject) => {
    const socket = target.protocol === 'wss:'
      ? tls.connect({ host: target.hostname, port, servername: target.hostname, rejectUnauthorized: upstreamTlsMode === 'strict' })
      : net.connect(port, target.hostname);

    socket.once('connect', () => resolve(socket));
    socket.once('error', reject);
  });
}

function normalizeUpstreamProxyConfig(config?: UpstreamProxyConfig | null): NormalizedUpstreamProxyConfig | null {
  if (!config || config.enabled === false) return null;
  const rawUrl = config.url?.trim();
  if (!rawUrl) return null;
  const url = new URL(rawUrl);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new Error('Upstream proxy URL must use http:// or https://');
  }
  const urlAuthorization = url.username
    ? `Basic ${Buffer.from(`${decodeURIComponent(url.username)}:${decodeURIComponent(url.password)}`).toString('base64')}`
    : undefined;
  url.username = '';
  url.password = '';
  return {
    url,
    authorization: config.authorization?.trim() || urlAuthorization,
    noProxy: (config.noProxy ?? []).map((item) => item.trim()).filter(Boolean),
  };
}

function hasActiveResponseRules(rules: MatchReplaceRule[]) {
  return rules.some((rule) => rule.enabled && rule.match && (rule.direction === 'response' || rule.direction === 'both'));
}

function isChunkedResponse(response: http.IncomingMessage) {
  const transferEncoding = response.headers['transfer-encoding'];
  return Array.isArray(transferEncoding)
    ? transferEncoding.some((value) => /chunked/i.test(value))
    : /chunked/i.test(String(transferEncoding ?? ''));
}

function upstreamProxyTransport(upstreamProxy: NormalizedUpstreamProxyConfig) {
  return upstreamProxy.url.protocol === 'https:' ? https : http;
}

interface ParsedRawRequest {
  method: string;
  path: string;
  headers: http.OutgoingHttpHeaders;
  body: Buffer;
}

function upstreamProxyHttpRequestOptions(target: URL, parsedRequest: ParsedRawRequest, upstreamProxy: NormalizedUpstreamProxyConfig): http.RequestOptions | https.RequestOptions {
  const headers: http.OutgoingHttpHeaders = { ...parsedRequest.headers, host: target.host };
  if (upstreamProxy.authorization) headers['proxy-authorization'] = upstreamProxy.authorization;
  return {
    protocol: upstreamProxy.url.protocol,
    hostname: upstreamProxy.url.hostname,
    port: upstreamProxy.url.port || (upstreamProxy.url.protocol === 'https:' ? 443 : 80),
    method: parsedRequest.method,
    path: target.toString(),
    headers,
  };
}

function renderUpstreamProxyRequest(requestRaw: string, target: URL, upstreamProxy: NormalizedUpstreamProxyConfig) {
  const parsed = parseRawRequest(requestRaw, target);
  const headers: http.OutgoingHttpHeaders = { ...parsed.headers, host: target.host };
  if (upstreamProxy.authorization) headers['Proxy-Authorization'] = upstreamProxy.authorization;
  const lines = [`${parsed.method} ${target.toString()} HTTP/1.1`];
  for (const [key, value] of Object.entries(headers)) {
    lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : value ?? ''}`);
  }
  return `${lines.join('\n')}\n\n${parsed.body.toString('utf8')}`;
}

function renderUpstreamProxyConnectRequest(host: string, port: number, upstreamProxy: NormalizedUpstreamProxyConfig) {
  const lines = [
    `CONNECT ${host}:${port} HTTP/1.1`,
    `Host: ${host}:${port}`,
  ];
  if (upstreamProxy.authorization) lines.push(`Proxy-Authorization: ${upstreamProxy.authorization}`);
  return `${lines.join('\r\n')}\r\n\r\n`;
}

function connectToUpstreamProxy(upstreamProxy: NormalizedUpstreamProxyConfig, upstreamTlsMode: UpstreamTlsMode) {
  const port = Number(upstreamProxy.url.port) || (upstreamProxy.url.protocol === 'https:' ? 443 : 80);
  return new Promise<net.Socket>((resolve, reject) => {
    const socket = upstreamProxy.url.protocol === 'https:'
      ? tls.connect({ host: upstreamProxy.url.hostname, port, servername: upstreamProxy.url.hostname, rejectUnauthorized: upstreamTlsMode === 'strict' })
      : net.connect(port, upstreamProxy.url.hostname);

    if (upstreamProxy.url.protocol === 'https:') {
      (socket as tls.TLSSocket).once('secureConnect', () => resolve(socket));
    } else {
      socket.once('connect', () => resolve(socket));
    }
    socket.once('error', reject);
  });
}

function isUpstreamProxyBypassed(hostname: string, host: string, noProxy: string[]) {
  const normalizedHostname = hostname.toLowerCase();
  const normalizedHost = host.toLowerCase();
  return noProxy.some((pattern) => {
    const normalizedPattern = pattern.toLowerCase();
    if (normalizedPattern === '*') return true;
    if (normalizedPattern.startsWith('*.')) {
      const suffix = normalizedPattern.slice(1);
      return normalizedHostname.endsWith(suffix) || normalizedHostname === normalizedPattern.slice(2);
    }
    if (normalizedPattern.startsWith('.')) return normalizedHostname.endsWith(normalizedPattern);
    return normalizedHostname === normalizedPattern || normalizedHost === normalizedPattern;
  });
}

function normalizeProxyHeaders(headers: http.IncomingHttpHeaders, target: URL) {
  const next: http.OutgoingHttpHeaders = { ...headers, host: target.host };
  delete next['proxy-connection'];
  delete next['proxy-authorization'];
  delete next.connection;
  delete next['accept-encoding'];
  return next;
}

function readBody(request: http.IncomingMessage) {
  return new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    request.on('data', (chunk: Buffer) => chunks.push(chunk));
    request.on('end', () => resolve(Buffer.concat(chunks)));
    request.on('error', reject);
  });
}

function renderRequest(request: http.IncomingMessage, target: URL, body: Buffer) {
  const lines = [`${request.method ?? 'GET'} ${target.pathname}${target.search} HTTP/${request.httpVersion}`];
  for (const [key, value] of Object.entries(request.headers)) {
    lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : value ?? ''}`);
  }
  return `${lines.join('\n')}\n\n${body.toString('utf8')}`;
}

function renderResponse(response: http.IncomingMessage, body: Buffer) {
  const lines = [`HTTP/${response.httpVersion} ${response.statusCode ?? 0} ${response.statusMessage ?? ''}`];
  for (const [key, value] of Object.entries(response.headers)) {
    lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : value ?? ''}`);
  }
  return `${lines.join('\n')}\n\n${body.toString('utf8')}`;
}

function renderSyntheticHttpResponse(statusCode: number, statusMessage: string, body: string, headers: http.OutgoingHttpHeaders = {}) {
  const lines = [`HTTP/1.1 ${statusCode} ${statusMessage}`];
  for (const [key, value] of Object.entries(headers)) {
    lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : value ?? ''}`);
  }
  lines.push(`content-length: ${Buffer.byteLength(body)}`);
  return `${lines.join('\n')}\n\n${body}`;
}

function contentType(header: string | string[] | number | undefined) {
  const raw = Array.isArray(header) ? header[0] : header;
  return typeof raw === 'string' ? raw.split(';')[0] : 'unknown';
}

function passiveRisk(headers: http.IncomingHttpHeaders | http.OutgoingHttpHeaders): HttpExchange['risk'] {
  const csp = headers['content-security-policy'];
  const contentTypeHeader = contentType(headers['content-type']);
  if (!csp && contentTypeHeader.includes('html')) return 'medium';
  if (!headers['x-content-type-options'] && contentTypeHeader.includes('javascript')) return 'low';
  return 'info';
}

function totalLength(chunks: Buffer[]) {
  return chunks.reduce((total, chunk) => total + chunk.length, 0);
}

function normalizeReplayTransportSettings(settings?: ReplayTransportSettings): ReplayTransportSettings {
  return {
    redirectMode: settings?.redirectMode === 'follow' ? 'follow' : 'manual',
    maxRedirects: Math.min(Math.max(Number(settings?.maxRedirects ?? 3) || 0, 0), 10),
    connectionMode: settings?.connectionMode === 'close' || settings?.connectionMode === 'keep-alive' ? settings.connectionMode : 'default',
    timeoutMs: Math.min(Math.max(Number(settings?.timeoutMs ?? 15000) || 15000, 1000), 120000),
  };
}

function replayOastPayloadTags(rawRequest: string, payloads: ReplayOastPayloadReference[] = []) {
  const tags = new Set<string>();
  for (const payload of payloads) {
    const id = payload.id?.trim();
    const token = payload.token?.trim();
    const endpoint = payload.endpoint?.trim();
    if (!id || !token || !endpoint) continue;
    if (
      rawRequest.includes(id)
      || rawRequest.includes(token)
      || rawRequest.includes(endpoint)
      || rawRequest.includes(encodeURIComponent(endpoint))
    ) {
      tags.add('oast-payload');
      tags.add(`callback-payload:${id}`);
      tags.add(`callback-protocol:${payload.protocol ?? 'http'}`);
    }
  }
  return Array.from(tags);
}

function parseRawRequest(rawRequest: string, target: URL, useTargetPath = false) {
  const normalized = rawRequest.replace(/\r\n/g, '\n');
  const [head, ...bodyParts] = normalized.split('\n\n');
  const lines = head.split('\n').filter(Boolean);
  const [method = 'GET', rawPath = `${target.pathname}${target.search}`] = (lines.shift() ?? '').split(/\s+/);
  const headers: http.OutgoingHttpHeaders = {};

  for (const line of lines) {
    const separator = line.indexOf(':');
    if (separator === -1) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!key) continue;
    if (/^(connection|proxy-connection|content-length)$/i.test(key)) continue;
    headers[key] = value;
  }

  headers.host = target.host;
  const body = Buffer.from(bodyParts.join('\n\n'), 'utf8');
  if (body.length > 0) headers['content-length'] = body.length;

  const path = useTargetPath
    ? `${target.pathname}${target.search}`
    : /^https?:\/\//i.test(rawPath)
    ? `${new URL(rawPath).pathname}${new URL(rawPath).search}`
    : rawPath || `${target.pathname}${target.search}`;

  return {
    method,
    path,
    headers,
    body,
  };
}

function parseRawResponse(rawResponse: string, edited: boolean) {
  const normalized = rawResponse.replace(/\r\n/g, '\n');
  const [head, ...bodyParts] = normalized.split('\n\n');
  const lines = head.split('\n').filter(Boolean);
  const statusLine = lines.shift() ?? 'HTTP/1.1 502 Bad Gateway';
  const statusMatch = statusLine.match(/^HTTP\/\d(?:\.\d)?\s+(\d{3})(?:\s+(.*))?$/i);
  const statusCode = statusMatch ? Number(statusMatch[1]) : 502;
  const statusMessage = statusMatch?.[2]?.trim() || http.STATUS_CODES[statusCode] || 'ProxyForge Response';
  const headers: http.OutgoingHttpHeaders = {};

  for (const line of lines) {
    const separator = line.indexOf(':');
    if (separator === -1) continue;
    const key = line.slice(0, separator).trim();
    const value = line.slice(separator + 1).trim();
    if (!key) continue;
    if (/^(connection|proxy-connection|content-length|transfer-encoding)$/i.test(key)) continue;
    if (edited && /^content-encoding$/i.test(key)) continue;
    headers[key] = value;
  }

  const body = Buffer.from(bodyParts.join('\n\n'), 'utf8');
  headers['content-length'] = body.length;

  return {
    statusCode,
    statusMessage,
    headers,
    body,
  };
}

function sanitizeMatchReplaceRules(rules: MatchReplaceRule[]) {
  return rules
    .filter((rule) => rule.id && rule.name)
    .map((rule) => ({
      id: rule.id,
      name: rule.name,
      enabled: Boolean(rule.enabled),
      direction: ['request', 'response', 'both'].includes(rule.direction) ? rule.direction : 'both',
      match: String(rule.match ?? ''),
      replace: String(rule.replace ?? ''),
      isRegex: Boolean(rule.isRegex),
      caseSensitive: Boolean(rule.caseSensitive),
    })) satisfies MatchReplaceRule[];
}

function sanitizeWebSocketFrameRewriteRules(rules: WebSocketFrameRewriteRule[]) {
  return rules
    .filter((rule) => rule.id && rule.name)
    .map((rule) => ({
      id: rule.id,
      name: rule.name,
      enabled: Boolean(rule.enabled),
      direction: ['client', 'server', 'both'].includes(rule.direction) ? rule.direction : 'both',
      frameType: ['text', 'binary', 'close', 'ping', 'pong', 'other', 'both'].includes(rule.frameType) ? rule.frameType : 'both',
      match: String(rule.match ?? ''),
      replace: String(rule.replace ?? ''),
      isRegex: Boolean(rule.isRegex),
      caseSensitive: Boolean(rule.caseSensitive),
    })) satisfies WebSocketFrameRewriteRule[];
}

function buildProxyMatchReplaceSampleMatches(rules: MatchReplaceRule[], exchanges: HttpExchange[]) {
  const samples: ProxyMatchReplaceRuleLibraryPackage['sampleMatches'] = [];
  for (const rule of rules) {
    const directions: Array<'request' | 'response'> = rule.direction === 'both' ? ['request', 'response'] : [rule.direction];
    for (const direction of directions) {
      for (const exchange of exchanges) {
        const before = direction === 'request' ? exchange.requestRaw : exchange.responseRaw;
        const after = applyMatchReplaceRule(before, rule);
        if (after === before) continue;
        samples.push({
          ruleId: rule.id,
          ruleName: rule.name,
          exchangeId: exchange.id,
          direction,
          beforeSnippet: before.slice(0, 300),
          afterSnippet: after.slice(0, 300),
        });
        break;
      }
    }
  }
  return samples.slice(0, 20);
}

function applyMatchReplaceRule(raw: string, rule: MatchReplaceRule) {
  if (rule.isRegex) {
    try {
      const flags = rule.caseSensitive ? 'g' : 'gi';
      return raw.replace(new RegExp(rule.match, flags), rule.replace);
    } catch {
      return raw;
    }
  }

  if (rule.caseSensitive) {
    return raw.split(rule.match).join(rule.replace);
  }

  return raw.replace(new RegExp(escapeRegExp(rule.match), 'gi'), rule.replace);
}

function applyWebSocketFrameRewriteRule(payload: string, rule: WebSocketFrameRewriteRule) {
  if (rule.isRegex) {
    try {
      const flags = rule.caseSensitive ? 'g' : 'gi';
      return payload.replace(new RegExp(rule.match, flags), rule.replace);
    } catch {
      return payload;
    }
  }

  if (rule.caseSensitive) {
    return payload.split(rule.match).join(rule.replace);
  }

  return payload.replace(new RegExp(escapeRegExp(rule.match), 'gi'), rule.replace);
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function webSocketOperationalSecretSignals(messages: WebSocketMessage[]) {
  return webSocketPayloadSecretSignals(messages
    .filter((message) => message.payloadEncoding !== 'hex')
    .map((message) => message.payload)
  );
}

function webSocketPayloadSecretSignals(payloads: string[]) {
  const raw = payloads.join('\n');
  const signals = [
    /authorization|bearer\s+[A-Za-z0-9._~+/=-]{6,}/i.test(raw) ? 'authorization-or-bearer-token' : '',
    /cookie|sessionid|sid=/i.test(raw) ? 'cookie-or-session-material' : '',
    /(?:token|secret|session|api[-_]?key|key)\s*[:= ]+[A-Za-z0-9._~+/=-]{6,}/i.test(raw) ? 'secret-like-material' : '',
    /support_admin|admin|role=/i.test(raw) ? 'privileged-role-material' : '',
  ].filter(Boolean);
  return Array.from(new Set(signals)).sort();
}

function countBy(values: string[]) {
  return values.reduce<Record<string, number>>((counts, value) => {
    counts[value] = (counts[value] ?? 0) + 1;
    return counts;
  }, {});
}

function hasHttpBody(raw: string) {
  const normalized = raw.replace(/\r\n/g, '\n');
  const [, ...bodyParts] = normalized.split('\n\n');
  return bodyParts.join('\n\n').trim().length > 0;
}

interface IntruderPayloadPlan {
  label: string;
  payloads: string[];
  rawRequest: string;
}

export function buildIntruderAttackModeMatrix(
  rawRequest: string,
  request: Pick<IntruderAttackRequest, 'payloads' | 'payloadSets' | 'payloadProcessors' | 'payloadRules' | 'attackMode'>,
  generatedAt = new Date().toISOString(),
): IntruderAttackModeMatrixPackage {
  const modes: IntruderAttackMode[] = ['sniper', 'battering-ram', 'pitchfork', 'cluster-bomb'];
  const payloadPositions = countIntruderMarkers(rawRequest);
  const payloadSets = normalizeIntruderPayloadSets(request as IntruderAttackRequest);
  const payloadTransformations = buildIntruderPayloadTransformationMatrix(request);
  const entries = modes.map((mode) => {
    const plans = buildIntruderPayloadPlans(rawRequest, request as IntruderAttackRequest, mode);
    return {
      mode,
      payloadPositions,
      payloadSetCount: payloadSets.length,
      payloadCounts: payloadSets.map((set) => set.length),
      requestCount: plans.length,
      samplePayloads: plans.slice(0, 3).map((plan) => plan.payloads),
      sampleRequests: plans.slice(0, 3).map((plan) => plan.rawRequest),
      semantics: intruderModeSemantics(mode),
      warnings: intruderModeWarnings(mode, payloadPositions, payloadSets),
    };
  });
  const selectedMode = sanitizeIntruderAttackMode(request.attackMode);
  return {
    kind: 'proxyforge-intruder-attack-mode-matrix',
    schemaVersion: 1,
    generatedAt,
    payloadPositions,
    payloadSetCount: payloadSets.length,
    payloadTransformations,
    modes: entries,
    selectedMode,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    summary: `Intruder attack mode matrix covered ${payloadPositions} payload position(s), ${payloadSets.length} payload set(s), ${payloadTransformations.processors.length} processor(s), ${payloadTransformations.rules.length} rule(s), and ${entries.map((entry) => `${entry.mode}:${entry.requestCount}`).join(', ')} request expansion(s).`,
    content: `proxyforge-intruder-attack-mode-matrix positions=${payloadPositions} processors=${payloadTransformations.processors.join(',') || 'none'} rules=${payloadTransformations.rules.join(',') || 'none'} modes=${entries.map((entry) => `${entry.mode}:${entry.requestCount}`).join(',')}`,
  };
}

export function buildIntruderCheckpointResumePackage(input: {
  summaries: IntruderAttackSummary[];
  queue?: IntruderCheckpointQueueEvidence[];
  generatedAt?: string;
}): IntruderCheckpointResumePackage {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const summaries = input.summaries.filter(Boolean);
  const firstSummary = summaries[0];
  const targetUrl = firstSummary?.targetUrl ?? input.queue?.[0]?.targetUrl ?? '';
  const attackMode = firstSummary?.attackMode ?? input.queue?.[0]?.attackMode ?? 'sniper';
  const checkpointChain = summaries.map((summary) => ({
    summaryId: summary.id,
    startOffset: summary.startOffset ?? 0,
    nextOffset: summary.nextOffset ?? summary.totalRequests,
    hasMore: Boolean(summary.hasMore),
    totalRequests: summary.totalRequests,
    retainedResultCount: summary.streaming?.retainedResultCount ?? summary.results.length,
    droppedResultCount: summary.streaming?.droppedResultCount ?? 0,
    resourcePoolName: summary.resourcePoolName ?? 'Default sequential pool',
    resourcePoolMaxConcurrent: summary.resourcePoolMaxConcurrent ?? 1,
    payloadRuleCount: summary.payloadRuleCount ?? 0,
    resultIds: summary.results.map((result) => result.id),
    rawRequestSamples: summary.results.slice(0, 3).map((result) => result.requestRaw),
  }));
  const resumeLinks = summaries.slice(1).map((summary, index) => {
    const previous = summaries[index];
    const expectedOffset = previous.nextOffset ?? previous.totalRequests;
    const actualStartOffset = summary.startOffset ?? 0;
    return {
      fromSummaryId: previous.id,
      toSummaryId: summary.id,
      expectedOffset,
      actualStartOffset,
      linked: expectedOffset === actualStartOffset,
    };
  });
  const queue = input.queue ?? summaries.map((summary, index) => ({
    id: `intruder-queue-${summary.id}`,
    attackName: `${summary.attackMode} ${new URL(summary.targetUrl).pathname || '/'}`,
    targetUrl: summary.targetUrl,
    attackMode: summary.attackMode,
    status: summary.blocked ? 'blocked' as const : summary.hasMore ? 'paused' as const : 'complete' as const,
    totalRequests: summary.payloadPlanCount ?? summary.totalRequests,
    completedRequests: summary.nextOffset ?? summary.totalRequests,
    message: summary.message,
    createdAt: summary.startedAt,
    updatedAt: summary.completedAt,
    latestSummaryId: summary.id,
    checkpointOffset: summary.nextOffset,
    resourcePoolName: summary.resourcePoolName,
    payloadRules: [],
  }));
  const resourcePools = Array.from(new Map(summaries.map((summary) => {
    const name = summary.resourcePoolName ?? 'Default sequential pool';
    return [name, {
      name,
      maxConcurrent: summary.resourcePoolMaxConcurrent ?? 1,
      summaryIds: summaries.filter((candidate) => (candidate.resourcePoolName ?? 'Default sequential pool') === name).map((candidate) => candidate.id),
    }];
  })).values());
  const rawMaterial = summaries.flatMap((summary) => summary.results.flatMap((result) => [result.requestRaw, result.responseRaw]));
  const operationalSecretSignals = intruderOperationalSecretSignals(...rawMaterial);
  const payloadPlanCount = Math.max(...summaries.map((summary) => summary.payloadPlanCount ?? summary.totalRequests), queue[0]?.totalRequests ?? 0, 0);
  const finalOffset = Math.max(...summaries.map((summary) => summary.nextOffset ?? summary.totalRequests), queue[0]?.completedRequests ?? 0, 0);
  const requirements = {
    checkpointPauseCovered: summaries.some((summary) => summary.hasMore && (summary.nextOffset ?? 0) > (summary.startOffset ?? 0)),
    resumeCovered: resumeLinks.some((link) => link.linked),
    queueStateCovered: queue.length > 0 && queue.some((item) => item.status === 'paused') && queue.some((item) => item.status === 'complete'),
    resourcePoolStateCovered: resourcePools.length > 0 && resourcePools.some((pool) => pool.maxConcurrent > 1 || /pool/i.test(pool.name)),
    payloadRuleStateCovered: summaries.some((summary) => (summary.payloadRuleCount ?? 0) > 0) || queue.some((item) => (item.payloadRules ?? []).length > 0),
    resultWindowStateCovered: summaries.some((summary) => (summary.streaming?.retainedResultCount ?? summary.results.length) <= (summary.streaming?.resultWindowSize ?? summary.results.length)),
    rawExecutorMaterialPreserved: rawMaterial.some((value) => /HTTP\/\d|HTTP\/2|Authorization:|Cookie:/i.test(value)),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-intruder-checkpoint-resume-package',
    generatedAt,
    summaryIds: summaries.map((summary) => summary.id),
    checkpointChain,
    resumeLinks,
    queue,
    resourcePools,
    requirements,
  };

  return {
    kind: 'proxyforge-intruder-checkpoint-resume-package',
    schemaVersion: 1,
    generatedAt,
    targetUrl,
    attackMode,
    summaryIds: summaries.map((summary) => summary.id),
    payloadPlanCount,
    totalRequestsSent: summaries.reduce((total, summary) => total + summary.totalRequests, 0),
    finalOffset,
    checkpointCount: summaries.length,
    pausedCheckpointCount: summaries.filter((summary) => summary.hasMore).length,
    resumedCheckpointCount: resumeLinks.filter((link) => link.linked).length,
    queue,
    checkpointChain,
    resumeLinks,
    resourcePools,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
    summary: `Intruder checkpoint package preserved ${summaries.length} slice(s), ${resumeLinks.filter((link) => link.linked).length} resume link(s), ${queue.length} queue item(s), and ${operationalSecretSignals.length} operational secret signal(s).`,
    content: JSON.stringify(body, null, 2),
  };
}

export function buildIntruderGrepExtractComparisonPackage(input: {
  summary: IntruderAttackSummary;
  promotedIssue?: {
    id: string;
    title: string;
    severity: Severity;
    confidence: 'certain' | 'firm' | 'tentative';
    detail: string;
    remediation: string;
  };
  generatedAt?: string;
}): IntruderGrepExtractComparisonPackage {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const summary = input.summary;
  const comparisons = buildIntruderComparisonEvidence(summary);
  const analysis = buildIntruderClusterRankingEvidence(summary);
  const resultSamples = summary.results.slice(0, 20).map((result) => ({
    id: result.id,
    payload: result.payload,
    payloads: result.payloads,
    status: result.status,
    length: result.length,
    timing: result.timing,
    grepMatches: result.grepMatches,
    extractMatches: result.extractMatches,
    requestRaw: result.requestRaw,
    responseRaw: result.responseRaw,
    tags: result.tags,
  }));
  const rawMaterial = summary.results.flatMap((result) => [result.requestRaw, result.responseRaw]);
  const operationalSecretSignals = intruderOperationalSecretSignals(...rawMaterial);
  const grepMatchCount = summary.results.reduce((total, result) => total + result.grepMatches.length, 0);
  const extractMatchCount = summary.results.reduce((total, result) => total + result.extractMatches.length, 0);
  const requirements = {
    grepMatchCovered: grepMatchCount > 0,
    extractRegexCovered: extractMatchCount > 0,
    baselineComparisonCovered: comparisons.length > 0 && comparisons.some((comparison) => comparison.verdict !== 'similar'),
    clusteringCovered: analysis.clusters.length > 0 && analysis.clusters.some((cluster) => cluster.resultCount > 0),
    statisticalRankingCovered: analysis.rankings.length > 0 && analysis.rankings[0].score >= 0,
    scannerPromotionCovered: Boolean(input.promotedIssue?.id && input.promotedIssue.title),
    rawExecutorMaterialPreserved: rawMaterial.some((value) => /HTTP\/\d|HTTP\/2|Authorization:|Cookie:/i.test(value)),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-intruder-grep-extract-comparison-package',
    generatedAt,
    summaryId: summary.id,
    resultIds: summary.results.map((result) => result.id),
    comparisons: comparisons.slice(0, 50),
    clusters: analysis.clusters.slice(0, 50),
    rankings: analysis.rankings.slice(0, 50),
    promotedIssue: input.promotedIssue,
    requirements,
  };

  return {
    kind: 'proxyforge-intruder-grep-extract-comparison-package',
    schemaVersion: 1,
    generatedAt,
    summaryId: summary.id,
    targetUrl: summary.targetUrl,
    attackMode: summary.attackMode,
    resultCount: summary.results.length,
    grepMatchCount,
    extractMatchCount,
    comparisonCount: comparisons.length,
    clusterCount: analysis.clusters.length,
    rankingCount: analysis.rankings.length,
    resultSamples,
    comparisons,
    clusters: analysis.clusters,
    rankings: analysis.rankings,
    promotedIssue: input.promotedIssue,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
    summary: `Intruder analysis package compared ${summary.results.length} result(s), found ${grepMatchCount} grep signal(s), ${extractMatchCount} extract signal(s), ${comparisons.length} comparison(s), and ${analysis.clusters.length} cluster(s).`,
    content: JSON.stringify(body, null, 2),
  };
}

export function buildIntruderLiveTargetProfilePackage(input: {
  summaries: IntruderAttackSummary[];
  attackModeMatrix?: IntruderAttackModeMatrixPackage;
  checkpointPackage?: IntruderCheckpointResumePackage;
  analysisPackage?: IntruderGrepExtractComparisonPackage;
  generatedAt?: string;
}): IntruderLiveTargetProfilePackage {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const summaries = input.summaries.filter((summary) => summary && !summary.blocked);
  const targetProfiles = summaries.map((summary) => {
    const parsedTarget = safeUrl(summary.targetUrl);
    const statusCodes = Array.from(new Set(summary.results.map((result) => result.status))).sort((left, right) => left - right);
    return {
      summaryId: summary.id,
      targetUrl: summary.targetUrl,
      path: parsedTarget ? `${parsedTarget.pathname || '/'}${parsedTarget.search || ''}` : summary.targetUrl,
      attackMode: summary.attackMode,
      totalRequests: summary.totalRequests,
      statusCodes,
      grepMatchCount: summary.results.reduce((total, result) => total + result.grepMatches.length, 0),
      extractMatchCount: summary.results.reduce((total, result) => total + result.extractMatches.length, 0),
      retainedResultCount: summary.streaming?.retainedResultCount ?? summary.results.length,
      droppedResultCount: summary.streaming?.droppedResultCount ?? 0,
      maxInFlight: summary.streaming?.maxInFlight ?? 0,
      requestRatePerSecond: summary.streaming?.requestRatePerSecond ?? 0,
      rawRequestSamples: summary.results.slice(0, 3).map((result) => result.requestRaw),
    };
  });
  const targetPaths = new Set(targetProfiles.map((profile) => profile.path));
  const attackModes = new Set(targetProfiles.map((profile) => profile.attackMode));
  const statusCodes = summaries.flatMap((summary) => summary.results.map((result) => result.status));
  const statusClasses = Array.from(new Set(statusCodes.map((status) => `${Math.floor(status / 100)}xx`))).sort();
  const totalRequestsSent = summaries.reduce((total, summary) => total + summary.totalRequests, 0);
  const retainedResultCount = summaries.reduce((total, summary) => total + (summary.streaming?.retainedResultCount ?? summary.results.length), 0);
  const droppedResultCount = summaries.reduce((total, summary) => total + (summary.streaming?.droppedResultCount ?? 0), 0);
  const maxInFlight = Math.max(...summaries.map((summary) => summary.streaming?.maxInFlight ?? 0), 0);
  const durationMs = summaries.reduce((total, summary) => total + (summary.streaming?.durationMs ?? 0), 0);
  const requestRatePerSecond = durationMs > 0 ? Number((totalRequestsSent / (durationMs / 1000)).toFixed(2)) : 0;
  const rawMaterial = summaries.flatMap((summary) => summary.results.flatMap((result) => [result.requestRaw, result.responseRaw]));
  const operationalSecretSignals = intruderOperationalSecretSignals(...rawMaterial);
  const matrixPayloadTransformations = input.attackModeMatrix?.payloadTransformations;
  const linkedPackageKinds = [
    input.attackModeMatrix?.kind,
    input.checkpointPackage?.kind,
    input.analysisPackage?.kind,
  ].flatMap((kind) => (kind ? [kind] : []));
  const summaryDigests = summaries.map((summary) => simpleDigest(JSON.stringify({
    id: summary.id,
    targetUrl: summary.targetUrl,
    attackMode: summary.attackMode,
    totalRequests: summary.totalRequests,
    resultCount: summary.results.length,
    streaming: summary.streaming,
  })));
  const profileDigest = simpleDigest(JSON.stringify({
    targetProfiles,
    statusClasses,
    linkedPackageKinds,
  }));
  const requirements = {
    liveTargetDiversityCovered: targetPaths.size >= 3 && statusClasses.includes('2xx') && statusClasses.includes('4xx'),
    attackModeDiversityCovered: attackModes.size >= 3 || (input.attackModeMatrix?.modes.length ?? 0) >= 4,
    highVolumeStreamingCovered: summaries.some((summary) => (
      summary.totalRequests >= 100
      && (summary.streaming?.completedChunks ?? 0) > 1
      && (summary.streaming?.retainedResultCount ?? 0) > 0
      && (summary.streaming?.droppedResultCount ?? 0) > 0
      && (summary.streaming?.requestRatePerSecond ?? 0) > 0
    )),
    resourcePoolConcurrencyCovered: maxInFlight > 1
      && summaries.some((summary) => (summary.streaming?.maxConcurrency ?? 0) > 1),
    checkpointResumeCovered: Boolean(input.checkpointPackage?.requirements.checkpointPauseCovered
      && input.checkpointPackage.requirements.resumeCovered
      && input.checkpointPackage.requirements.queueStateCovered),
    grepExtractTriageCovered: Boolean(input.analysisPackage?.requirements.grepMatchCovered
      && input.analysisPackage.requirements.extractRegexCovered
      && input.analysisPackage.requirements.clusteringCovered
      && input.analysisPackage.requirements.statisticalRankingCovered),
    authzDifferentialCovered: statusCodes.some((status) => status >= 200 && status < 300)
      && statusCodes.some((status) => status === 401 || status === 403),
    payloadTransformCoverageCovered: Boolean((matrixPayloadTransformations?.processors.length ?? 0) > 0
      && (matrixPayloadTransformations?.rules.length ?? 0) > 0)
      || summaries.some((summary) => (summary.payloadRuleCount ?? 0) > 0),
    packageRefreshCovered: summaryDigests.length === summaries.length
      && profileDigest.length > 0
      && linkedPackageKinds.length >= 3,
    rawExecutorMaterialPreserved: rawMaterial.some((value) => /HTTP\/\d|HTTP\/2|Authorization:|Cookie:|X-API-Key:/i.test(value)),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const packageRefreshProof = {
    refreshedAt: generatedAt,
    summaryDigests,
    profileDigest,
    linkedPackageKinds,
    staleSummaryIds: [],
  };
  const body = {
    kind: 'proxyforge-intruder-live-target-profile-package',
    generatedAt,
    targetProfiles,
    statusClasses,
    packageRefreshProof,
    linkedPackages: {
      attackModeMatrix: input.attackModeMatrix,
      checkpointPackage: input.checkpointPackage,
      analysisPackage: input.analysisPackage,
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };

  return {
    kind: 'proxyforge-intruder-live-target-profile-package',
    schemaVersion: 1,
    generatedAt,
    targetUrlCount: targetPaths.size,
    attackModeCount: attackModes.size,
    totalRequestsSent,
    retainedResultCount,
    droppedResultCount,
    maxInFlight,
    requestRatePerSecond,
    statusClasses,
    targetProfiles,
    packageRefreshProof,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
    summary: `Intruder live-target profile preserved ${summaries.length} run(s), ${targetPaths.size} target path(s), ${attackModes.size} attack mode(s), ${totalRequestsSent} request(s), ${retainedResultCount} retained result(s), ${droppedResultCount} dropped-window result(s), max in-flight ${maxInFlight}, and ${operationalSecretSignals.length} operational secret signal(s).`,
    content: JSON.stringify(body, null, 2),
  };
}

export function correlateIntruderOastResults(
  summary: IntruderAttackSummary,
  payloads: IntruderOastPayloadReference[],
  interactions: IntruderOastInteractionReference[],
): IntruderAttackSummary {
  const cleanPayloads = sanitizeIntruderOastPayloads(payloads);
  const cleanInteractions = sanitizeIntruderOastInteractions(interactions);
  const results = summary.results.map((result) => {
    const matchedPayloads = matchIntruderOastPayloads(`${result.requestRaw}\n${result.responseRaw}`, cleanPayloads);
    const payloadIds = Array.from(new Set([...(result.oastPayloadIds ?? []), ...matchedPayloads.map((payload) => payload.id)]));
    const callbackInteractionIds = Array.from(new Set([
      ...(result.callbackInteractionIds ?? []),
      ...cleanInteractions
        .filter((interaction) => payloadIds.includes(interaction.payloadId) || matchedPayloads.some((payload) => intruderOastTextMatchesPayload(intruderInteractionRaw(interaction), payload)))
        .map((interaction) => interaction.id),
    ]));
    return {
      ...result,
      oastPayloadIds: payloadIds,
      callbackInteractionIds,
      tags: Array.from(new Set([
        ...result.tags,
        payloadIds.length > 0 ? 'oast-payload' : '',
        callbackInteractionIds.length > 0 ? 'oast-hit' : payloadIds.length > 0 ? 'oast-pending' : '',
      ].filter(Boolean))),
    };
  });
  return {
    ...summary,
    results,
    oast: buildIntruderOastSummary(cleanPayloads, cleanInteractions, results),
  };
}

export function buildIntruderOastCorrelationPackage(input: {
  summary: IntruderAttackSummary;
  payloads: IntruderOastPayloadReference[];
  interactions: IntruderOastInteractionReference[];
  generatedAt?: string;
}): IntruderOastCorrelationPackage {
  const generatedAt = input.generatedAt ?? new Date().toISOString();
  const correlatedSummary = correlateIntruderOastResults(input.summary, input.payloads, input.interactions);
  const oastSummary = correlatedSummary.oast ?? buildIntruderOastSummary(input.payloads, input.interactions, correlatedSummary.results);
  const resultRows = correlatedSummary.results
    .filter((result) => (result.oastPayloadIds?.length ?? 0) > 0 || (result.callbackInteractionIds?.length ?? 0) > 0)
    .map((result) => ({
      id: result.id,
      payload: result.payload,
      status: result.status,
      oastPayloadIds: result.oastPayloadIds ?? [],
      callbackInteractionIds: result.callbackInteractionIds ?? [],
      tags: result.tags,
      requestRaw: result.requestRaw,
      responseRaw: result.responseRaw,
    }));
  const rawMaterial = resultRows.flatMap((result) => [result.requestRaw, result.responseRaw]);
  const requirements = {
    payloadRowsCovered: resultRows.length > 0 && resultRows.every((result) => result.oastPayloadIds.length > 0),
    callbackInteractionsCovered: input.interactions.length > 0,
    rowCorrelationCovered: resultRows.some((result) => result.callbackInteractionIds.length > 0),
    rawExecutorMaterialPreserved: rawMaterial.some((value) => /HTTP\/\d|Authorization:|Cookie:|Bearer|session=/i.test(value)),
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-intruder-oast-correlation-package',
    generatedAt,
    summaryId: correlatedSummary.id,
    targetUrl: correlatedSummary.targetUrl,
    oast: oastSummary,
    resultRows,
    requirements,
  };

  return {
    kind: 'proxyforge-intruder-oast-correlation-package',
    schemaVersion: 1,
    generatedAt,
    summaryId: correlatedSummary.id,
    targetUrl: correlatedSummary.targetUrl,
    attackMode: correlatedSummary.attackMode,
    payloadCount: oastSummary.payloadCount,
    interactionCount: oastSummary.interactionCount,
    correlatedResultCount: oastSummary.correlatedResultCount,
    correlatedInteractionCount: oastSummary.correlatedInteractionCount,
    resultRows,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `Intruder OAST correlation mapped ${oastSummary.correlatedInteractionCount} callback interaction(s) onto ${oastSummary.correlatedResultCount} result row(s).`,
    content: JSON.stringify(body, null, 2),
  };
}

export function buildProxyHttpListenerCapturePackage(
  exchanges: HttpExchange[],
  generatedAt = new Date().toISOString(),
): ProxyHttpListenerCapturePackage {
  const proxyExchanges = exchanges.filter((exchange) => (
    exchange.source === 'proxy'
    && !exchange.tags?.includes('tunnel')
    && exchange.mime !== 'mitm-tunnel'
  ));
  const methodCounts = countBy(proxyExchanges.map((exchange) => exchange.method || 'UNKNOWN'));
  const statusFamilies = {
    '2xx': proxyExchanges.filter((exchange) => exchange.status >= 200 && exchange.status < 300).length,
    '3xx': proxyExchanges.filter((exchange) => exchange.status >= 300 && exchange.status < 400).length,
    '4xx': proxyExchanges.filter((exchange) => exchange.status >= 400 && exchange.status < 500).length,
    '5xx': proxyExchanges.filter((exchange) => exchange.status >= 500 && exchange.status < 600).length,
    other: proxyExchanges.filter((exchange) => exchange.status < 200 || exchange.status >= 600).length,
  };
  const rawRequestBytes = proxyExchanges.reduce((total, exchange) => total + Buffer.byteLength(exchange.requestRaw ?? ''), 0);
  const rawResponseBytes = proxyExchanges.reduce((total, exchange) => total + Buffer.byteLength(exchange.responseRaw ?? ''), 0);
  const bodyCaptureCount = proxyExchanges.filter((exchange) => hasHttpBody(exchange.requestRaw) || hasHttpBody(exchange.responseRaw)).length;
  const operationalSecretSignals = Array.from(new Set(proxyExchanges.flatMap((exchange) => [
    /authorization:/i.test(exchange.requestRaw) ? 'authorization-header' : '',
    /cookie:/i.test(exchange.requestRaw) ? 'cookie-header' : '',
    /x-api-key:/i.test(exchange.requestRaw) ? 'x-api-key-header' : '',
    /token|secret|session|api[-_ ]?key/i.test(`${exchange.requestRaw}\n${exchange.responseRaw}`) ? 'secret-like-material' : '',
  ].filter(Boolean)))).sort();
  const methods = Object.keys(methodCounts);
  const packageBody = {
    generatedAt,
    exchangeIds: proxyExchanges.map((exchange) => exchange.id),
    methodCounts,
    statusFamilies,
    operationalSecretSignals,
  };

  return {
    kind: 'proxyforge-proxy-http-listener-capture-package',
    schemaVersion: 1,
    generatedAt,
    exchangeCount: exchanges.length,
    proxyExchangeCount: proxyExchanges.length,
    methodCounts,
    statusFamilies,
    hosts: Array.from(new Set(proxyExchanges.map((exchange) => exchange.host).filter(Boolean))).sort(),
    paths: Array.from(new Set(proxyExchanges.map((exchange) => exchange.path).filter(Boolean))).sort(),
    bodyCaptureCount,
    rawRequestBytes,
    rawResponseBytes,
    operationalSecretSignals,
    samples: proxyExchanges.slice(0, 5).map((exchange) => ({
      id: exchange.id,
      method: exchange.method,
      url: exchange.url,
      status: exchange.status,
      mime: exchange.mime,
      notes: exchange.notes,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      tags: exchange.tags,
    })),
    requirements: {
      loopbackProxyListenerCovered: proxyExchanges.some((exchange) => /Captured by local proxy listener/i.test(exchange.notes)),
      historyRowsCaptured: proxyExchanges.length > 0,
      multiMethodCaptureCovered: methods.length >= 2,
      requestBodyCaptureCovered: proxyExchanges.some((exchange) => hasHttpBody(exchange.requestRaw)),
      responseBodyCaptureCovered: proxyExchanges.some((exchange) => hasHttpBody(exchange.responseRaw)),
      fullFidelityRawCovered: proxyExchanges.every((exchange) => exchange.requestRaw.includes('HTTP/') && exchange.responseRaw.includes('HTTP/')),
      operationalSecretsPreserved: operationalSecretSignals.length > 0,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `HTTP listener captured ${proxyExchanges.length} proxy history row(s), ${methods.length} method(s), ${bodyCaptureCount} body-bearing exchange(s), and ${operationalSecretSignals.length} operational secret signal(s).`,
    content: JSON.stringify(packageBody, null, 2),
  };
}

export function buildHttpsMitmEvidencePackage(
  exchanges: HttpExchange[],
  options: HttpsMitmEvidenceOptions = {},
): HttpsMitmEvidencePackage {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const capturedHttps = exchanges.filter((exchange) => (
    exchange.tags?.includes('https')
    && (exchange.tags.includes('captured') || /Captured by HTTPS inspection/i.test(exchange.notes))
  ));
  const mitmTunnels = exchanges.filter((exchange) => (
    exchange.tags?.includes('mitm') || exchange.mime === 'mitm-tunnel'
  ));
  const strictFailures = exchanges.filter((exchange) => (
    exchange.tags?.includes('strict-upstream-tls')
    || /upstream TLS strict/i.test(exchange.notes)
  ));
  const related = capturedHttps.concat(strictFailures);
  const hosts = Array.from(new Set(related.map((exchange) => exchange.host).filter(Boolean))).sort();
  const paths = Array.from(new Set(related.map((exchange) => exchange.path).filter(Boolean))).sort();
  const hostCertificateCount = options.certificate?.hostCertificateCount ?? 0;
  const projectCaGenerated = Boolean(options.certificate?.ready || options.certificate?.fingerprintSha256);
  const trustMode = options.trustMode ?? 'project-ca';
  const packageBody = {
    generatedAt,
    exchangeIds: related.slice(0, 12).map((exchange) => exchange.id),
    certificateFingerprintSha256: options.certificate?.fingerprintSha256,
    hostCertificateCount,
    trustMode,
    strictFailureIds: strictFailures.map((exchange) => exchange.id),
  };

  return {
    kind: 'proxyforge-https-mitm-evidence-package',
    schemaVersion: 1,
    generatedAt,
    exchangeCount: exchanges.length,
    capturedHttpsExchangeCount: capturedHttps.length,
    mitmTunnelCount: mitmTunnels.length,
    strictUpstreamFailureCount: strictFailures.length,
    hosts,
    paths,
    certificate: {
      ready: Boolean(options.certificate?.ready),
      projectId: options.certificate?.projectId,
      fingerprintSha256: options.certificate?.fingerprintSha256,
      validUntil: options.certificate?.validUntil,
      hostCertificateCount,
      rootCertificatePath: options.certificate?.rootCertificatePath,
      trustMode,
    },
    modes: {
      relaxedCaptured: capturedHttps.some((exchange) => /upstream TLS relaxed/i.test(exchange.notes)),
      strictFailureCaptured: strictFailures.length > 0,
      inspectionTunnelCaptured: mitmTunnels.length > 0,
    },
    requirements: {
      projectCaGenerated,
      hostCertificateReused: hostCertificateCount > 0 && capturedHttps.length > hostCertificateCount,
      decryptedTrafficCaptured: capturedHttps.length > 0,
      strictUpstreamFailureCaptured: strictFailures.length > 0,
    },
    samples: related.slice(0, 4).map((exchange) => ({
      id: exchange.id,
      method: exchange.method,
      url: exchange.url,
      status: exchange.status,
      notes: exchange.notes,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
      tags: exchange.tags,
    })),
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `HTTPS MITM package captured ${capturedHttps.length} decrypted HTTPS exchange(s), ${mitmTunnels.length} MITM tunnel marker(s), ${strictFailures.length} strict-upstream failure(s), and ${hostCertificateCount} generated/reused host certificate(s).`,
    content: JSON.stringify(packageBody, null, 2),
  };
}

export function buildProxyInterceptEvidencePackage(
  exchanges: HttpExchange[],
  generatedAt = new Date().toISOString(),
): ProxyInterceptEvidencePackage {
  const intercepted = exchanges.filter((exchange) => (
    exchange.tags?.includes('intercepted')
    || exchange.tags?.includes('edited')
    || exchange.tags?.includes('response-edited')
    || exchange.tags?.includes('response-dropped')
    || exchange.tags?.includes('dropped')
  ));
  const requestDropped = intercepted.filter((exchange) => exchange.tags.includes('dropped'));
  const responseDropped = intercepted.filter((exchange) => exchange.tags.includes('response-dropped'));
  const responseEdited = intercepted.filter((exchange) => exchange.tags.includes('response-edited'));
  const requestEdited = intercepted.filter((exchange) => exchange.tags.includes('edited') && !exchange.tags.includes('response-edited'));
  const matchReplace = exchanges.filter((exchange) => exchange.tags?.includes('match-replace'));
  const requestForwarded = intercepted.filter((exchange) => (
    (exchange.tags.includes('edited') || exchange.tags.includes('forwarded'))
    && !exchange.tags.includes('response-edited')
    && !exchange.tags.includes('dropped')
    && !exchange.tags.includes('response-dropped')
  ));
  const responseForwarded = intercepted.filter((exchange) => (
    exchange.tags.includes('response-forwarded')
    || exchange.tags.includes('response-edited')
  ));
  const decisions = intercepted.map((exchange) => {
    const direction: 'request' | 'response' = exchange.tags.includes('response-edited') || exchange.tags.includes('response-dropped')
      ? 'response'
      : 'request';
    const action: 'forward' | 'drop' = exchange.tags.includes('dropped') || exchange.tags.includes('response-dropped') ? 'drop' : 'forward';
    const edited = exchange.tags.includes('edited') || exchange.tags.includes('response-edited') || exchange.tags.includes('match-replace');
    return {
      exchangeId: exchange.id,
      direction,
      action,
      edited,
      path: exchange.path,
      status: exchange.status,
      tags: exchange.tags,
    };
  });
  const packageBody = {
    generatedAt,
    decisionCount: decisions.length,
    paths: Array.from(new Set(decisions.map((decision) => decision.path))).sort(),
    tags: Array.from(new Set(intercepted.flatMap((exchange) => exchange.tags))).sort(),
  };

  return {
    kind: 'proxyforge-proxy-intercept-evidence-package',
    schemaVersion: 1,
    generatedAt,
    exchangeCount: exchanges.length,
    requestForwardedCount: requestForwarded.length,
    requestEditedCount: requestEdited.length,
    requestDroppedCount: requestDropped.length,
    responseForwardedCount: responseForwarded.length,
    responseEditedCount: responseEdited.length,
    responseDroppedCount: responseDropped.length,
    matchReplaceCount: matchReplace.length,
    paths: packageBody.paths,
    decisions,
    requirements: {
      requestForwardCovered: requestForwarded.length > 0,
      requestEditCovered: requestEdited.length > 0,
      requestDropCovered: requestDropped.length > 0,
      responseForwardCovered: responseForwarded.length > 0,
      responseEditCovered: responseEdited.length > 0,
      responseDropCovered: responseDropped.length > 0,
      matchReplaceCovered: matchReplace.length > 0,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `Proxy intercept evidence covered ${requestForwarded.length} request forward/edit decision(s), ${requestDropped.length} request drop(s), ${responseForwarded.length} response decision(s), ${responseDropped.length} response drop(s), and ${matchReplace.length} match/replace exchange(s).`,
    content: JSON.stringify(packageBody, null, 2),
  };
}

export function buildProxyMatchReplaceRuleLibraryPackage(
  rules: MatchReplaceRule[],
  exchanges: HttpExchange[] = [],
  generatedAt = new Date().toISOString(),
): ProxyMatchReplaceRuleLibraryPackage {
  const sanitizedRules = sanitizeMatchReplaceRules(rules);
  const activeRules = sanitizedRules.filter((rule) => rule.enabled && rule.match);
  const sampleMatches = buildProxyMatchReplaceSampleMatches(activeRules, exchanges);
  const appliedRuleTags = Array.from(new Set(exchanges.flatMap((exchange) => (
    exchange.tags.filter((tag) => tag.startsWith('request-rule:') || tag.startsWith('response-rule:'))
  )))).sort();
  const directionCounts = {
    request: sanitizedRules.filter((rule) => rule.direction === 'request').length,
    response: sanitizedRules.filter((rule) => rule.direction === 'response').length,
    both: sanitizedRules.filter((rule) => rule.direction === 'both').length,
  };
  const threshold = 100;
  const warnings: string[] = [];
  const droppedRuleCount = Math.max(0, rules.length - sanitizedRules.length);
  if (droppedRuleCount > 0) warnings.push(`${droppedRuleCount} malformed rule(s) were skipped during sanitization.`);
  if (sanitizedRules.length >= threshold) warnings.push(`Large match/replace library contains ${sanitizedRules.length} rules; use filtering and scoped enablement before live traffic.`);
  const packageBody = {
    generatedAt,
    ruleCount: sanitizedRules.length,
    enabledRuleCount: activeRules.length,
    directionCounts,
    appliedRuleTags,
    rules: sanitizedRules,
  };

  return {
    kind: 'proxyforge-proxy-match-replace-rule-library',
    schemaVersion: 1,
    generatedAt,
    ruleCount: sanitizedRules.length,
    enabledRuleCount: activeRules.length,
    directionCounts,
    regexRuleCount: sanitizedRules.filter((rule) => rule.isRegex).length,
    caseSensitiveRuleCount: sanitizedRules.filter((rule) => rule.caseSensitive).length,
    largeRuleSet: {
      threshold,
      exceeded: sanitizedRules.length >= threshold,
      totalRules: sanitizedRules.length,
    },
    appliedRuleTags,
    sampleMatches,
    rules: sanitizedRules,
    warnings,
    requirements: {
      importExportCovered: sanitizedRules.length > 0,
      requestRewriteCovered: sampleMatches.some((sample) => sample.direction === 'request'),
      responseRewriteCovered: sampleMatches.some((sample) => sample.direction === 'response'),
      largeRuleSetCovered: sanitizedRules.length >= threshold,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `Proxy match/replace library exported ${sanitizedRules.length} rule(s), ${activeRules.length} active rule(s), ${sampleMatches.length} sample rewrite(s), and large-rule coverage=${sanitizedRules.length >= threshold}.`,
    content: JSON.stringify(packageBody, null, 2),
  };
}

export function importProxyMatchReplaceRuleLibraryPackage(rawPackage: string | { rules?: MatchReplaceRule[] } | MatchReplaceRule[]): MatchReplaceRule[] {
  const parsed = typeof rawPackage === 'string' ? JSON.parse(rawPackage) : rawPackage;
  const rules = Array.isArray(parsed) ? parsed : parsed?.rules;
  if (!Array.isArray(rules)) throw new Error('Proxy match/replace package does not contain a rules array.');
  return sanitizeMatchReplaceRules(rules);
}

export function buildWebSocketCaptureEvidencePackage(
  messages: WebSocketMessage[],
  options: WebSocketCaptureEvidenceOptions = {},
): WebSocketCaptureEvidencePackage {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const frames = messages.filter((message) => message.connectionId && message.tags?.includes('websocket'));
  const upgradeExchanges = (options.exchanges ?? []).filter((exchange) => (
    exchange.method === 'WEBSOCKET'
    && exchange.status === 101
    && exchange.tags?.includes('websocket')
  ));
  const hostCounts = countBy(frames.map((message) => message.host || 'unknown'));
  const pathCounts = countBy(frames.map((message) => message.path || 'unknown'));
  const typeCounts = countBy(frames.map((message) => message.type || 'other'));
  const directionCounts = countBy(frames.map((message) => message.direction));
  const totalPayloadBytes = frames.reduce((total, message) => total + Math.max(0, message.length ?? 0), 0);
  const connectionIds = Array.from(new Set(frames.map((message) => message.connectionId))).sort();
  const connectionSummaries = connectionIds.map((connectionId) => {
    const connectionFrames = frames.filter((message) => message.connectionId === connectionId);
    const first = connectionFrames[0];
    const last = connectionFrames[connectionFrames.length - 1] ?? first;
    return {
      connectionId,
      host: first?.host ?? 'unknown',
      path: first?.path ?? 'unknown',
      url: first?.url ?? connectionId,
      firstFrameId: first?.id ?? '',
      lastFrameId: last?.id ?? '',
      frameCount: connectionFrames.length,
      clientFrameCount: connectionFrames.filter((message) => message.direction === 'client').length,
      serverFrameCount: connectionFrames.filter((message) => message.direction === 'server').length,
      typeCounts: countBy(connectionFrames.map((message) => message.type || 'other')),
      totalPayloadBytes: connectionFrames.reduce((total, message) => total + Math.max(0, message.length ?? 0), 0),
      fullPayloadSamples: connectionFrames.slice(0, 8).map((message) => ({
        id: message.id,
        direction: message.direction,
        type: message.type,
        payload: message.payload,
        payloadEncoding: message.payloadEncoding,
        length: message.length,
        tags: message.tags,
      })),
      operationalSecretSignals: webSocketOperationalSecretSignals(connectionFrames),
    };
  });
  const operationalSecretSignals = webSocketOperationalSecretSignals(frames);
  const sampleFrames = frames.slice(0, 12).map((message) => ({
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
  }));
  const packageBody = {
    generatedAt,
    upgradeExchangeIds: upgradeExchanges.map((exchange) => exchange.id),
    connectionIds,
    directionCounts,
    typeCounts,
    hostCounts,
    pathCounts,
    operationalSecretSignals,
    reportPhaseOnlyRedaction: true,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };

  return {
    kind: 'proxyforge-websocket-capture-evidence-package',
    schemaVersion: 1,
    generatedAt,
    upgradeExchangeIds: packageBody.upgradeExchangeIds,
    connectionCount: connectionIds.length,
    frameCount: frames.length,
    clientFrameCount: directionCounts.client ?? 0,
    serverFrameCount: directionCounts.server ?? 0,
    textFrameCount: typeCounts.text ?? 0,
    binaryFrameCount: typeCounts.binary ?? 0,
    controlFrameCount: (typeCounts.close ?? 0) + (typeCounts.ping ?? 0) + (typeCounts.pong ?? 0),
    totalPayloadBytes,
    hostCounts,
    pathCounts,
    connectionSummaries,
    sampleFrames,
    operationalSecretSignals,
    requirements: {
      upgradeCaptureCovered: upgradeExchanges.length > 0,
      bidirectionalFramesCovered: (directionCounts.client ?? 0) > 0 && (directionCounts.server ?? 0) > 0,
      textAndBinaryFramesCovered: (typeCounts.text ?? 0) > 0 && (typeCounts.binary ?? 0) > 0,
      payloadBytesAccounted: frames.length > 0 && totalPayloadBytes === connectionSummaries.reduce((total, connection) => total + connection.totalPayloadBytes, 0),
      connectionGroupingCovered: connectionSummaries.length > 0 && connectionSummaries.every((connection) => connection.frameCount > 0 && connection.host !== 'unknown'),
      fullFidelityPayloadsPreserved: sampleFrames.some((frame) => frame.payload.length > 0),
      operationalSecretsPreserved: operationalSecretSignals.length > 0,
      reportPhaseOnlyRedaction: true,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `WebSocket capture package preserved ${frames.length} frame(s) across ${connectionIds.length} connection(s), ${(directionCounts.client ?? 0)} client frame(s), ${(directionCounts.server ?? 0)} server frame(s), ${totalPayloadBytes} payload byte(s), and ${operationalSecretSignals.length} operational secret signal(s).`,
    content: JSON.stringify(packageBody, null, 2),
  };
}

export function buildWebSocketInterceptReplayEvidencePackage(
  messages: WebSocketMessage[],
  options: WebSocketInterceptReplayEvidenceOptions = {},
): WebSocketInterceptReplayEvidencePackage {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const frames = messages.filter((message) => message.connectionId && message.tags?.includes('websocket'));
  const rewriteRules = sanitizeWebSocketFrameRewriteRules(options.rewriteRules ?? []);
  const activeRewriteRules = rewriteRules.filter((rule) => rule.enabled && rule.match);
  const savedReplays = (options.savedReplays ?? []).map((replay) => ({
    ...replay,
    payload: String(replay.payload ?? ''),
    tags: Array.from(new Set(['websocket', 'saved-replay', ...(replay.tags ?? [])])),
  }));
  const decisionFrames = frames.filter((message) => (
    message.tags.includes('intercepted')
    || message.tags.includes('edited')
    || message.tags.includes('dropped')
    || message.tags.includes('replayed')
    || message.tags.includes('rewritten')
    || message.tags.some((tag) => tag.startsWith('rewrite:'))
  ));
  const decisions = decisionFrames.map((message) => {
    const replayed = message.tags.includes('replayed');
    const dropped = message.tags.includes('dropped');
    return {
      frameId: message.id,
      connectionId: message.connectionId,
      direction: message.direction,
      action: (replayed ? 'replay' : dropped ? 'drop' : 'forward') as 'forward' | 'drop' | 'replay',
      edited: message.tags.includes('edited'),
      replayed,
      rewritten: message.tags.includes('rewritten') || message.tags.some((tag) => tag.startsWith('rewrite:')),
      type: message.type,
      payload: message.payload,
      payloadEncoding: message.payloadEncoding,
      length: message.length,
      tags: message.tags,
    };
  });
  const decisionPayloads = decisions
    .filter((decision) => decision.payloadEncoding !== 'hex')
    .map((decision) => decision.payload);
  const savedPayloads = savedReplays
    .filter((replay) => replay.payloadEncoding !== 'hex')
    .map((replay) => replay.payload);
  const operationalSecretSignals = webSocketPayloadSecretSignals([...decisionPayloads, ...savedPayloads]);
  const fullPayloadSamples = [
    ...decisions.slice(0, 8).map((decision) => ({
      source: 'decision' as const,
      id: decision.frameId,
      direction: decision.direction,
      payload: decision.payload,
      payloadEncoding: decision.payloadEncoding,
      tags: decision.tags,
    })),
    ...savedReplays.slice(0, 4).map((replay) => ({
      source: 'saved-replay' as const,
      id: replay.id,
      direction: replay.direction,
      payload: replay.payload,
      payloadEncoding: replay.payloadEncoding,
      tags: replay.tags,
    })),
  ];
  const actionCounts = countBy(decisions.map((decision) => decision.action));
  const directionCounts = countBy(decisionFrames.map((message) => message.direction));
  const packageBody = {
    generatedAt,
    decisionFrameIds: decisions.map((decision) => decision.frameId),
    savedReplayIds: savedReplays.map((replay) => replay.id),
    rewriteRuleIds: rewriteRules.map((rule) => rule.id),
    actionCounts,
    directionCounts,
    operationalSecretSignals,
    reportPhaseOnlyRedaction: true,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };

  return {
    kind: 'proxyforge-websocket-intercept-rewrite-replay-evidence-package',
    schemaVersion: 1,
    generatedAt,
    frameCount: frames.length,
    interceptedFrameCount: decisionFrames.filter((message) => message.tags.includes('intercepted') || message.tags.includes('edited') || message.tags.includes('dropped')).length,
    editedFrameCount: decisionFrames.filter((message) => message.tags.includes('edited')).length,
    droppedFrameCount: decisionFrames.filter((message) => message.tags.includes('dropped')).length,
    replayedFrameCount: decisionFrames.filter((message) => message.tags.includes('replayed')).length,
    rewrittenFrameCount: decisionFrames.filter((message) => message.tags.includes('rewritten') || message.tags.some((tag) => tag.startsWith('rewrite:'))).length,
    savedReplayCount: savedReplays.length,
    rewriteRuleCount: rewriteRules.length,
    activeRewriteRuleCount: activeRewriteRules.length,
    directionCounts,
    actionCounts,
    decisions,
    rewriteRules,
    savedReplays,
    fullPayloadSamples,
    operationalSecretSignals,
    requirements: {
      clientInterceptCovered: decisionFrames.some((message) => message.direction === 'client' && (message.tags.includes('edited') || message.tags.includes('intercepted') || message.tags.includes('dropped'))),
      serverInterceptCovered: decisionFrames.some((message) => message.direction === 'server' && (message.tags.includes('intercepted') || message.tags.includes('edited') || message.tags.includes('dropped'))),
      editForwardCovered: decisions.some((decision) => decision.edited && decision.action === 'forward'),
      dropCovered: decisions.some((decision) => decision.action === 'drop'),
      liveReplayCovered: decisions.some((decision) => decision.replayed && decision.action === 'replay'),
      savedReplayCovered: savedReplays.length > 0,
      rewriteRulesCovered: activeRewriteRules.length > 0,
      rewrittenReplayCovered: decisions.some((decision) => decision.replayed && decision.rewritten),
      fullFidelityPayloadsPreserved: fullPayloadSamples.some((sample) => sample.payload.length > 0),
      operationalSecretsPreserved: operationalSecretSignals.length > 0,
      reportPhaseOnlyRedaction: true,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `WebSocket intercept/replay package preserved ${decisions.length} decision frame(s), ${actionCounts.drop ?? 0} drop(s), ${actionCounts.forward ?? 0} forward(s), ${actionCounts.replay ?? 0} live replay(s), ${savedReplays.length} saved replay(s), and ${activeRewriteRules.length} active rewrite rule(s).`,
    content: JSON.stringify(packageBody, null, 2),
  };
}

export function buildWebSocketStateTranscriptEvidencePackage(
  options: WebSocketStateTranscriptEvidenceOptions = {},
): WebSocketStateTranscriptEvidencePackage {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const graphs = options.graphs ?? [];
  const graphExports = options.graphExports ?? [];
  const clusters = options.clusters ?? [];
  const transcripts = options.transcripts ?? [];
  const restoredFrames = options.restoredFrames ?? [];
  const filtersApplied = Array.from(new Set(options.filtersApplied ?? [])).sort();
  const largeTranscriptFrameThreshold = options.largeTranscriptFrameThreshold ?? 50;
  const transcriptPayloads = transcripts.map((transcript) => transcript.content);
  const restoredPayloads = restoredFrames
    .filter((frame) => frame.payloadEncoding !== 'hex')
    .map((frame) => frame.payload);
  const operationalSecretSignals = webSocketPayloadSecretSignals([...transcriptPayloads, ...restoredPayloads]);
  const largeTranscriptFrameCount = restoredFrames.filter((frame) => (
    restoredFrames.filter((candidate) => candidate.transcriptId === frame.transcriptId).length >= largeTranscriptFrameThreshold
  )).length;
  const stateGraphSummaries = graphs.map((graph) => ({
    graphId: graph.id,
    connectionId: graph.connectionId,
    host: graph.host,
    path: graph.path,
    nodeCount: graph.nodes.length,
    edgeCount: graph.edges.length,
    totalNodeCount: graph.totalNodeCount,
    totalEdgeCount: graph.totalEdgeCount,
    truncatedNodeCount: graph.truncatedNodeCount,
    truncatedEdgeCount: graph.truncatedEdgeCount,
    privilegedNodeCount: graph.nodes.filter((node) => node.kind === 'privileged').length,
    closeNodeCount: graph.nodes.filter((node) => node.kind === 'close').length,
    privilegedEdgeCount: graph.edges.filter((edge) => edge.kind === 'privileged').length,
    summary: graph.summary,
  }));
  const fullPayloadSamples = [
    ...transcripts.slice(0, 4).map((transcript) => ({
      source: 'transcript' as const,
      id: transcript.id,
      payload: transcript.content,
      payloadEncoding: 'text' as WebSocketMessage['payloadEncoding'],
      tags: ['websocket', 'transcript-export', transcript.format],
    })),
    ...restoredFrames.slice(0, 8).map((frame) => ({
      source: 'restored-frame' as const,
      id: frame.id,
      payload: frame.payload,
      payloadEncoding: frame.payloadEncoding,
      tags: frame.tags,
    })),
  ];
  const packageBody = {
    generatedAt,
    graphIds: graphs.map((graph) => graph.id),
    graphExportIds: graphExports.map((artifact) => artifact.id),
    clusterIds: clusters.map((cluster) => cluster.id),
    transcriptIds: transcripts.map((transcript) => transcript.id),
    restoredFrameIds: restoredFrames.map((frame) => frame.id),
    filtersApplied,
    largeTranscriptFrameThreshold,
    operationalSecretSignals,
    reportPhaseOnlyRedaction: true,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
  };

  return {
    kind: 'proxyforge-websocket-state-transcript-evidence-package',
    schemaVersion: 1,
    generatedAt,
    graphCount: graphs.length,
    graphExportCount: graphExports.length,
    clusterCount: clusters.length,
    transcriptExportCount: transcripts.length,
    restoredFrameCount: restoredFrames.length,
    largeTranscriptFrameCount,
    filtersApplied,
    stateGraphSummaries,
    graphExports,
    connectionClusters: clusters,
    transcriptExports: transcripts,
    restoredFrames,
    fullPayloadSamples,
    operationalSecretSignals,
    requirements: {
      stateGraphCovered: graphs.length > 0 && graphs.some((graph) => graph.nodes.length > 0 && graph.edges.length > 0),
      graphFilterCovered: filtersApplied.length >= 2 || graphs.some((graph) => /filtered|privileged|close|added/i.test(graph.summary)),
      graphExportCovered: graphExports.length > 0 && graphExports.some((artifact) => artifact.sizeBytes > 0 && (artifact.content ?? artifact.fileName).length > 0),
      truncationMetadataCovered: graphs.some((graph) => graph.truncatedNodeCount > 0 || graph.truncatedEdgeCount > 0)
        || graphExports.some((artifact) => (artifact.truncatedNodeCount ?? 0) > 0 || (artifact.truncatedEdgeCount ?? 0) > 0),
      connectionClusteringCovered: clusters.length > 0 && clusters.some((cluster) => cluster.connectionCount > 0 && cluster.frameCount > 0),
      transcriptJsonExportCovered: transcripts.some((transcript) => transcript.format === 'json' && /proxyforge-websocket-transcript/i.test(transcript.content)),
      transcriptMarkdownExportCovered: transcripts.some((transcript) => transcript.format === 'markdown' && /^#\s+/m.test(transcript.content)),
      transcriptImportRestoreCovered: restoredFrames.length > 0 && restoredFrames.every((frame) => frame.tags.includes('restored-transcript') || frame.originalFrameId),
      largeTranscriptRestoreCovered: largeTranscriptFrameCount >= largeTranscriptFrameThreshold,
      fullFidelityPayloadsPreserved: fullPayloadSamples.some((sample) => sample.payload.length > 0),
      operationalSecretsPreserved: operationalSecretSignals.length > 0,
      reportPhaseOnlyRedaction: true,
    },
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `WebSocket state/transcript package preserved ${graphs.length} state graph(s), ${graphExports.length} graph export(s), ${clusters.length} connection cluster(s), ${transcripts.length} transcript export(s), and ${restoredFrames.length} restored frame(s).`,
    content: JSON.stringify(packageBody, null, 2),
  };
}

function buildIntruderPayloadTransformationMatrix(
  request: Pick<IntruderAttackRequest, 'payloads' | 'payloadSets' | 'payloadProcessors' | 'payloadRules'>,
): IntruderPayloadTransformationMatrix {
  const processors = request.payloadProcessors ?? [];
  const rules = sanitizeIntruderPayloadRules(request.payloadRules);
  const inputSets = request.payloadSets?.length ? request.payloadSets : [request.payloads ?? []];
  const expandedSets = normalizeIntruderPayloadSets(request as IntruderAttackRequest);
  const warnings: string[] = [];
  if (!inputSets.some((set) => set?.length)) warnings.push('No payload values supplied.');
  if (expandedSets.some((set) => set.length >= INTRUDER_MAX_PAYLOAD_VALUES)) warnings.push(`One or more payload sets reached the ${INTRUDER_MAX_PAYLOAD_VALUES} value cap.`);
  return {
    processors,
    rules,
    inputSetCount: inputSets.length,
    inputPayloadCounts: inputSets.map((set) => set?.length ?? 0),
    expandedPayloadCounts: expandedSets.map((set) => set.length),
    sampleExpandedPayloads: expandedSets.map((set) => set.slice(0, 8)),
    warnings,
  };
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
  const allowed = new Set<IntruderPayloadRuleId>(['case-variants', 'url-recursive', 'path-depth', 'delimiter-variants', 'extension-bypass', 'null-byte']);
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
    if (rules.includes('delimiter-variants')) {
      values.add(payload.replace(/[\s/\\]+/g, '-'));
      values.add(payload.replace(/[\s/\\]+/g, '_'));
      values.add(payload.replace(/[\s/\\]+/g, '.'));
      values.add(payload.replace(/[\s/\\]+/g, '/'));
      values.add(payload.replace(/[\s/\\]+/g, '%2f'));
    }
    if (rules.includes('extension-bypass')) {
      const normalized = payload.replace(/[/.]+$/g, '');
      values.add(`${normalized}.json`);
      values.add(`${normalized}.bak`);
      values.add(`${normalized};`);
      values.add(`${normalized}/.`);
    }
    if (rules.includes('null-byte')) {
      values.add(`${payload}%00`);
      values.add(`${payload}\\u0000`);
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
    if (processor === 'double-url-encode') return encodeURIComponent(encodeURIComponent(next));
    if (processor === 'base64') return Buffer.from(next, 'utf8').toString('base64');
    if (processor === 'html-encode') return htmlEncodePayload(next);
    if (processor === 'json-escape') return JSON.stringify(next).slice(1, -1);
    if (processor === 'hex-encode') return Buffer.from(next, 'utf8').toString('hex');
    if (processor === 'uppercase') return next.toUpperCase();
    if (processor === 'lowercase') return next.toLowerCase();
    return next;
  }, payload);
}

function htmlEncodePayload(payload: string) {
  return payload.replace(/[&<>"']/g, (char) => {
    if (char === '&') return '&amp;';
    if (char === '<') return '&lt;';
    if (char === '>') return '&gt;';
    if (char === '"') return '&quot;';
    return '&#39;';
  });
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

function sanitizeIntruderOastPayloads(payloads: IntruderOastPayloadReference[] = []) {
  const seen = new Set<string>();
  const cleanPayloads: IntruderOastPayloadReference[] = [];
  for (const payload of payloads) {
    const id = payload.id?.trim();
    const token = payload.token?.trim();
    const endpoint = payload.endpoint?.trim();
    if (!id || !token || !endpoint || seen.has(id)) continue;
    seen.add(id);
    cleanPayloads.push({
      id,
      token,
      endpoint,
      ...(payload.label?.trim() ? { label: payload.label.trim() } : {}),
      ...(payload.protocol ? { protocol: payload.protocol } : {}),
    });
  }
  return cleanPayloads.slice(0, 500);
}

function sanitizeIntruderOastInteractions(interactions: IntruderOastInteractionReference[] = []) {
  const seen = new Set<string>();
  return interactions
    .map((interaction) => ({
      ...interaction,
      id: interaction.id?.trim(),
      payloadId: interaction.payloadId?.trim() || 'unmatched',
      protocol: interaction.protocol?.trim() || 'http',
      raw: interaction.raw,
    }))
    .filter((interaction): interaction is IntruderOastInteractionReference => Boolean(interaction.id))
    .filter((interaction) => {
      if (seen.has(interaction.id)) return false;
      seen.add(interaction.id);
      return true;
    });
}

function matchIntruderOastPayloads(raw: string, payloads: IntruderOastPayloadReference[]) {
  return payloads.filter((payload) => intruderOastTextMatchesPayload(raw, payload));
}

function intruderOastTextMatchesPayload(raw: string, payload: IntruderOastPayloadReference) {
  return Boolean(raw && (
    raw.includes(payload.id)
    || raw.includes(payload.token)
    || raw.includes(payload.endpoint)
    || raw.includes(encodeURIComponent(payload.endpoint))
  ));
}

function intruderInteractionRaw(interaction: IntruderOastInteractionReference) {
  return Buffer.isBuffer(interaction.raw) ? interaction.raw.toString('utf8') : String(interaction.raw ?? '');
}

function buildIntruderOastSummary(
  payloads: IntruderOastPayloadReference[],
  interactions: IntruderOastInteractionReference[],
  results: IntruderAttackResult[],
): IntruderOastCorrelationSummary {
  const payloadIds = new Set(payloads.map((payload) => payload.id));
  const matchedInteractions = interactions.filter((interaction) => payloadIds.has(interaction.payloadId));
  const resultRows = results.filter((result) => (result.oastPayloadIds?.length ?? 0) > 0 || (result.callbackInteractionIds?.length ?? 0) > 0);
  const correlatedInteractionIds = new Set(resultRows.flatMap((result) => result.callbackInteractionIds ?? []));
  const observedPayloadIds = new Set(matchedInteractions.map((interaction) => interaction.payloadId));
  return {
    payloadCount: payloads.length,
    interactionCount: interactions.length,
    correlatedResultCount: resultRows.filter((result) => (result.callbackInteractionIds?.length ?? 0) > 0).length,
    correlatedInteractionCount: correlatedInteractionIds.size,
    pendingPayloadIds: payloads.map((payload) => payload.id).filter((id) => !observedPayloadIds.has(id)),
  };
}

function replaceIntruderMarkersByPosition(rawRequest: string, payloads: string[]) {
  let index = 0;
  return rawRequest.replace(/§([^§]*)§/g, (_match, label: string) => payloads[index++] ?? label ?? '');
}

function markerDefault(rawRequest: string, targetIndex: number) {
  let index = 0;
  let value = 'baseline';
  rawRequest.replace(/§([^§]*)§/g, (_match, label: string) => {
    if (index === targetIndex) value = label || 'baseline';
    index += 1;
    return _match;
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

function intruderModeSemantics(mode: IntruderAttackMode) {
  if (mode === 'battering-ram') return 'Each payload from the first set is placed into every marked position in the same request.';
  if (mode === 'pitchfork') return 'Payload sets advance in lockstep, one payload per marked position per request.';
  if (mode === 'cluster-bomb') return 'Payload sets are combined as a Cartesian product across marked positions.';
  return 'Each marked position is attacked one at a time while other positions keep their marker defaults.';
}

function intruderModeWarnings(mode: IntruderAttackMode, payloadPositions: number, payloadSets: string[][]) {
  const warnings: string[] = [];
  if (payloadPositions === 0) warnings.push('No explicit payload markers found; the first payload set will be replayed without marker substitution.');
  if ((mode === 'pitchfork' || mode === 'cluster-bomb') && payloadPositions > payloadSets.length) {
    warnings.push('Fewer payload sets than marked positions; later positions reuse the last payload set.');
  }
  if (mode === 'cluster-bomb') {
    const product = Array.from({ length: Math.max(payloadPositions, 1) }, (_unused, index) => payloadSets[Math.min(index, payloadSets.length - 1)]?.length ?? 0)
      .reduce((total, count) => total * Math.max(count, 0), 1);
    if (product > INTRUDER_MAX_PAYLOAD_PLANS) warnings.push(`Cartesian product was capped at ${INTRUDER_MAX_PAYLOAD_PLANS} request plans.`);
  }
  return warnings;
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

function estimateIntruderResultBytes(result: IntruderAttackResult) {
  return 512
    + Buffer.byteLength(result.payload, 'utf8')
    + Buffer.byteLength(result.payloads.join('\n'), 'utf8')
    + Buffer.byteLength(result.notes, 'utf8')
    + Buffer.byteLength(result.requestRaw, 'utf8')
    + Buffer.byteLength(result.responseRaw, 'utf8')
    + Buffer.byteLength(result.tags.join('\n'), 'utf8');
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
}): IntruderStreamingSummary {
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

function buildIntruderComparisonEvidence(summary: IntruderAttackSummary): IntruderGrepExtractComparisonPackage['comparisons'] {
  const [baseline, ...candidates] = summary.results;
  if (!baseline) return [];
  return candidates
    .map((candidate, index) => {
      const grepDelta = diffIntruderStringSets(baseline.grepMatches, candidate.grepMatches);
      const extractDelta = diffIntruderStringSets(baseline.extractMatches, candidate.extractMatches);
      const statusDelta = candidate.status - baseline.status;
      const lengthDelta = candidate.length - baseline.length;
      const timingDelta = candidate.timing - baseline.timing;
      const verdict = intruderComparisonVerdict(candidate, statusDelta, lengthDelta, timingDelta, grepDelta, extractDelta);
      return {
        id: `intruder-comparison-${summary.id}-${index + 1}`,
        baselineResultId: baseline.id,
        candidateResultId: candidate.id,
        baselinePayload: baseline.payload,
        candidatePayload: candidate.payload,
        statusDelta,
        lengthDelta,
        timingDelta,
        grepDelta,
        extractDelta,
        verdict,
        notes: `${candidate.payload} compared to ${baseline.payload}: status ${formatSignedDelta(statusDelta)}, length ${formatSignedDelta(lengthDelta)}, timing ${formatSignedDelta(timingDelta)}ms`,
      };
    })
    .sort((a, b) => intruderComparisonScore(b) - intruderComparisonScore(a));
}

function buildIntruderClusterRankingEvidence(summary: IntruderAttackSummary): {
  clusters: IntruderGrepExtractComparisonPackage['clusters'];
  rankings: IntruderGrepExtractComparisonPackage['rankings'];
} {
  if (summary.results.length === 0) return { clusters: [], rankings: [] };
  const averageLength = meanIntruderNumber(summary.results.map((result) => result.length));
  const lengthStdDev = standardIntruderDeviation(summary.results.map((result) => result.length), averageLength);
  const averageTiming = meanIntruderNumber(summary.results.map((result) => result.timing));
  const timingStdDev = standardIntruderDeviation(summary.results.map((result) => result.timing), averageTiming);
  const statusCounts = new Map<number, number>();
  for (const result of summary.results) statusCounts.set(result.status, (statusCounts.get(result.status) ?? 0) + 1);

  const rankings = summary.results
    .map((result) => {
      const lengthZScore = zScoreIntruder(result.length, averageLength, lengthStdDev);
      const timingZScore = zScoreIntruder(result.timing, averageTiming, timingStdDev);
      const statusRarity = 1 - ((statusCounts.get(result.status) ?? 0) / summary.results.length);
      const grepSignalCount = result.grepMatches.length;
      const extractSignalCount = result.extractMatches.length;
      const regressionBoost = result.status >= 500 ? 2 : result.status >= 400 ? 1.25 : 0;
      const signalBoost = (grepSignalCount + extractSignalCount) * 0.6;
      const score = Number((Math.abs(lengthZScore) + Math.abs(timingZScore) + statusRarity * 4 + regressionBoost + signalBoost).toFixed(2));
      const verdict = result.status >= 500 ? 'regression' as const : score >= 1.5 || grepSignalCount > 0 || extractSignalCount > 0 ? 'interesting' as const : 'similar' as const;
      const reasons = [
        statusRarity >= 0.5 ? `rare status ${result.status}` : '',
        Math.abs(lengthZScore) >= 1 ? `length z ${lengthZScore.toFixed(2)}` : '',
        Math.abs(timingZScore) >= 1 ? `timing z ${timingZScore.toFixed(2)}` : '',
        grepSignalCount ? `${grepSignalCount} grep signal${grepSignalCount === 1 ? '' : 's'}` : '',
        extractSignalCount ? `${extractSignalCount} extract signal${extractSignalCount === 1 ? '' : 's'}` : '',
      ].filter(Boolean);
      return {
        id: `intruder-ranking-${summary.id}-${result.id}`,
        resultId: result.id,
        payload: result.payload,
        rank: 0,
        score,
        verdict,
        status: result.status,
        length: result.length,
        timing: result.timing,
        lengthZScore,
        timingZScore,
        statusRarity,
        grepSignalCount,
        extractSignalCount,
        reasons,
      };
    })
    .sort((a, b) => b.score - a.score)
    .map((ranking, index) => ({ ...ranking, rank: index + 1 }));

  const clusterMap = new Map<string, IntruderAttackResult[]>();
  for (const result of summary.results) {
    const signature = [
      result.status,
      result.mime,
      result.grepMatches.length ? result.grepMatches.slice().sort().join('|') : 'no-grep',
      result.extractMatches.length ? 'extract' : 'no-extract',
      Math.round(result.length / 128) * 128,
    ].join(':');
    clusterMap.set(signature, [...(clusterMap.get(signature) ?? []), result]);
  }
  const clusters = Array.from(clusterMap.entries()).map(([signature, results], index) => {
    const representative = results.slice().sort((a, b) => intruderRankingScoreForResult(rankings, b.id) - intruderRankingScoreForResult(rankings, a.id))[0] ?? results[0];
    const relatedRanking = rankings.find((ranking) => ranking.resultId === representative.id);
    return {
      id: `intruder-cluster-${summary.id}-${index + 1}`,
      title: `${results.length} result${results.length === 1 ? '' : 's'} with ${representative.status} ${representative.mime}`,
      signature,
      verdict: relatedRanking?.verdict ?? 'similar',
      status: representative.status,
      mime: representative.mime,
      resultCount: results.length,
      representativeResultId: representative.id,
      payloads: results.map((result) => result.payload).slice(0, 12),
      averageLength: Math.round(meanIntruderNumber(results.map((result) => result.length))),
      averageTiming: Math.round(meanIntruderNumber(results.map((result) => result.timing))),
      grepSignals: Array.from(new Set(results.flatMap((result) => result.grepMatches))).sort(),
      extractSignals: Array.from(new Set(results.flatMap((result) => result.extractMatches))).sort(),
      notes: `Cluster ${signature} keeps ${results.length} retained result(s) with representative payload ${representative.payload}.`,
    };
  }).sort((a, b) => b.resultCount - a.resultCount || intruderClusterVerdictWeight(b.verdict) - intruderClusterVerdictWeight(a.verdict));

  return { clusters, rankings };
}

function intruderOperationalSecretSignals(...values: string[]) {
  const text = values.join('\n');
  return Array.from(new Set([
    /authorization:/i.test(text) ? 'authorization-header' : '',
    /cookie:/i.test(text) ? 'cookie-header' : '',
    /x-api-key:/i.test(text) ? 'x-api-key-header' : '',
    /bearer\s+[a-z0-9._-]+/i.test(text) ? 'bearer-token' : '',
    /session=|token|secret|api[-_ ]?key/i.test(text) ? 'secret-like-material' : '',
  ].filter(Boolean))).sort();
}

function diffIntruderStringSets(left: string[], right: string[]) {
  const leftSet = new Set(left);
  const rightSet = new Set(right);
  return [
    ...right.filter((value) => !leftSet.has(value)).map((value) => `+${value}`),
    ...left.filter((value) => !rightSet.has(value)).map((value) => `-${value}`),
  ];
}

function intruderComparisonVerdict(
  result: IntruderAttackResult,
  statusDelta: number,
  lengthDelta: number,
  timingDelta: number,
  grepDelta: string[],
  extractDelta: string[],
): 'interesting' | 'similar' | 'regression' {
  if (result.status >= 500 || statusDelta >= 500) return 'regression';
  if (statusDelta !== 0 || Math.abs(lengthDelta) > 64 || Math.abs(timingDelta) > 250 || grepDelta.length > 0 || extractDelta.length > 0) return 'interesting';
  return 'similar';
}

function intruderComparisonScore(comparison: IntruderGrepExtractComparisonPackage['comparisons'][number]) {
  return Math.abs(comparison.statusDelta) * 10
    + Math.abs(comparison.lengthDelta)
    + Math.abs(comparison.timingDelta) / 10
    + comparison.grepDelta.length * 50
    + comparison.extractDelta.length * 35
    + (comparison.verdict === 'regression' ? 1000 : comparison.verdict === 'interesting' ? 100 : 0);
}

function intruderRankingScoreForResult(rankings: IntruderGrepExtractComparisonPackage['rankings'], resultId: string) {
  return rankings.find((ranking) => ranking.resultId === resultId)?.score ?? 0;
}

function intruderClusterVerdictWeight(verdict: 'interesting' | 'similar' | 'regression') {
  if (verdict === 'regression') return 2;
  if (verdict === 'interesting') return 1;
  return 0;
}

function meanIntruderNumber(values: number[]) {
  if (values.length === 0) return 0;
  return values.reduce((total, value) => total + value, 0) / values.length;
}

function standardIntruderDeviation(values: number[], average = meanIntruderNumber(values)) {
  if (values.length <= 1) return 0;
  const variance = values.reduce((total, value) => total + (value - average) ** 2, 0) / values.length;
  return Math.sqrt(variance);
}

function zScoreIntruder(value: number, average: number, stdDev: number) {
  if (!Number.isFinite(stdDev) || stdDev === 0) return 0;
  return Number(((value - average) / stdDev).toFixed(2));
}

function formatSignedDelta(value: number) {
  if (value > 0) return `+${value}`;
  return String(value);
}

export function buildActiveScanCheckPackEvidencePackage(
  request: ActiveScanRequest,
  summary: ActiveScanSummary,
  options: {
    blockedSummary?: ActiveScanSummary;
    checkPacks?: ActiveScanCheckPackDefinition[];
    generatedAt?: string;
  } = {},
): ActiveScanCheckPackEvidencePackage {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const requestedChecks = sanitizeActiveScanChecks(request.checks);
  const executedChecks = activeScanExecutedChecks(summary);
  const checkPacks = options.checkPacks?.length ? options.checkPacks : [{
    id: 'custom-active-scan-pack',
    name: 'Custom active scan pack',
    checks: request.checks,
    source: 'request',
  }];
  const checkPackMatrix = checkPacks.map((pack) => {
    const supportedChecks = sanitizeActiveScanChecks(pack.checks as ActiveScanCheckId[]);
    const supportedSet = new Set(supportedChecks);
    return {
      id: pack.id,
      name: pack.name,
      source: pack.source ?? 'operator',
      requestedChecks: pack.checks,
      supportedChecks,
      unsupportedChecks: pack.checks.filter((check) => !isActiveScanCheckId(check)),
      selectedSupportedChecks: requestedChecks.filter((check) => supportedSet.has(check)),
    };
  });
  const rawProbeSamples = summary.exchanges.slice(0, 14).map((exchange) => ({
    id: exchange.id,
    method: exchange.method,
    host: exchange.host,
    path: exchange.path,
    status: exchange.status,
    requestRaw: exchange.requestRaw,
    responseRaw: exchange.responseRaw,
    tags: exchange.tags,
  }));
  const operationalSecretSignals = activeScanOperationalSecretSignals(rawProbeSamples.flatMap((sample) => [
    sample.requestRaw,
    sample.responseRaw,
  ]));
  const checkCoverage = ACTIVE_SCAN_BUILT_IN_CHECKS.map((checkId) => {
    const exchangeIds = summary.exchanges
      .filter((exchange) => exchange.tags.includes(`check:${checkId}`))
      .map((exchange) => exchange.id);
    return {
      checkId,
      label: activeScanCheckLabel(checkId),
      requested: requestedChecks.includes(checkId),
      executed: executedChecks.includes(checkId),
      exchangeIds,
      findingIds: summary.findings.filter((finding) => finding.checkId === checkId).map((finding) => finding.id),
      suppressedFindingIds: summary.suppressedFindings.filter((finding) => finding.checkId === checkId).map((finding) => finding.id),
    };
  });
  const scopeGate = {
    blockedOutOfScope: Boolean(options.blockedSummary?.blocked && options.blockedSummary.totalRequests === 0),
    blockedMessage: options.blockedSummary?.message,
  };
  const allowedRequestBudget = request.maxRequests + (requestedChecks.includes('authz-diff') ? 1 : 0);
  const requirements = {
    scopeGateBlocksOutOfScope: scopeGate.blockedOutOfScope,
    allBuiltInChecksCovered: ACTIVE_SCAN_BUILT_IN_CHECKS.every((check) => (
      requestedChecks.includes(check) && executedChecks.includes(check)
    )),
    checkPackExpansionCovered: checkPackMatrix.some((pack) => (
      pack.supportedChecks.length >= 2 && pack.selectedSupportedChecks.length >= 2
    )),
    rateAndCapControlsRecorded: request.throttleMs >= 0
      && request.maxRequests > 0
      && request.maxRequests <= 25
      && summary.totalRequests <= allowedRequestBudget,
    authzTwoLegComparisonCovered: summary.exchanges.some((exchange) => exchange.tags.includes('auth-state:baseline'))
      && summary.exchanges.some((exchange) => exchange.tags.includes('auth-state:low-privilege')),
    findingDedupeConfidenceCovered: summary.findings.length > 0
      && summary.findings.every((finding) => Boolean(finding.dedupeKey && finding.confidenceReason)),
    falsePositiveTuningCovered: summary.tuning.falsePositiveControls.length > 0
      && summary.tuning.falsePositiveControls.includes('preserve-confidence-reason-per-finding'),
    rawProbeExchangesPreserved: rawProbeSamples.some((sample) => sample.requestRaw.trim() && sample.responseRaw.trim()),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-active-scan-check-pack-evidence-package',
    schemaVersion: 1,
    generatedAt,
    targetUrl: request.targetUrl,
    requestedChecks,
    executedChecks,
    checkPackMatrix,
    checkCoverage,
    scopeGate,
    tuning: summary.tuning,
    findingCount: summary.findings.length,
    suppressedFindingCount: summary.suppressedFindings.length,
    rawProbeSamples,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  return {
    kind: 'proxyforge-active-scan-check-pack-evidence-package',
    schemaVersion: 1,
    generatedAt,
    targetUrl: request.targetUrl,
    scopeAllowlist: request.scopeAllowlist,
    throttleMs: request.throttleMs,
    maxRequests: request.maxRequests,
    requestedChecks,
    executedChecks,
    checkPackMatrix,
    checkCoverage,
    scopeGate,
    rawProbeSamples,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `Active Scanner check-pack evidence covered ${executedChecks.length}/${ACTIVE_SCAN_BUILT_IN_CHECKS.length} built-in check families, ${summary.totalRequests} raw probe exchange(s), ${summary.findings.length} retained finding(s), ${summary.suppressedFindings.length} suppressed signal(s), ${operationalSecretSignals.length} operational secret signal(s), and report-export-only redaction.`,
    content: JSON.stringify(body, null, 2),
  };
}

export function buildCrawlAuditInsertionEvidencePackage(
  request: CrawlAuditRequest,
  summary: CrawlAuditSummary,
  options: {
    blockedSummary?: CrawlAuditSummary;
    generatedAt?: string;
  } = {},
): CrawlAuditInsertionEvidencePackage {
  const generatedAt = options.generatedAt ?? new Date().toISOString();
  const validInsertionPoints = request.insertionPoints.filter((point) => Boolean(safeParseUrl(point.url)));
  const uniquePoints = uniqueInsertionPoints(request.insertionPoints);
  const scopedInsertionPoints = uniquePoints.filter((point) => {
    const target = safeParseUrl(point.url);
    return Boolean(target && isAllowedHost(target.hostname, request.scopeAllowlist));
  });
  const auditedKeys = new Set(summary.exchanges.flatMap((exchange) => {
    const type = exchange.tags.find((tag) => tag.startsWith('insertion:'))?.replace(/^insertion:/, '');
    const name = exchange.tags.find((tag) => tag.startsWith('insertion-name:'))?.replace(/^insertion-name:/, '');
    return type && name ? [`${type}:${name}`] : [];
  }));
  const auditedInsertionPoints = scopedInsertionPoints
    .filter((point) => auditedKeys.has(`${point.type}:${point.name}`))
    .map((point) => {
      const pointExchangeIds = summary.exchanges
        .filter((exchange) => exchange.tags.includes(`insertion:${point.type}`) && exchange.tags.includes(`insertion-name:${point.name}`))
        .map((exchange) => exchange.id);
      const pointExchangeIdSet = new Set(pointExchangeIds);
      return {
        type: point.type,
        name: point.name,
        method: point.method,
        url: point.url,
        evidence: point.evidence,
        exchangeIds: pointExchangeIds,
        findingIds: summary.findings
          .filter((finding) => finding.evidenceExchangeId && pointExchangeIdSet.has(finding.evidenceExchangeId))
          .map((finding) => finding.id),
      };
    });
  const checkCoverage = sanitizeActiveScanChecks(request.checks).map((checkId) => ({
    checkId,
    exchangeIds: summary.exchanges
      .filter((exchange) => exchange.tags.includes(`check:${checkId}`))
      .map((exchange) => exchange.id),
    findingIds: summary.findings.filter((finding) => finding.checkId === checkId).map((finding) => finding.id),
    suppressedFindingIds: summary.suppressedFindings.filter((finding) => finding.checkId === checkId).map((finding) => finding.id),
  }));
  const rawProbeSamples = summary.exchanges.slice(0, 16).map((exchange) => ({
    id: exchange.id,
    method: exchange.method,
    host: exchange.host,
    path: exchange.path,
    status: exchange.status,
    requestRaw: exchange.requestRaw,
    responseRaw: exchange.responseRaw,
    tags: exchange.tags,
  }));
  const operationalSecretSignals = activeScanOperationalSecretSignals(rawProbeSamples.flatMap((sample) => [
    sample.requestRaw,
    sample.responseRaw,
  ]));
  const insertionTypeCounts = countBy(auditedInsertionPoints.map((point) => point.type));
  const duplicateMergedCount = Math.max(0, validInsertionPoints.length - uniquePoints.length);
  const outOfScopeSkippedCount = Math.max(0, uniquePoints.length - scopedInsertionPoints.length);
  const scopeGate = {
    blockedOutOfScope: Boolean(options.blockedSummary?.blocked && options.blockedSummary.auditedInsertionPoints === 0),
    blockedMessage: options.blockedSummary?.message,
  };
  const requirements = {
    crawlerInsertionPointsLinked: request.insertionPoints.length > 0 && auditedInsertionPoints.length > 0,
    scopeGateBlocksOutOfScope: scopeGate.blockedOutOfScope,
    queryFormPathCoverage: ['query', 'form', 'path'].every((type) => (insertionTypeCounts[type] ?? 0) > 0),
    duplicateAndOutOfScopeReviewCovered: duplicateMergedCount > 0 && outOfScopeSkippedCount > 0,
    activeScannerHandoffCovered: summary.exchanges.length > 0
      && summary.exchanges.every((exchange) => exchange.source === 'scanner' && exchange.tags.includes('crawl-audit') && exchange.tags.includes('active-scan')),
    rateAndCapControlsRecorded: request.throttleMs >= 0
      && request.maxInsertionPoints > 0
      && summary.auditedInsertionPoints <= request.maxInsertionPoints
      && summary.totalRequests <= summary.auditedInsertionPoints * Math.max(1, sanitizeActiveScanChecks(request.checks).length + 1),
    findingDedupeConfidenceCovered: summary.findings.length > 0
      && summary.findings.every((finding) => Boolean(finding.dedupeKey && finding.confidenceReason && finding.evidenceExchangeId)),
    falsePositiveTuningCovered: summary.tuning.falsePositiveControls.length > 0,
    rawProbeExchangesPreserved: rawProbeSamples.some((sample) => sample.requestRaw.trim() && sample.responseRaw.trim()),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-crawl-audit-insertion-evidence-package',
    schemaVersion: 1,
    generatedAt,
    requestedInsertionPointCount: request.insertionPoints.length,
    scopedInsertionPointCount: scopedInsertionPoints.length,
    auditedInsertionPointCount: summary.auditedInsertionPoints,
    duplicateMergedCount,
    outOfScopeSkippedCount,
    insertionTypeCounts,
    auditedInsertionPoints,
    checkCoverage,
    scopeGate,
    tuning: summary.tuning,
    rawProbeSamples,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
  };
  return {
    kind: 'proxyforge-crawl-audit-insertion-evidence-package',
    schemaVersion: 1,
    generatedAt,
    requestedInsertionPointCount: request.insertionPoints.length,
    scopedInsertionPointCount: scopedInsertionPoints.length,
    auditedInsertionPointCount: summary.auditedInsertionPoints,
    duplicateMergedCount,
    outOfScopeSkippedCount,
    insertionTypeCounts,
    auditedInsertionPoints,
    checkCoverage,
    scopeGate,
    rawProbeSamples,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    summary: `Crawl audit package linked ${summary.auditedInsertionPoints}/${scopedInsertionPoints.length} scoped crawler insertion point(s), ${Object.keys(insertionTypeCounts).join('/')} insertion types, ${summary.totalRequests} scanner probe(s), ${duplicateMergedCount} duplicate merge(s), ${outOfScopeSkippedCount} out-of-scope skip(s), and ${operationalSecretSignals.length} operational secret signal(s).`,
    content: JSON.stringify(body, null, 2),
  };
}

function sanitizeActiveScanChecks(checks: ActiveScanCheckId[]) {
  return Array.from(new Set((checks ?? []).filter(isActiveScanCheckId)));
}

function isActiveScanCheckId(check: unknown): check is ActiveScanCheckId {
  return typeof check === 'string' && (ACTIVE_SCAN_BUILT_IN_CHECKS as string[]).includes(check);
}

function activeScanExecutedChecks(summary: ActiveScanSummary): ActiveScanCheckId[] {
  const checks = summary.exchanges.flatMap((exchange) => (
    exchange.tags
      .map((tag) => tag.match(/^check:(.+)$/)?.[1])
      .filter(isActiveScanCheckId)
  ));
  return Array.from(new Set(checks));
}

function activeScanOperationalSecretSignals(rawValues: string[]) {
  const raw = rawValues.join('\n');
  const signals = [
    /^authorization:\s*\S+/im.test(raw) ? 'authorization-header' : '',
    /^cookie:\s*\S+/im.test(raw) ? 'cookie-header' : '',
    /^x-api-key:\s*\S+/im.test(raw) ? 'x-api-key-header' : '',
    /bearer\s+[A-Za-z0-9._~+/=-]{6,}/i.test(raw) ? 'bearer-token' : '',
    /(?:token|secret|session|api[-_]?key|key)\s*[:= ]+[A-Za-z0-9._~+/=-]{6,}/i.test(raw) ? 'secret-like-material' : '',
    /\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/.test(raw) ? 'jwt-like-material' : '',
  ].filter(Boolean);
  return Array.from(new Set(signals)).sort();
}

function activeScanSummary(
  request: ActiveScanRequest,
  startedAt: Date,
  blocked: boolean,
  message: string,
  findings: ActiveScanFinding[],
  exchanges: HttpExchange[],
  suppressedFindings: ActiveScanSuppressedFinding[] = [],
  tuning: ActiveScanTuningMetadata = defaultActiveScanTuning(findings, suppressedFindings, 0),
): ActiveScanSummary {
  return {
    id: `active-scan-${startedAt.getTime()}-${Math.random().toString(16).slice(2)}`,
    targetUrl: request.targetUrl,
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    totalRequests: exchanges.length,
    blocked,
    message,
    findings,
    suppressedFindings,
    tuning,
    exchanges,
  };
}

function crawlAuditSummary(
  _request: CrawlAuditRequest,
  startedAt: Date,
  blocked: boolean,
  message: string,
  findings: ActiveScanFinding[],
  exchanges: HttpExchange[],
  auditedInsertionPoints: number,
  suppressedFindings: ActiveScanSuppressedFinding[] = [],
  tuning: ActiveScanTuningMetadata = defaultActiveScanTuning(findings, suppressedFindings, 0),
): CrawlAuditSummary {
  return {
    id: `crawl-audit-${startedAt.getTime()}-${Math.random().toString(16).slice(2)}`,
    targetUrl: 'crawl-insertion-points',
    startedAt: startedAt.toISOString(),
    completedAt: new Date().toISOString(),
    totalRequests: exchanges.length,
    blocked,
    message,
    findings,
    suppressedFindings,
    tuning,
    exchanges,
    auditedInsertionPoints,
  };
}

function tuneActiveScanFindings(findings: ActiveScanFinding[], exchanges: HttpExchange[]) {
  const exchangeById = new Map(exchanges.map((exchange) => [exchange.id, exchange]));
  const seen = new Set<string>();
  const tunedFindings: ActiveScanFinding[] = [];
  const suppressedFindings: ActiveScanSuppressedFinding[] = [];
  let dedupedFindingCount = 0;

  for (const finding of findings) {
    const exchange = finding.evidenceExchangeId ? exchangeById.get(finding.evidenceExchangeId) : undefined;
    const dedupeKey = finding.dedupeKey ?? `${finding.checkId}:${finding.host}:${finding.path}:${finding.title}`.toLowerCase();
    const suppressionReason = activeScanSuppressionReason(finding, exchange);
    if (seen.has(dedupeKey)) {
      dedupedFindingCount += 1;
      suppressedFindings.push(suppressedFinding(finding, 'duplicate-dedupe-key'));
      continue;
    }
    seen.add(dedupeKey);
    if (suppressionReason) {
      suppressedFindings.push(suppressedFinding(finding, suppressionReason));
      continue;
    }
    tunedFindings.push(finding);
  }

  return {
    findings: tunedFindings,
    suppressedFindings,
    tuning: defaultActiveScanTuning(tunedFindings, suppressedFindings, dedupedFindingCount),
  };
}

function defaultActiveScanTuning(
  findings: ActiveScanFinding[],
  suppressedFindings: ActiveScanSuppressedFinding[],
  dedupedFindingCount: number,
): ActiveScanTuningMetadata {
  return {
    profile: 'browser-app-calibration',
    falsePositiveControls: [
      'scope-gated-live-probes',
      'dedupe-by-check-host-path-title',
      'suppress-error-page-security-header-noise',
      'suppress-error-page-method-advertising-noise',
      'require-cors-origin-reflection-or-wildcard-credentials',
      'require-cache-key-reflection-evidence',
      'preserve-confidence-reason-per-finding',
    ],
    suppressedFindingCount: suppressedFindings.length,
    dedupedFindingCount,
    findingDedupeKeys: Array.from(new Set(findings.map((finding) => finding.dedupeKey).filter(Boolean) as string[])),
    calibrationNotes: [
      `${findings.length} finding${findings.length === 1 ? '' : 's'} retained after browser-app false-positive tuning.`,
      `${suppressedFindings.length} noisy signal${suppressedFindings.length === 1 ? '' : 's'} suppressed before issue promotion.`,
    ],
  };
}

function activeScanSuppressionReason(finding: ActiveScanFinding, exchange?: HttpExchange) {
  if (!exchange) return '';
  if (exchange.status >= 400 && finding.checkId === 'security-headers') {
    return 'error-response-security-header-noise';
  }
  if (exchange.status >= 400 && finding.checkId === 'method-options') {
    return 'error-response-method-advertising-noise';
  }
  if (finding.title === 'HTTPS response missing Strict-Transport-Security' && isLoopbackHost(exchange.host)) {
    return 'loopback-host-hsts-noise';
  }
  return '';
}

function suppressedFinding(finding: ActiveScanFinding, reason: string): ActiveScanSuppressedFinding {
  return {
    id: `suppressed-${finding.id}`,
    checkId: finding.checkId,
    title: finding.title,
    host: finding.host,
    path: finding.path,
    evidenceExchangeId: finding.evidenceExchangeId,
    dedupeKey: finding.dedupeKey,
    reason,
  };
}

function isLoopbackHost(host: string) {
  const withoutPort = host.split(':')[0].toLowerCase();
  return withoutPort === 'localhost' || withoutPort === '127.0.0.1' || withoutPort === '::1' || withoutPort.endsWith('.localhost');
}

function uniqueInsertionPoints(points: CrawlAuditInsertionPoint[]) {
  const seen = new Set<string>();
  const unique: CrawlAuditInsertionPoint[] = [];
  for (const point of points) {
    const target = safeParseUrl(point.url);
    if (!target) continue;
    const key = `${point.method}:${target.toString()}:${point.type}:${point.name}`;
    if (seen.has(key)) continue;
    seen.add(key);
    unique.push({ ...point, url: target.toString() });
  }
  return unique;
}

function renderInsertionPointRequest(point: CrawlAuditInsertionPoint, target: URL, sessionHeaders: Record<string, string> = {}) {
  const method = point.method.toUpperCase() || (point.type === 'form' ? 'POST' : 'GET');
  const requestTarget = new URL(target.toString());
  const headers: Record<string, string> = {
    host: target.host,
    'user-agent': 'ProxyForge Crawl Audit',
    accept: '*/*',
    'x-proxyforge-insertion-point': `${point.type}:${point.name}`,
  };
  for (const [name, value] of Object.entries(sessionHeaders)) {
    const normalizedName = normalizeProbeHeaderName(name);
    const normalizedValue = normalizeProbeHeaderValue(value);
    if (!normalizedName || !normalizedValue || isForbiddenProbeHeader(normalizedName)) continue;
    headers[normalizedName] = normalizedValue;
  }
  headers.host = target.host;
  headers['x-proxyforge-insertion-point'] = `${point.type}:${point.name}`;
  if (point.type === 'query') requestTarget.searchParams.set(point.name, 'proxyforge-audit');
  if (point.type === 'header') {
    const headerName = normalizeProbeHeaderName(point.name);
    if (headerName && !isForbiddenProbeHeader(headerName)) headers[headerName] = 'proxyforge-audit';
  }
  if (point.type === 'cookie') {
    const cookieName = point.name.replace(/[=;\r\n]/g, '').trim();
    if (cookieName) headers.cookie = [headers.cookie, `${cookieName}=proxyforge-audit`].filter(Boolean).join('; ');
  }
  const path = `${requestTarget.pathname}${requestTarget.search}` || '/';
  let contentType = 'application/x-www-form-urlencoded';
  let body = Buffer.alloc(0);
  if (method !== 'GET' && method !== 'HEAD') {
    if (point.type === 'json') {
      contentType = 'application/json';
      body = Buffer.from(JSON.stringify({ [point.name]: 'proxyforge-audit' }), 'utf8');
    } else if (point.type === 'graphql') {
      contentType = 'application/json';
      body = Buffer.from(JSON.stringify({
        query: 'query ProxyForgeAudit($value: String) { __typename }',
        variables: { [point.name.replace(/^variables\./, '') || 'value']: 'proxyforge-audit' },
      }), 'utf8');
    } else if (point.type === 'xml') {
      const tag = point.name.replace(/[^A-Za-z0-9_.:-]/g, '').split('@')[0] || 'probe';
      contentType = 'application/xml';
      body = Buffer.from(`<${tag}>proxyforge-audit</${tag}>`, 'utf8');
    } else if (point.type === 'multipart') {
      const boundary = `proxyforge-${hashString(`${point.id}:${point.name}`).slice(0, 12)}`;
      contentType = `multipart/form-data; boundary=${boundary}`;
      body = Buffer.from([
        `--${boundary}`,
        `Content-Disposition: form-data; name="${point.name.replace(/"/g, '')}"`,
        '',
        'proxyforge-audit',
        `--${boundary}--`,
        '',
      ].join('\r\n'), 'utf8');
    } else {
      body = Buffer.from(`${encodeURIComponent(point.name)}=proxyforge-audit`, 'utf8');
    }
  }

  if (body.length > 0) {
    headers['content-type'] = contentType;
    headers['content-length'] = body.length.toString();
  }

  return renderParsedRequest(method, path, headers, body);
}

function normalizeProbeHeaderName(name: string) {
  const trimmed = name.trim();
  if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(trimmed)) return '';
  return trimmed;
}

function normalizeProbeHeaderValue(value: unknown) {
  const text = String(value ?? '').trim();
  if (!text || /[\r\n]/.test(text)) return '';
  return text;
}

function isForbiddenProbeHeader(name: string) {
  return /^(host|content-length|transfer-encoding|connection|proxy-connection|proxy-authorization)$/i.test(name);
}

function hashString(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, '0');
}

function safeParseUrl(value: string) {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

function activeScanCheckLabel(check: ActiveScanCheckId) {
  const labels: Record<ActiveScanCheckId, string> = {
    'security-headers': 'security headers',
    'cors-origin': 'CORS origin',
    'cache-key': 'cache key',
    'method-options': 'OPTIONS method',
    'authz-diff': 'auth state diff',
    'jwt-claims': 'JWT claims',
    'graphql-introspection': 'GraphQL introspection',
    'oast-ssrf': 'OAST SSRF callback',
    'reflected-xss': 'reflected XSS',
    'sql-injection': 'SQL injection',
    'path-traversal': 'path traversal',
    'open-redirect': 'open redirect',
    'command-injection': 'command injection',
  };
  return labels[check];
}

function setProbeQueryParam(parsed: ReturnType<typeof parseRawRequest>, target: URL, name: string, value: string) {
  const probeUrl = new URL(parsed.path || `${target.pathname}${target.search}` || '/', target);
  probeUrl.searchParams.set(name, value);
  parsed.path = `${probeUrl.pathname}${probeUrl.search}`;
}

function forceGetQueryProbe(parsed: ReturnType<typeof parseRawRequest>, headers: Record<string, string | number | string[]>) {
  parsed.method = 'GET';
  parsed.body = Buffer.alloc(0);
  delete headers['content-type'];
  delete headers['Content-Type'];
  delete headers['content-length'];
  delete headers['Content-Length'];
}

function mutateActiveScanRequest(rawRequest: string, target: URL, check: ActiveScanCheckId, request?: ActiveScanRequest) {
  const parsed = parseRawRequest(rawRequest, target);
  const headers = { ...parsed.headers } as Record<string, string | number | string[]>;
  headers.host = target.host;
  headers['x-proxyforge-active-scan'] = check;

  if (check === 'cors-origin') {
    headers.origin = 'https://proxyforge.invalid';
    headers['access-control-request-method'] = parsed.method;
  }

  if (check === 'cache-key') {
    headers['x-forwarded-host'] = 'proxyforge.invalid';
    headers['x-original-url'] = '/proxyforge-cache-probe';
  }

  if (check === 'method-options') {
    parsed.method = 'OPTIONS';
    parsed.body = Buffer.alloc(0);
    delete headers['content-length'];
    headers['access-control-request-method'] = rawRequest.split(/\s+/)[0] || 'GET';
    headers.origin = `https://${target.hostname}`;
  }

  if (check === 'authz-diff') {
    headers['x-proxyforge-role'] = 'customer';
    headers['x-proxyforge-identity'] = 'low-privilege-comparison';
    headers['x-proxyforge-auth-state'] = 'downgraded';
    delete headers.authorization;
    delete headers.Authorization;
    delete headers.cookie;
    delete headers.Cookie;
    delete headers['x-api-key'];
    delete headers['X-API-Key'];
    delete headers['x-auth-token'];
    delete headers['X-Auth-Token'];
  }

  if (check === 'jwt-claims') {
    headers['x-proxyforge-token-audit'] = 'claims-only';
  }

  if (check === 'graphql-introspection') {
    parsed.method = 'POST';
    parsed.body = Buffer.from(JSON.stringify({ query: 'query ProxyForgeIntrospection { __schema { queryType { name } mutationType { name } types { name } } }' }), 'utf8');
    headers['content-type'] = 'application/json';
    headers['content-length'] = parsed.body.length.toString();
  }

  if (check === 'oast-ssrf') {
    forceGetQueryProbe(parsed, headers);
    const payloadUrl = request?.oastPayloadUrl?.trim() || 'http://127.0.0.1:1/proxyforge-oast-missing';
    setProbeQueryParam(parsed, target, 'url', payloadUrl);
    if (request?.oastPayloadToken) headers['x-proxyforge-oast-token'] = request.oastPayloadToken;
    if (request?.oastPayloadId) headers['x-proxyforge-oast-payload-id'] = request.oastPayloadId;
  }

  if (check === 'reflected-xss') {
    forceGetQueryProbe(parsed, headers);
    setProbeQueryParam(parsed, target, 'pf_xss', '<script>proxyforge_xss_probe</script>');
  }

  if (check === 'sql-injection') {
    forceGetQueryProbe(parsed, headers);
    setProbeQueryParam(parsed, target, 'pf_id', "' OR 'proxyforge_sql_probe'='proxyforge_sql_probe");
  }

  if (check === 'path-traversal') {
    forceGetQueryProbe(parsed, headers);
    setProbeQueryParam(parsed, target, 'file', '../../../../../../etc/passwd');
  }

  if (check === 'open-redirect') {
    forceGetQueryProbe(parsed, headers);
    setProbeQueryParam(parsed, target, 'next', 'https://proxyforge.invalid/redirect-proof');
  }

  if (check === 'command-injection') {
    forceGetQueryProbe(parsed, headers);
    setProbeQueryParam(parsed, target, 'cmd', ';id;echo proxyforge_command_probe');
  }

  return renderParsedRequest(parsed.method, parsed.path, headers, parsed.body);
}

function renderParsedRequest(method: string, path: string, headers: Record<string, string | number | string[]>, body: Buffer) {
  const lines = [`${method} ${path} HTTP/1.1`];
  for (const [key, value] of Object.entries(headers)) {
    if (/^content-length$/i.test(key) && body.length === 0) continue;
    lines.push(`${key}: ${Array.isArray(value) ? value.join(', ') : value}`);
  }
  return `${lines.join('\n')}\n\n${body.toString('utf8')}`;
}

function buildActiveScanFindings(check: ActiveScanCheckId, exchange: HttpExchange): ActiveScanFinding[] {
  if (exchange.status === 0) {
    return [{
      id: `finding-${exchange.id}-network`,
      checkId: check,
      title: 'Active scan probe failed before response',
      severity: 'info',
      confidence: 'firm',
      host: exchange.host,
      path: exchange.path,
      detail: exchange.notes,
      remediation: 'Confirm target reachability, proxy routing, and whether the selected request is still valid.',
      evidenceExchangeId: exchange.id,
    }];
  }

  const headers = parseResponseHeaders(exchange.responseRaw);
  const responseText = responseBodyText(exchange.responseRaw);
  const body = responseText.toLowerCase();
  const findings: ActiveScanFinding[] = [];

  if (check === 'security-headers') {
    if (exchange.mime.includes('html') && !headers.has('content-security-policy')) {
      findings.push(activeFinding(exchange, check, 'HTML response missing Content-Security-Policy', 'medium', 'firm', 'The baseline active replay returned HTML without a Content-Security-Policy header.', 'Define a restrictive Content-Security-Policy and tune it per application surface.'));
    }
    if ((exchange.mime.includes('javascript') || exchange.mime.includes('json')) && !headers.has('x-content-type-options')) {
      findings.push(activeFinding(exchange, check, 'Script or JSON response missing X-Content-Type-Options', 'low', 'firm', 'The active replay returned script or JSON content without X-Content-Type-Options: nosniff.', 'Serve active content with X-Content-Type-Options: nosniff.'));
    }
    if (exchange.url.startsWith('https://') && !headers.has('strict-transport-security')) {
      findings.push(activeFinding(exchange, check, 'HTTPS response missing Strict-Transport-Security', 'low', 'tentative', 'The active replay used HTTPS but the response did not advertise HSTS.', 'Set Strict-Transport-Security after validating HTTPS is enforced across the host.'));
    }
  }

  if (check === 'cors-origin') {
    const acao = headers.get('access-control-allow-origin') ?? '';
    const acac = headers.get('access-control-allow-credentials') ?? '';
    if (acao === 'https://proxyforge.invalid' || (acao === '*' && acac.toLowerCase() === 'true')) {
      findings.push(activeFinding(exchange, check, 'CORS policy trusts scanner-controlled origin', 'high', 'firm', `The CORS probe observed Access-Control-Allow-Origin: ${acao || 'missing'} with credentials ${acac || 'not set'}.`, 'Allow only trusted origins and avoid wildcard origins on credentialed responses.'));
    }
  }

  if (check === 'cache-key' && body.includes('proxyforge.invalid')) {
    findings.push(activeFinding(exchange, check, 'Untrusted cache-routing header reflected', 'medium', 'tentative', 'A cache/key probe header value was reflected in the response, which can indicate host header trust or cache poisoning exposure.', 'Validate forwarded host headers at the edge and avoid reflecting untrusted routing headers.'));
  }

  if (check === 'method-options') {
    const allow = headers.get('allow') ?? headers.get('access-control-allow-methods') ?? '';
    if (/delete|put|patch/i.test(allow)) {
      findings.push(activeFinding(exchange, check, 'OPTIONS response advertises state-changing methods', 'info', 'tentative', `The OPTIONS probe advertised methods: ${allow}.`, 'Confirm state-changing methods enforce authorization and CSRF protections per route.'));
    }
  }

  if (check === 'jwt-claims') {
    const jwtMatches = `${exchange.requestRaw}\n${exchange.responseRaw}`.match(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g) ?? [];
    const roleHints = /"?(?:role|roles|scope|scopes|permissions)"?\s*[:=]\s*"?[A-Za-z0-9_ .:-]*(?:admin|write|support|internal)/i.test(exchange.responseRaw);
    if (jwtMatches.length > 0 || roleHints) {
      findings.push(activeFinding(
        exchange,
        check,
        'Token or privileged claim material exposed',
        jwtMatches.length > 0 ? 'medium' : 'low',
        jwtMatches.length > 0 ? 'firm' : 'tentative',
        `The token audit observed ${jwtMatches.length} JWT-like value${jwtMatches.length === 1 ? '' : 's'}${roleHints ? ' and privileged role/scope hints' : ''} in request or response evidence.`,
        'Avoid exposing reusable bearer tokens or internal authorization claims to clients; scope tokens narrowly and redact them from responses and logs.',
      ));
    }
  }

  if (check === 'graphql-introspection') {
    if (/__schema|__type|querytype|mutationtype|subscriptiontype/i.test(exchange.responseRaw)) {
      findings.push(activeFinding(
        exchange,
        check,
        'GraphQL introspection data exposed',
        'medium',
        'firm',
        'The GraphQL introspection probe returned schema markers such as __schema, queryType, or mutationType.',
        'Disable introspection on production GraphQL endpoints unless explicitly required, and enforce authorization on schema discovery.',
      ));
    }
  }

  if (check === 'oast-ssrf') {
    const marker = headers.get('x-fixture-vulnerability') ?? '';
    const callbackUrl = extractJsonField(exchange.responseRaw, 'callbackUrl');
    const callbackStatus = extractJsonField(exchange.responseRaw, 'callbackStatus');
    const callbackEvidence = /ssrf-local-callback|callbackStatus|callbackUrl/i.test(exchange.responseRaw);
    if (/ssrf|callback/i.test(marker) || callbackEvidence) {
      findings.push(activeFinding(
        exchange,
        check,
        'Out-of-band callback was triggered',
        'high',
        'firm',
        [
          'The OAST active scan probe caused the target to request the scanner-controlled callback endpoint.',
          callbackStatus ? `Callback status ${callbackStatus}.` : '',
          callbackUrl ? `Callback endpoint ${callbackUrl}.` : '',
        ].filter(Boolean).join(' '),
        'Block server-side fetches to untrusted destinations and enforce allowlists, egress controls, and protocol restrictions on URL-consuming features.',
      ));
    }
  }

  if (check === 'reflected-xss' && /<script>\s*proxyforge_xss_probe\s*<\/script>/i.test(responseText)) {
    findings.push(activeFinding(
      exchange,
      check,
      'Reflected script payload returned unencoded',
      'high',
      'firm',
      'The reflected-XSS probe payload was returned in the response body without clear output encoding evidence.',
      'HTML-encode untrusted input by context, enforce template auto-escaping, and add a restrictive Content-Security-Policy as defense in depth.',
    ));
  }

  if (check === 'sql-injection' && /(sql syntax|mysql|postgres|sqlite|odbc|ora-\d+|unclosed quotation)/i.test(responseText)) {
    findings.push(activeFinding(
      exchange,
      check,
      'SQL injection probe exposed database error evidence',
      'high',
      /sql syntax|unclosed quotation/i.test(responseText) ? 'firm' : 'tentative',
      'The SQL injection probe returned database error markers or echoed the scanner-controlled SQL marker.',
      'Use parameterized queries, remove SQL error details from client responses, and validate query-shaping inputs server-side.',
    ));
  }

  if (check === 'path-traversal' && /(root:x:0:0|win\.ini|\[extensions\]|proxyforge_traversal_probe)/i.test(responseText)) {
    findings.push(activeFinding(
      exchange,
      check,
      'Path traversal probe reached file-like content',
      'high',
      /root:x:0:0|win\.ini|\[extensions\]/i.test(responseText) ? 'firm' : 'tentative',
      'The path traversal probe returned file-content markers after submitting a traversal sequence.',
      'Canonicalize requested paths before access checks, enforce an allowlisted base directory, and reject traversal sequences before file resolution.',
    ));
  }

  if (check === 'open-redirect') {
    const location = headers.get('location') ?? '';
    if (exchange.status >= 300 && exchange.status < 400 && /^https:\/\/proxyforge\.invalid\/redirect-proof/i.test(location)) {
      findings.push(activeFinding(
        exchange,
        check,
        'Open redirect accepts scanner-controlled destination',
        'medium',
        'firm',
        `The redirect probe observed scanner-controlled redirect evidence in Location: ${location}.`,
        'Permit redirects only to trusted relative paths or allowlisted origins, and bind post-auth redirects to server-side state.',
      ));
    }
  }

  if (check === 'command-injection' && /(uid=\d+|gid=\d+|proxyforge_command_probe|command output|sh:|bash:)/i.test(responseText)) {
    findings.push(activeFinding(
      exchange,
      check,
      'Command injection probe produced execution-like output',
      'critical',
      /uid=\d+|proxyforge_command_probe/i.test(responseText) ? 'firm' : 'tentative',
      'The command injection probe returned command-output markers or scanner-controlled command text.',
      'Avoid shell invocation with user-controlled input; use fixed argument arrays, strict allowlists, and isolated worker permissions.',
    ));
  }

  return findings;
}

function extractJsonField(rawResponse: string, field: string) {
  const body = responseBodyText(rawResponse);
  try {
    const parsed = JSON.parse(body) as Record<string, unknown>;
    const value = parsed[field];
    return typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' ? String(value) : '';
  } catch {
    const match = body.match(new RegExp(`"${field}"\\s*:\\s*"?([^",}]+)"?`, 'i'));
    return match?.[1] ?? '';
  }
}

function buildAuthStateFindings(baseline: HttpExchange, downgraded: HttpExchange): ActiveScanFinding[] {
  if (baseline.status === 0 || downgraded.status === 0) {
    return [activeFinding(
      downgraded,
      'authz-diff',
      'Authenticated state comparison incomplete',
      'info',
      'tentative',
      `Baseline status ${baseline.status}; downgraded status ${downgraded.status}. One comparison leg failed before a usable response was captured.`,
      'Confirm both identities can reach the route, then rerun the authorization comparison.',
    )];
  }
  const lengthDelta = Math.abs(baseline.length - downgraded.length);
  const sameStatus = baseline.status === downgraded.status;
  const sameShape = lengthDelta <= Math.max(32, Math.round(Math.max(baseline.length, downgraded.length) * 0.08));
  const privilegedMarker = /support_admin|finance_admin|internal|refunds\.write|admin/i.test(downgraded.responseRaw);
  const identicalBody = responseBodyText(baseline.responseRaw) === responseBodyText(downgraded.responseRaw);
  if (sameStatus && sameShape && identicalBody && !privilegedMarker) {
    return [];
  }
  if ((sameStatus && sameShape && baseline.status < 400) || privilegedMarker) {
    return [activeFinding(
      downgraded,
      'authz-diff',
      'Authenticated state comparison preserved privileged response',
      privilegedMarker ? 'high' : 'medium',
      privilegedMarker ? 'firm' : 'tentative',
      `Baseline ${baseline.status}/${baseline.length} bytes and low-privilege comparison ${downgraded.status}/${downgraded.length} bytes differed by ${lengthDelta} bytes${privilegedMarker ? '; privileged markers remained visible' : ''}.`,
      'Validate the route with distinct authorized identities and enforce object, role, and workflow authorization server-side.',
    )];
  }
  return [];
}

function responseBodyText(rawResponse: string) {
  const parts = rawResponse.split(/\r?\n\r?\n/);
  return parts.length > 1 ? parts.slice(1).join('\n\n').trim() : rawResponse.trim();
}

function activeFinding(
  exchange: HttpExchange,
  checkId: ActiveScanCheckId,
  title: string,
  severity: Severity,
  confidence: ActiveScanFinding['confidence'],
  detail: string,
  remediation: string,
): ActiveScanFinding {
  return {
    id: `finding-${exchange.id}-${checkId}-${Math.random().toString(16).slice(2)}`,
    checkId,
    title,
    severity,
    confidence,
    host: exchange.host,
    path: exchange.path,
    detail,
    remediation,
    evidenceExchangeId: exchange.id,
    dedupeKey: `${checkId}:${exchange.host}:${exchange.path}:${title}`.toLowerCase(),
    confidenceReason: `${confidence} confidence from ${activeScanCheckLabel(checkId)} evidence attached to ${exchange.id}.`,
  };
}

function parseResponseHeaders(rawResponse: string) {
  const normalized = rawResponse.replace(/\r\n/g, '\n');
  const [head] = normalized.split('\n\n');
  const headers = new Map<string, string>();
  for (const line of head.split('\n').slice(1)) {
    const separator = line.indexOf(':');
    if (separator === -1) continue;
    headers.set(line.slice(0, separator).trim().toLowerCase(), line.slice(separator + 1).trim());
  }
  return headers;
}

function delay(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

interface ParsedWebSocketFrame {
  opcode: number;
  payload: Buffer;
  rawFrame: Buffer;
}

class WebSocketFrameRouter {
  private buffer = Buffer.alloc(0);

  constructor(private readonly sink: (frame: ParsedWebSocketFrame) => void) {}

  push(chunk: Buffer) {
    this.buffer = Buffer.concat([this.buffer, chunk]);

    while (this.buffer.length >= 2) {
      const first = this.buffer[0];
      const second = this.buffer[1];
      const opcode = first & 0x0f;
      const masked = Boolean(second & 0x80);
      let length = second & 0x7f;
      let offset = 2;

      if (length === 126) {
        if (this.buffer.length < offset + 2) return;
        length = this.buffer.readUInt16BE(offset);
        offset += 2;
      } else if (length === 127) {
        if (this.buffer.length < offset + 8) return;
        const longLength = this.buffer.readBigUInt64BE(offset);
        if (longLength > BigInt(Number.MAX_SAFE_INTEGER)) {
          this.buffer = Buffer.alloc(0);
          return;
        }
        length = Number(longLength);
        offset += 8;
      }

      const maskLength = masked ? 4 : 0;
      const frameLength = offset + maskLength + length;
      if (this.buffer.length < frameLength) return;
      const rawFrame = Buffer.from(this.buffer.subarray(0, frameLength));

      const mask = masked ? this.buffer.subarray(offset, offset + 4) : undefined;
      offset += maskLength;
      const payload = Buffer.from(this.buffer.subarray(offset, offset + length));
      if (mask) {
        for (let index = 0; index < payload.length; index += 1) {
          payload[index] ^= mask[index % 4];
        }
      }

      this.sink({ opcode, payload, rawFrame });
      this.buffer = this.buffer.subarray(frameLength);
    }
  }
}

function encodeWebSocketFrame(payload: Buffer, opcode: number, masked: boolean) {
  const first = 0x80 | (opcode & 0x0f);
  const header: number[] = [first];

  if (payload.length < 126) {
    header.push((masked ? 0x80 : 0) | payload.length);
  } else if (payload.length <= 0xffff) {
    header.push((masked ? 0x80 : 0) | 126, (payload.length >> 8) & 0xff, payload.length & 0xff);
  } else {
    const length = BigInt(payload.length);
    header.push((masked ? 0x80 : 0) | 127);
    for (let shift = 56; shift >= 0; shift -= 8) {
      header.push(Number((length >> BigInt(shift)) & 0xffn));
    }
  }

  if (!masked) return Buffer.concat([Buffer.from(header), payload]);

  const mask = randomBytes(4);
  const encoded = Buffer.from(payload);
  for (let index = 0; index < encoded.length; index += 1) {
    encoded[index] ^= mask[index % 4];
  }

  return Buffer.concat([Buffer.from(header), mask, encoded]);
}

function webSocketOpcodeType(opcode: number): WebSocketMessage['type'] {
  if (opcode === 1) return 'text';
  if (opcode === 2) return 'binary';
  if (opcode === 8) return 'close';
  if (opcode === 9) return 'ping';
  if (opcode === 10) return 'pong';
  return 'other';
}

function webSocketPayloadPreview(frame: ParsedWebSocketFrame) {
  if (frame.opcode === 1) return frame.payload.toString('utf8').slice(0, MAX_CAPTURE_BYTES);
  return frame.payload.toString('hex').slice(0, MAX_CAPTURE_BYTES);
}

function webSocketPayloadEncoding(frame: ParsedWebSocketFrame): WebSocketMessage['payloadEncoding'] {
  return frame.opcode === 1 ? 'text' : 'hex';
}

function editableWebSocketPayloadToBuffer(payload: string, encoding: WebSocketMessage['payloadEncoding'] = 'text') {
  if (encoding === 'hex') {
    const cleaned = payload.replace(/[^a-fA-F0-9]/g, '');
    return Buffer.from(cleaned.length % 2 === 0 ? cleaned : `0${cleaned}`, 'hex');
  }
  if (encoding === 'base64') return Buffer.from(payload, 'base64');
  return Buffer.from(payload, 'utf8');
}

function safeUrl(value: string) {
  try {
    return new URL(value);
  } catch {
    return undefined;
  }
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}

function isAllowedHost(hostname: string, scopeAllowlist: string[]) {
  if (scopeAllowlist.length === 0) return false;
  const normalizedHost = hostname.toLowerCase();
  return scopeAllowlist.some((pattern) => {
    const normalizedPattern = pattern.trim().toLowerCase();
    if (!normalizedPattern) return false;
    if (normalizedPattern === '*') return true;
    if (normalizedPattern.startsWith('*.')) {
      const suffix = normalizedPattern.slice(1);
      return normalizedHost.endsWith(suffix) || normalizedHost === normalizedPattern.slice(2);
    }
    return normalizedHost === normalizedPattern;
  });
}
