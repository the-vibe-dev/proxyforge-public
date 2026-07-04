import type {
  ActiveScanCheckId,
  HttpExchange,
  Issue,
  ScannerEvidenceDelta,
  ScannerRetestOutcome,
  ScannerRetestWorkflow,
  Severity,
} from './types';

export interface ScannerRetestRequestEdit {
  field: string;
  before?: string;
  after?: string;
  reason: string;
}

export interface ScannerRetestEvidenceDeltaRequest {
  issue: Issue;
  baselineExchange: HttpExchange;
  retestExchange?: HttpExchange;
  previousRetests?: ScannerRetestWorkflow[];
  evidenceDeltas?: ScannerEvidenceDelta[];
  checkIds?: ActiveScanCheckId[];
  checkPackId?: string;
  scopeAllowlist?: string[];
  throttleMs?: number;
  maxRequests?: number;
  sessionProfileName?: string;
  operator?: string;
  runnerPolicyId?: string;
  requestEdits?: ScannerRetestRequestEdit[];
  outcomeOverride?: ScannerRetestOutcome;
  startedAt?: string;
  completedAt?: string;
  now?: string;
}

export interface ScannerRetestEvidenceDeltaPackage {
  id: string;
  kind: 'proxyforge-scanner-retest-evidence-delta-package';
  schemaVersion: 1;
  generatedAt: string;
  issue: {
    id: string;
    title: string;
    host: string;
    path: string;
    severity: Severity;
    confidence: Issue['confidence'];
    status: Issue['status'];
  };
  workflow: ScannerRetestWorkflow;
  comparison: {
    baselineStatus: number;
    retestStatus?: number;
    statusChanged: boolean;
    bodyLengthDelta: number;
    bodyDigestChanged: boolean;
    evidenceDelta: 'fixed' | 'regressed' | 'still-present' | 'inconclusive' | 'blocked';
    reason: string;
  };
  outcomeCoverage: Partial<Record<ScannerRetestOutcome, number>>;
  controls: {
    checkPackId: string;
    checkIds: ActiveScanCheckId[];
    scopeAllowlist: string[];
    throttleMs: number;
    maxRequests: number;
    sessionProfileName?: string;
    operator: string;
    runnerPolicyId: string;
    requestEdits: ScannerRetestRequestEdit[];
  };
  reportAttachments: Array<{
    id: string;
    kind: 'baseline-proof' | 'retest-proof' | 'evidence-delta' | 'previous-retest';
    artifactId: string;
    reportReady: boolean;
    redactionPhase: 'report-export-only';
  }>;
  rawExchangeSamples: Array<{
    id: string;
    method: string;
    host: string;
    path: string;
    status: number;
    source: HttpExchange['source'];
    tags: string[];
    requestRaw: string;
    responseRaw: string;
  }>;
  operationalSecretSignals: string[];
  requirements: {
    issueLinked: boolean;
    baselineExchangePreserved: boolean;
    retestExchangePreserved: boolean;
    originalProofReplayed: boolean;
    outcomeClassified: boolean;
    fixedRegressedStillVulnerableInconclusiveCovered: boolean;
    runnerControlsPreserved: boolean;
    requestEditsPreserved: boolean;
    evidenceDeltaComputed: boolean;
    reportAttachmentsLinked: boolean;
    operationalSecretsPreserved: boolean;
    reportPhaseOnlyRedaction: boolean;
  };
  secretHandling: 'execution-full-fidelity-secrets-preserved';
  reportRedactionBoundary: 'redact-only-during-report-export';
  reportReady: true;
  summary: string;
  content: string;
}

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

export function buildScannerRetestWorkflow(request: ScannerRetestEvidenceDeltaRequest): ScannerRetestWorkflow {
  const now = request.now ?? new Date().toISOString();
  const outcome = classifyRetestOutcome(request);
  return {
    id: `scanner-retest-${simpleDigest(`${request.issue.id}|${request.baselineExchange.id}|${request.retestExchange?.id ?? 'missing'}|${outcome}`).slice(0, 12)}`,
    issueId: request.issue.id,
    issueTitle: request.issue.title,
    host: request.issue.host,
    path: request.issue.path,
    checkPackId: request.checkPackId ?? 'custom',
    checkCount: Math.max(1, request.checkIds?.length ?? 0),
    baselineStatus: request.issue.status,
    outcome,
    startedAt: request.startedAt ?? now,
    completedAt: request.completedAt ?? now,
    sessionProfileName: request.sessionProfileName,
    baselineExchangeId: request.baselineExchange.id,
    retestExchangeId: request.retestExchange?.id,
    evidenceDeltaId: `scanner-delta-${simpleDigest(`${request.issue.id}|${outcome}|${request.retestExchange?.responseRaw ?? ''}`).slice(0, 12)}`,
    summary: `${request.issue.title} retest classified as ${outcome} with baseline proof ${request.baselineExchange.id}${request.retestExchange ? ` and retest proof ${request.retestExchange.id}` : ''}.`,
  };
}

export function buildScannerRetestEvidenceDeltaPackage(request: ScannerRetestEvidenceDeltaRequest): ScannerRetestEvidenceDeltaPackage {
  const generatedAt = request.now ?? request.completedAt ?? new Date().toISOString();
  const workflow = buildScannerRetestWorkflow({ ...request, now: generatedAt });
  const baselineBody = bodyFromRaw(request.baselineExchange.responseRaw);
  const retestBody = request.retestExchange ? bodyFromRaw(request.retestExchange.responseRaw) : '';
  const comparison = buildRetestComparison(request, workflow.outcome, baselineBody, retestBody);
  const rawExchangeSamples = [request.baselineExchange, request.retestExchange]
    .filter((exchange): exchange is HttpExchange => Boolean(exchange))
    .map((exchange) => ({
      id: exchange.id,
      method: exchange.method,
      host: exchange.host,
      path: exchange.path,
      status: exchange.status,
      source: exchange.source,
      tags: exchange.tags,
      requestRaw: exchange.requestRaw,
      responseRaw: exchange.responseRaw,
    }));
  const operationalSecretSignals = scannerOperationalSecretSignals(
    ...rawExchangeSamples.flatMap((sample) => [sample.requestRaw, sample.responseRaw]),
  );
  const outcomeCoverage = countOutcomes([workflow, ...(request.previousRetests ?? [])]);
  const reportAttachments = [
    {
      id: `${request.baselineExchange.id}-baseline-proof`,
      kind: 'baseline-proof' as const,
      artifactId: request.baselineExchange.id,
      reportReady: true,
      redactionPhase: 'report-export-only' as const,
    },
    ...(request.retestExchange ? [{
      id: `${request.retestExchange.id}-retest-proof`,
      kind: 'retest-proof' as const,
      artifactId: request.retestExchange.id,
      reportReady: true,
      redactionPhase: 'report-export-only' as const,
    }] : []),
    {
      id: `${workflow.evidenceDeltaId ?? workflow.id}-evidence-delta`,
      kind: 'evidence-delta' as const,
      artifactId: workflow.evidenceDeltaId ?? workflow.id,
      reportReady: true,
      redactionPhase: 'report-export-only' as const,
    },
    ...(request.previousRetests ?? []).slice(0, 8).map((retest) => ({
      id: `${retest.id}-previous-retest`,
      kind: 'previous-retest' as const,
      artifactId: retest.evidenceDeltaId ?? retest.id,
      reportReady: true,
      redactionPhase: 'report-export-only' as const,
    })),
  ];
  const controls = {
    checkPackId: request.checkPackId ?? 'custom',
    checkIds: request.checkIds ?? [],
    scopeAllowlist: request.scopeAllowlist ?? [],
    throttleMs: request.throttleMs ?? 0,
    maxRequests: request.maxRequests ?? Math.max(1, request.checkIds?.length ?? 1),
    sessionProfileName: request.sessionProfileName,
    operator: request.operator ?? 'ProxyForge scanner verifier',
    runnerPolicyId: request.runnerPolicyId ?? 'project-safety-policy',
    requestEdits: request.requestEdits ?? [],
  };
  const requirements = {
    issueLinked: Boolean(request.issue.id && workflow.issueId === request.issue.id),
    baselineExchangePreserved: Boolean(request.baselineExchange.requestRaw.trim() && request.baselineExchange.responseRaw.trim()),
    retestExchangePreserved: Boolean(request.retestExchange?.requestRaw.trim() && request.retestExchange?.responseRaw.trim()),
    originalProofReplayed: Boolean(request.retestExchange && sameProofRoute(request.baselineExchange, request.retestExchange)),
    outcomeClassified: ['fixed', 'regressed', 'still-vulnerable', 'inconclusive', 'blocked'].includes(workflow.outcome),
    fixedRegressedStillVulnerableInconclusiveCovered: ['fixed', 'regressed', 'still-vulnerable', 'inconclusive'].every((outcome) => (outcomeCoverage[outcome as ScannerRetestOutcome] ?? 0) > 0),
    runnerControlsPreserved: controls.checkIds.length > 0 && controls.scopeAllowlist.length > 0 && controls.maxRequests > 0 && Boolean(controls.operator && controls.runnerPolicyId),
    requestEditsPreserved: controls.requestEdits.length > 0,
    evidenceDeltaComputed: comparison.statusChanged || comparison.bodyDigestChanged || comparison.bodyLengthDelta !== 0,
    reportAttachmentsLinked: reportAttachments.length >= 3 && reportAttachments.every((attachment) => attachment.reportReady && attachment.redactionPhase === 'report-export-only'),
    operationalSecretsPreserved: operationalSecretSignals.length > 0,
    reportPhaseOnlyRedaction: true,
  };
  const body = {
    kind: 'proxyforge-scanner-retest-evidence-delta-package',
    schemaVersion: 1,
    generatedAt,
    issue: {
      id: request.issue.id,
      title: request.issue.title,
      host: request.issue.host,
      path: request.issue.path,
      severity: request.issue.severity,
      confidence: request.issue.confidence,
      status: request.issue.status,
    },
    workflow,
    comparison,
    outcomeCoverage,
    controls,
    priorEvidenceDeltaIds: (request.evidenceDeltas ?? []).map((delta) => delta.id),
    rawExchangeSamples,
    operationalSecretSignals,
    reportAttachments,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
  };
  const content = JSON.stringify(body, null, 2);
  const packageId = `scanner-retest-evidence-${simpleDigest(content).slice(0, 12)}`;
  return {
    id: packageId,
    kind: 'proxyforge-scanner-retest-evidence-delta-package',
    schemaVersion: 1,
    generatedAt,
    issue: body.issue,
    workflow,
    comparison,
    outcomeCoverage,
    controls,
    reportAttachments,
    rawExchangeSamples,
    operationalSecretSignals,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: true,
    summary: `Scanner retest package classified ${request.issue.title} as ${workflow.outcome}, linked baseline/retest raw proof, preserved ${operationalSecretSignals.length} operational secret signal(s), and recorded ${Object.keys(outcomeCoverage).length} outcome class(es) for report-ready deltas.`,
    content,
  };
}

function classifyRetestOutcome(request: ScannerRetestEvidenceDeltaRequest): ScannerRetestOutcome {
  if (request.outcomeOverride) return request.outcomeOverride;
  const retest = request.retestExchange;
  if (!retest) return 'inconclusive';
  const haystack = `${retest.responseRaw}\n${retest.notes}\n${retest.tags.join(' ')}`;
  if (retest.tags.some((tag) => /blocked|scope-blocked|policy-blocked/i.test(tag)) || retest.status === 0) return 'blocked';
  if (retest.status >= 500 || /timeout|upstream error|inconclusive/i.test(haystack)) return 'inconclusive';
  const fixedSignal = retest.status === 401
    || retest.status === 403
    || retest.status === 404
    || retest.status === 410
    || /fixed|remediation validated|missing_permission|forbidden|unauthorized|not found/i.test(haystack);
  const presentSignal = (retest.status >= 200 && retest.status < 300)
    || /approved|support_admin|refundId|__schema|role":"admin|vulnerable|finding returned/i.test(haystack);
  if (request.issue.status === 'fixed' && presentSignal) return 'regressed';
  if (fixedSignal) return 'fixed';
  if (presentSignal) return 'still-vulnerable';
  return 'inconclusive';
}

function buildRetestComparison(
  request: ScannerRetestEvidenceDeltaRequest,
  outcome: ScannerRetestOutcome,
  baselineBody: string,
  retestBody: string,
) {
  const retestStatus = request.retestExchange?.status;
  const reason = outcome === 'fixed'
    ? 'Retest response no longer reproduces the original proof signal.'
    : outcome === 'regressed'
      ? 'Previously fixed issue reproduced during retest.'
      : outcome === 'still-vulnerable'
        ? 'Retest still returns a vulnerable proof response.'
        : outcome === 'blocked'
          ? 'Retest was blocked by scope, policy, or transport.'
          : 'Retest did not produce enough signal to close or reopen the finding.';
  return {
    baselineStatus: request.baselineExchange.status,
    retestStatus,
    statusChanged: retestStatus !== undefined && retestStatus !== request.baselineExchange.status,
    bodyLengthDelta: retestBody.length - baselineBody.length,
    bodyDigestChanged: Boolean(request.retestExchange) && simpleDigest(baselineBody) !== simpleDigest(retestBody),
    evidenceDelta: outcome === 'still-vulnerable' ? 'still-present' as const : outcome,
    reason,
  };
}

function countOutcomes(workflows: ScannerRetestWorkflow[]) {
  return workflows.reduce<Partial<Record<ScannerRetestOutcome, number>>>((memo, workflow) => ({
    ...memo,
    [workflow.outcome]: (memo[workflow.outcome] ?? 0) + 1,
  }), {});
}

function sameProofRoute(a: HttpExchange, b: HttpExchange) {
  return a.method.toUpperCase() === b.method.toUpperCase()
    && a.host.toLowerCase() === b.host.toLowerCase()
    && normalizePath(a.path) === normalizePath(b.path);
}

function normalizePath(value: string) {
  return value.split('?', 1)[0] || '/';
}

function bodyFromRaw(raw: string) {
  return raw.split(/\r?\n\r?\n/).slice(1).join('\n\n');
}

function scannerOperationalSecretSignals(...rawValues: string[]) {
  const text = rawValues.join('\n');
  const signals: string[] = [];
  if (/^authorization:\s*\S+/im.test(text)) signals.push('authorization-header');
  if (/^cookie:\s*\S+/im.test(text)) signals.push('cookie-header');
  if (/^x-api-key:\s*\S+/im.test(text)) signals.push('x-api-key-header');
  if (/^idempotency-key:\s*\S+/im.test(text)) signals.push('idempotency-key-header');
  if (/(bearer\s+[a-z0-9._~+/=-]+|api[_-]?key|access[_-]?token|refresh[_-]?token|secret|session=|eyJ[a-z0-9_-]+\.)/i.test(text)) {
    signals.push('secret-like-material');
  }
  return Array.from(new Set(signals));
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
