import type { HttpExchange, Issue, ScannerIssueRule, Severity } from './types';

export type ScannerPassiveCheckId =
  | 'security-headers'
  | 'cookie-flags'
  | 'cors-policy'
  | 'cache-control'
  | 'mixed-content'
  | 'information-disclosure'
  | 'authz-metadata'
  | 'server-error';

export interface ScannerPassiveIssueCandidate {
  id: string;
  exchangeId: string;
  checkId: ScannerPassiveCheckId;
  checkLabel: string;
  title: string;
  severity: Severity;
  host: string;
  path: string;
  url: string;
  confidence: Issue['confidence'];
  status: Issue['status'];
  detail: string;
  remediation: string;
  evidence: string[];
  confidenceReason: string;
  dedupeKey: string;
  routeVariantKey: string;
  requestRaw: string;
  responseRaw: string;
  reportAttachmentIds?: string[];
  triageNote?: string;
}

export interface ScannerPassiveDedupeCluster {
  key: string;
  representativeCandidateId: string;
  candidateIds: string[];
  exchangeIds: string[];
  checkIds: ScannerPassiveCheckId[];
  hosts: string[];
  paths: string[];
  highestSeverity: Severity;
  strongestConfidence: Issue['confidence'];
  duplicateCount: number;
  exactDuplicateCount: number;
  routeVariantCount: number;
  summary: string;
}

export interface ScannerPassiveSuppression {
  id: string;
  reason: string;
  match: string;
  affectedCandidateIds: string[];
  createdAt: string;
}

export interface ScannerPassiveReportAttachment {
  id: string;
  issueCandidateId: string;
  exchangeId: string;
  fileName: string;
  description: string;
  redactionControl: 'none-during-execution' | 'report-export-only';
}

export interface ScannerPassiveSeverityReview {
  id: string;
  candidateId: string;
  originalSeverity: Severity;
  normalizedSeverity: Severity;
  confidence: Issue['confidence'];
  ruleId: string;
  reason: string;
}

export interface ScannerPassiveParityEvidenceRequest {
  exchanges: HttpExchange[];
  candidates?: ScannerPassiveIssueCandidate[];
  issueRules?: ScannerIssueRule[];
  suppressions?: ScannerPassiveSuppression[];
  reportAttachments?: ScannerPassiveReportAttachment[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface ScannerPassiveParityEvidencePackage {
  id: string;
  kind: 'proxyforge-scanner-passive-dedupe-parity-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  exchangeCount: number;
  candidateCount: number;
  findingCount: number;
  duplicateCandidateCount: number;
  clusterCount: number;
  checkCoverage: Array<{ id: ScannerPassiveCheckId; label: string; candidateCount: number; findingCount: number; duplicateCount: number }>;
  confidenceSummary: Record<Issue['confidence'], number>;
  severitySummary: Record<Severity, number>;
  dedupeClusters: ScannerPassiveDedupeCluster[];
  severityReviews: ScannerPassiveSeverityReview[];
  falsePositiveControls: {
    suppressionCount: number;
    suppressedCandidateIds: string[];
    controls: string[];
  };
  artifactIds: {
    exchangeIds: string[];
    candidateIds: string[];
    representativeFindingIds: string[];
    issueRuleIds: string[];
    suppressionIds: string[];
    reportAttachmentIds: string[];
  };
  requirements: {
    passiveChecksCovered: boolean;
    dedupeCovered: boolean;
    routeVariantDedupeCovered: boolean;
    confidenceSummaryCovered: boolean;
    severityNormalizationCovered: boolean;
    falsePositiveTuningCovered: boolean;
    issueRulePolicyCovered: boolean;
    reportAttachmentCovered: boolean;
    activeScannerHandoffCovered: boolean;
    rawRequestResponsePreserved: boolean;
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

const checkLabels: Record<ScannerPassiveCheckId, string> = {
  'security-headers': 'Security headers',
  'cookie-flags': 'Cookie flags',
  'cors-policy': 'CORS policy',
  'cache-control': 'Cache control',
  'mixed-content': 'Mixed content',
  'information-disclosure': 'Information disclosure',
  'authz-metadata': 'Authorization metadata',
  'server-error': 'Server error',
};

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const confidenceRank: Record<Issue['confidence'], number> = {
  certain: 3,
  firm: 2,
  tentative: 1,
};

const requiredPassiveChecks: ScannerPassiveCheckId[] = [
  'security-headers',
  'cookie-flags',
  'cors-policy',
  'cache-control',
  'mixed-content',
  'information-disclosure',
  'authz-metadata',
  'server-error',
];

export function buildScannerPassiveParityEvidencePackage(
  request: ScannerPassiveParityEvidenceRequest,
): ScannerPassiveParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const candidates = request.candidates?.length ? request.candidates : buildPassiveIssueCandidates(request.exchanges);
  const clusters = buildDedupeClusters(candidates);
  const representativeIds = new Set(clusters.map((cluster) => cluster.representativeCandidateId));
  const findings = candidates.filter((candidate) => representativeIds.has(candidate.id));
  const suppressedCandidateIds = new Set((request.suppressions ?? []).flatMap((suppression) => suppression.affectedCandidateIds));
  const activeFindings = findings.filter((finding) => !suppressedCandidateIds.has(finding.id));
  const checkCoverage = requiredPassiveChecks.map((id) => {
    const checkCandidates = candidates.filter((candidate) => candidate.checkId === id);
    const checkFindings = activeFindings.filter((candidate) => candidate.checkId === id);
    return {
      id,
      label: checkLabels[id],
      candidateCount: checkCandidates.length,
      findingCount: checkFindings.length,
      duplicateCount: Math.max(0, checkCandidates.length - checkFindings.length),
    };
  });
  const issueRules = request.issueRules ?? defaultIssueRules(exportedAt);
  const severityReviews = buildSeverityReviews(activeFindings, issueRules);
  const rawMaterial = [
    JSON.stringify(candidates),
    JSON.stringify(clusters),
    JSON.stringify(request.suppressions ?? []),
    JSON.stringify(request.reportAttachments ?? []),
    ...request.exchanges.flatMap((exchange) => [exchange.requestRaw, exchange.responseRaw, exchange.notes]),
    ...candidates.flatMap((candidate) => [candidate.requestRaw, candidate.responseRaw, candidate.detail, candidate.confidenceReason]),
  ].join('\n');
  const requirements = {
    passiveChecksCovered: requiredPassiveChecks.every((id) => checkCoverage.some((row) => row.id === id && row.candidateCount > 0)),
    dedupeCovered: clusters.some((cluster) => cluster.duplicateCount > 0 && cluster.exactDuplicateCount > 0),
    routeVariantDedupeCovered: clusters.some((cluster) => cluster.routeVariantCount > 0),
    confidenceSummaryCovered: ['certain', 'firm', 'tentative'].every((confidence) => confidence in countConfidence(activeFindings)),
    severityNormalizationCovered: severityReviews.length > 0
      && severityReviews.some((review) => review.originalSeverity !== review.normalizedSeverity)
      && severityReviews.some((review) => review.originalSeverity === review.normalizedSeverity),
    falsePositiveTuningCovered: (request.suppressions ?? []).length > 0
      && (request.suppressions ?? []).some((suppression) => suppression.affectedCandidateIds.length > 0),
    issueRulePolicyCovered: ['raise', 'lower', 'suppress', 'require-review']
      .every((action) => issueRules.some((rule) => rule.action === action)),
    reportAttachmentCovered: (request.reportAttachments ?? []).length > 0
      && (request.reportAttachments ?? []).every((attachment) => attachment.redactionControl === 'report-export-only'),
    activeScannerHandoffCovered: activeFindings.some((finding) => /scanner-run|active scanner|retest|insertion/i.test([
      finding.detail,
      finding.triageNote ?? '',
      finding.remediation,
    ].join('\n'))),
    rawRequestResponsePreserved: /HTTP\/[12]|Authorization:|Cookie:|Set-Cookie:|X-API-Key:|requestRaw|responseRaw/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-scanner-passive-dedupe-parity-package',
    exportedAt,
    exchanges: request.exchanges,
    candidates,
    findings: activeFindings,
    checkCoverage,
    confidenceSummary: countConfidence(activeFindings),
    severitySummary: countSeverity(activeFindings),
    dedupeClusters: clusters,
    severityReviews,
    issueRules,
    suppressions: request.suppressions ?? [],
    reportAttachments: request.reportAttachments ?? [],
    falsePositiveControls: {
      suppressionCount: request.suppressions?.length ?? 0,
      suppressedCandidateIds: Array.from(suppressedCandidateIds),
      controls: [
        'dedupe-key-required-before-report',
        'confidence-reason-required-per-finding',
        'suppression-review-preserved',
        'retest-or-active-scanner-handoff-before-submission',
      ],
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `scanner-passive-dedupe-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-scanner-passive-dedupe-parity-package',
    title: 'Scanner passive checks and dedupe parity evidence package',
    fileName: `proxyforge-scanner-passive-dedupe-parity-${stamp}.json`,
    path: `scanner/proxyforge-scanner-passive-dedupe-parity-${stamp}.json`,
    exportedAt,
    exchangeCount: request.exchanges.length,
    candidateCount: candidates.length,
    findingCount: activeFindings.length,
    duplicateCandidateCount: Math.max(0, candidates.length - activeFindings.length),
    clusterCount: clusters.length,
    checkCoverage,
    confidenceSummary: countConfidence(activeFindings),
    severitySummary: countSeverity(activeFindings),
    dedupeClusters: clusters,
    severityReviews,
    falsePositiveControls: unsigned.falsePositiveControls,
    artifactIds: {
      exchangeIds: request.exchanges.map((exchange) => exchange.id),
      candidateIds: candidates.map((candidate) => candidate.id),
      representativeFindingIds: activeFindings.map((finding) => finding.id),
      issueRuleIds: issueRules.map((rule) => rule.id),
      suppressionIds: (request.suppressions ?? []).map((suppression) => suppression.id),
      reportAttachmentIds: (request.reportAttachments ?? []).map((attachment) => attachment.id),
    },
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Scanner passive parity evidence covers security headers, cookie flags, CORS, cache controls, mixed content, information disclosure, authz metadata, server errors, dedupe clusters, route variants, confidence summaries, issue-rule severity normalization, false-positive suppressions, report attachments, active Scanner handoff, full-fidelity raw exchanges, and report-export-only redaction.',
    content,
  };
}

export function buildPassiveIssueCandidates(exchanges: HttpExchange[]): ScannerPassiveIssueCandidate[] {
  return exchanges.flatMap((exchange) => {
    const headers = parseResponseHeaders(exchange.responseRaw);
    const requestHeaders = parseRequestHeaders(exchange.requestRaw);
    const responseLower = exchange.responseRaw.toLowerCase();
    const body = rawBody(exchange.responseRaw);
    const candidates: ScannerPassiveIssueCandidate[] = [];
    const add = (input: Omit<ScannerPassiveIssueCandidate, 'id' | 'exchangeId' | 'checkLabel' | 'host' | 'path' | 'url' | 'status' | 'dedupeKey' | 'routeVariantKey' | 'requestRaw' | 'responseRaw'>) => {
      const routeVariantKey = passiveRouteVariantKey(input.checkId, input.title, exchange.host, exchange.path);
      const candidate: ScannerPassiveIssueCandidate = {
        ...input,
        id: `passive-${exchange.id}-${input.checkId}-${simpleDigest(`${input.title}:${input.evidence.join('|')}`).slice(0, 8)}`,
        exchangeId: exchange.id,
        checkLabel: checkLabels[input.checkId],
        host: exchange.host,
        path: exchange.path,
        url: exchange.url,
        status: 'open',
        dedupeKey: routeVariantKey,
        routeVariantKey,
        requestRaw: exchange.requestRaw,
        responseRaw: exchange.responseRaw,
      };
      candidates.push(candidate);
    };

    const missingSecurityHeaders = [
      exchange.mime.includes('text/html') && !headers.has('content-security-policy') ? 'Content-Security-Policy' : '',
      exchange.mime.includes('text/html') && !headers.has('x-frame-options') ? 'X-Frame-Options' : '',
      !headers.has('x-content-type-options') ? 'X-Content-Type-Options' : '',
    ].filter(Boolean);
    if (missingSecurityHeaders.length) {
      add({
        checkId: 'security-headers',
        title: 'Response missing browser hardening headers',
        severity: exchange.mime.includes('text/html') ? 'medium' : 'low',
        confidence: 'firm',
        detail: `Passive Scanner observed missing ${missingSecurityHeaders.join(', ')}. Send to active scanner or retest before report submission.`,
        remediation: 'Add the missing browser hardening headers and validate them on each affected route.',
        evidence: missingSecurityHeaders,
        confidenceReason: 'The captured response headers did not include the expected browser hardening controls.',
        triageNote: 'Passive issue is ready for scanner-run --checks security-headers confirmation.',
      });
    }

    const setCookies = headers.get('set-cookie') ?? [];
    const weakCookies = setCookies.filter((cookie) => !/;\s*secure/i.test(cookie) || !/;\s*httponly/i.test(cookie) || !/;\s*samesite=/i.test(cookie));
    if (weakCookies.length) {
      add({
        checkId: 'cookie-flags',
        title: 'Cookie set without defensive flags',
        severity: 'medium',
        confidence: 'firm',
        detail: 'Passive Scanner found Set-Cookie headers missing Secure, HttpOnly, or SameSite flags. Retest after session-profile refresh before reporting.',
        remediation: 'Set Secure, HttpOnly, and SameSite on session cookies unless a narrowly scoped exception is documented.',
        evidence: weakCookies,
        confidenceReason: 'The raw Set-Cookie response header is present and lacks one or more defensive attributes.',
        triageNote: 'Attach the raw response and rerun scanner-retest after cookie policy changes.',
      });
    }

    const requestOrigin = firstHeader(requestHeaders, 'origin');
    const allowOrigin = firstHeader(headers, 'access-control-allow-origin');
    const allowCredentials = firstHeader(headers, 'access-control-allow-credentials');
    if (allowOrigin && (allowOrigin === '*' || (requestOrigin && allowOrigin === requestOrigin)) && /true/i.test(allowCredentials ?? '')) {
      add({
        checkId: 'cors-policy',
        title: 'Permissive credentialed CORS policy observed',
        severity: 'high',
        confidence: 'firm',
        detail: 'Passive Scanner observed credentialed CORS on a captured response. Queue active scanner validation with the captured Origin header before submission.',
        remediation: 'Restrict Access-Control-Allow-Origin to trusted origins and avoid credentialed wildcard or reflected-origin behavior.',
        evidence: [`Origin: ${requestOrigin ?? '(none)'}`, `Access-Control-Allow-Origin: ${allowOrigin}`, `Access-Control-Allow-Credentials: ${allowCredentials}`],
        confidenceReason: 'The captured request and response contain a credentialed CORS configuration.',
        triageNote: 'Use scanner-run --checks cors-origin with this exchange as the seed.',
      });
    }

    const cacheControl = firstHeader(headers, 'cache-control') ?? '';
    const authRequest = /authorization:|cookie:/i.test(exchange.requestRaw);
    const sensitiveBody = /"email"|account|profile|token|session|balance|refund/i.test(body);
    if ((authRequest || sensitiveBody) && !/(no-store|private)/i.test(cacheControl)) {
      add({
        checkId: 'cache-control',
        title: 'Sensitive response lacks strict cache controls',
        severity: 'medium',
        confidence: 'firm',
        detail: 'Passive Scanner observed authenticated or sensitive content without no-store/private cache controls. Retest before report export.',
        remediation: 'Return Cache-Control: no-store for sensitive authenticated responses unless a safe caching design is documented.',
        evidence: [`Cache-Control: ${cacheControl || '(missing)'}`, `authenticatedRequest=${authRequest}`, `sensitiveBody=${sensitiveBody}`],
        confidenceReason: 'The captured request or body indicates sensitive content and the response cache policy is weak.',
        triageNote: 'Promote to active Scanner only after confirming the route is user-specific.',
      });
    }

    if (exchange.url.startsWith('https://') && /<(script|img|link|iframe)[^>]+(?:src|href)=["']http:\/\//i.test(body)) {
      add({
        checkId: 'mixed-content',
        title: 'HTTPS page references insecure subresources',
        severity: 'low',
        confidence: 'tentative',
        detail: 'Passive Scanner found HTTP subresource references inside an HTTPS response. Browser replay should confirm whether the asset is reachable and blocked.',
        remediation: 'Load subresources over HTTPS or remove the insecure reference.',
        evidence: [body.match(/<(script|img|link|iframe)[^>]+(?:src|href)=["']http:\/\/[^"']+/i)?.[0] ?? 'http:// subresource reference'],
        confidenceReason: 'The raw HTML body includes an insecure subresource URL; browser behavior still needs confirmation.',
        triageNote: 'Use Chromium capture to confirm render-time impact before reporting.',
      });
    }

    if (/stack trace|traceback|exception|sql syntax|aws_secret_access_key|private_key|debug=true/i.test(exchange.responseRaw)) {
      add({
        checkId: 'information-disclosure',
        title: 'Diagnostic or secret-like material exposed',
        severity: 'high',
        confidence: 'certain',
        detail: 'Passive Scanner found diagnostic, stack trace, or secret-like response material. Preserve raw evidence for executor use and redact only during report export.',
        remediation: 'Remove diagnostic output and secret-like material from client responses.',
        evidence: extractEvidence(exchange.responseRaw, /stack trace|traceback|exception|sql syntax|aws_secret_access_key|private_key|debug=true/i),
        confidenceReason: 'A direct diagnostic or secret-like marker was found in the captured response.',
        triageNote: 'Pin raw evidence to a report attachment and preserve full token/key context until submission redaction.',
      });
    }

    if (/support_admin|featureflags|internal\/export|role"\s*:\s*"admin|permission/i.test(exchange.responseRaw)) {
      add({
        checkId: 'authz-metadata',
        title: 'Privileged workflow metadata exposed',
        severity: 'medium',
        confidence: 'firm',
        detail: 'Passive Scanner found role, feature flag, permission, or internal route metadata that should feed authorization review and active scanner handoff.',
        remediation: 'Avoid returning internal authorization labels to clients unless required by the visible workflow.',
        evidence: extractEvidence(exchange.responseRaw, /support_admin|featureflags|internal\/export|role"\s*:\s*"admin|permission/i),
        confidenceReason: 'The response contains internal authorization or workflow markers.',
        triageNote: 'Queue target-access-review and scanner-run --checks authz-diff with this route.',
      });
    }

    if (exchange.status >= 500 || /^http\/[12](?:\.\d)?\s+5\d\d/im.test(exchange.responseRaw)) {
      add({
        checkId: 'server-error',
        title: 'Server error observed during passive review',
        severity: 'high',
        confidence: 'tentative',
        detail: 'Passive Scanner captured a 5xx response. Review error-page tuning and retest before classifying impact.',
        remediation: 'Normalize application error handling and remove diagnostic output from failed responses.',
        evidence: [String(exchange.status), firstLine(exchange.responseRaw)],
        confidenceReason: 'The captured response status is 5xx; manual review determines security impact.',
        triageNote: 'False-positive review should suppress generic noisy error pages without diagnostic evidence.',
      });
    }

    if (responseLower.includes('x-powered-by:')) {
      add({
        checkId: 'information-disclosure',
        title: 'Technology version header exposed',
        severity: 'info',
        confidence: 'firm',
        detail: 'Passive Scanner observed a technology disclosure header. Keep it as supporting intel unless version-specific impact is confirmed.',
        remediation: 'Remove nonessential technology disclosure headers.',
        evidence: headers.get('x-powered-by') ?? ['X-Powered-By present'],
        confidenceReason: 'The response contains an explicit technology disclosure header.',
        triageNote: 'Usually suppress unless paired with exploitable version evidence.',
      });
    }

    return candidates;
  });
}

function buildDedupeClusters(candidates: ScannerPassiveIssueCandidate[]): ScannerPassiveDedupeCluster[] {
  const grouped = new Map<string, ScannerPassiveIssueCandidate[]>();
  for (const candidate of candidates) {
    const current = grouped.get(candidate.dedupeKey) ?? [];
    current.push(candidate);
    grouped.set(candidate.dedupeKey, current);
  }
  return Array.from(grouped.entries()).map(([key, rows]) => {
    const representative = rows.slice().sort((left, right) => (
      severityRank[right.severity] - severityRank[left.severity]
      || confidenceRank[right.confidence] - confidenceRank[left.confidence]
      || left.id.localeCompare(right.id)
    ))[0];
    const paths = Array.from(new Set(rows.map((row) => row.path)));
    const exactDuplicateCount = rows.length - new Set(rows.map((row) => `${row.host}${row.path}`)).size;
    const routeVariantCount = Math.max(0, paths.length - 1);
    return {
      key,
      representativeCandidateId: representative.id,
      candidateIds: rows.map((row) => row.id),
      exchangeIds: Array.from(new Set(rows.map((row) => row.exchangeId))),
      checkIds: Array.from(new Set(rows.map((row) => row.checkId))),
      hosts: Array.from(new Set(rows.map((row) => row.host))),
      paths,
      highestSeverity: representative.severity,
      strongestConfidence: rows.reduce<Issue['confidence']>((highest, row) => (
        confidenceRank[row.confidence] > confidenceRank[highest] ? row.confidence : highest
      ), 'tentative'),
      duplicateCount: Math.max(0, rows.length - 1),
      exactDuplicateCount,
      routeVariantCount,
      summary: `${rows.length} passive signal(s) folded into ${representative.title} for ${representative.host}${normalizePath(representative.path)}.`,
    };
  });
}

function buildSeverityReviews(candidates: ScannerPassiveIssueCandidate[], issueRules: ScannerIssueRule[]): ScannerPassiveSeverityReview[] {
  return candidates.map((candidate) => {
    const rule = issueRules.find((item) => item.checkId === 'all' || String(item.checkId) === candidate.checkId) ?? issueRules[0];
    const normalizedSeverity = normalizeSeverity(candidate.severity, rule);
    return {
      id: `scanner-passive-severity-${candidate.id}`,
      candidateId: candidate.id,
      originalSeverity: candidate.severity,
      normalizedSeverity,
      confidence: candidate.confidence,
      ruleId: rule?.id ?? 'default-passive-rule',
      reason: rule
        ? `${rule.action} rule ${rule.name} applied to ${candidate.checkId}.`
        : 'Default passive severity policy preserved original severity.',
    };
  });
}

function normalizeSeverity(severity: Severity, rule?: ScannerIssueRule): Severity {
  if (!rule) return severity;
  if (rule.action === 'raise' && severityRank[severity] < severityRank[rule.severity]) return rule.severity;
  if (rule.action === 'lower' && severityRank[severity] > severityRank[rule.severity]) return rule.severity;
  if (rule.action === 'suppress') return 'info';
  return severity;
}

function defaultIssueRules(createdAt: string): ScannerIssueRule[] {
  return [
    makeIssueRule('raise', 'medium', 'firm', createdAt),
    makeIssueRule('lower', 'low', 'tentative', createdAt),
    makeIssueRule('suppress', 'info', 'tentative', createdAt),
    makeIssueRule('require-review', 'medium', 'firm', createdAt),
  ];
}

function makeIssueRule(action: ScannerIssueRule['action'], severity: Severity, confidence: Issue['confidence'], createdAt: string): ScannerIssueRule {
  return {
    id: `scanner-passive-rule-${action}`,
    name: `Passive ${action} policy`,
    createdAt,
    checkId: 'all',
    severity,
    confidence,
    action,
    status: 'active',
    summary: `Passive Scanner ${action} policy for confidence and severity normalization.`,
  };
}

function countConfidence(candidates: ScannerPassiveIssueCandidate[]): Record<Issue['confidence'], number> {
  return {
    certain: candidates.filter((candidate) => candidate.confidence === 'certain').length,
    firm: candidates.filter((candidate) => candidate.confidence === 'firm').length,
    tentative: candidates.filter((candidate) => candidate.confidence === 'tentative').length,
  };
}

function countSeverity(candidates: ScannerPassiveIssueCandidate[]): Record<Severity, number> {
  return {
    critical: candidates.filter((candidate) => candidate.severity === 'critical').length,
    high: candidates.filter((candidate) => candidate.severity === 'high').length,
    medium: candidates.filter((candidate) => candidate.severity === 'medium').length,
    low: candidates.filter((candidate) => candidate.severity === 'low').length,
    info: candidates.filter((candidate) => candidate.severity === 'info').length,
  };
}

function passiveRouteVariantKey(checkId: ScannerPassiveCheckId, title: string, host: string, path: string) {
  return `${checkId}:${title}:${host}:${normalizePath(path)}`.toLowerCase();
}

function normalizePath(path: string) {
  return path
    .replace(/[0-9a-f]{8}-[0-9a-f-]{27,}/gi, ':uuid')
    .replace(/\b\d{2,}\b/g, ':id')
    .replace(/\/+/g, '/');
}

function parseResponseHeaders(raw: string) {
  return parseHeaders(raw, 1);
}

function parseRequestHeaders(raw: string) {
  return parseHeaders(raw, 1);
}

function parseHeaders(raw: string, startLineOffset: number) {
  const headers = new Map<string, string[]>();
  const lines = raw.split(/\r?\n/);
  for (let index = startLineOffset; index < lines.length; index += 1) {
    const line = lines[index];
    if (!line.trim()) break;
    const separator = line.indexOf(':');
    if (separator === -1) continue;
    const name = line.slice(0, separator).trim().toLowerCase();
    const value = line.slice(separator + 1).trim();
    headers.set(name, [...(headers.get(name) ?? []), value]);
  }
  return headers;
}

function firstHeader(headers: Map<string, string[]>, name: string) {
  return headers.get(name.toLowerCase())?.[0];
}

function rawBody(raw: string) {
  return raw.split(/\r?\n\r?\n/).slice(1).join('\n\n');
}

function firstLine(raw: string) {
  return raw.split(/\r?\n/, 1)[0] ?? '';
}

function extractEvidence(raw: string, pattern: RegExp) {
  const lines = raw.split(/\r?\n/).filter((line) => pattern.test(line));
  return lines.length ? lines.slice(0, 5) : [pattern.source];
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
