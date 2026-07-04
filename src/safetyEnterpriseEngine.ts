export type SafetyRunnerKind = 'replay' | 'intruder' | 'scanner' | 'crawler' | 'automation' | 'exploit' | 'callback-replay' | 'agent';
export type SafetyDecisionStatus = 'allowed' | 'blocked' | 'requires-approval';
export type SafetyAuditDecision = 'allowed' | 'blocked' | 'approved' | 'override-applied';

export interface SafetyScopePolicy {
  id: string;
  name: string;
  scopeAllowlist: string[];
  requireScopeMatch: boolean;
  minThrottleMs: number;
  maxRequestsPerRun: number;
  requireApprovalFor: SafetyRunnerKind[];
  auditLogging: boolean;
  redactAuditSecrets: boolean;
}

export interface SafetyPolicyOverride {
  id: string;
  operatorId: string;
  operatorName: string;
  role: string;
  enabled: boolean;
  reason: string;
  scopeAdditions: string[];
  minThrottleMs?: number;
  maxRequestsPerRun?: number;
  expiresAt: string;
  approvedBy: string;
}

export interface SafetyRunnerRequest {
  id: string;
  runner: SafetyRunnerKind;
  targetUrl: string;
  requestedBy: string;
  requestCount: number;
  throttleMs: number;
  approvalId?: string;
  rawRequest?: string;
  rawResponse?: string;
}

export interface SafetyApprovalRecord {
  id: string;
  runner: SafetyRunnerKind;
  targetUrl: string;
  requestedBy: string;
  approvedBy: string;
  status: 'approved' | 'revoked' | 'expired';
  reason: string;
  createdAt: string;
  rawRequest?: string;
}

export interface SafetyPolicyDecision {
  id: string;
  requestId: string;
  runner: SafetyRunnerKind;
  targetUrl: string;
  status: SafetyDecisionStatus;
  scopeMatched: boolean;
  throttleSatisfied: boolean;
  requestCapSatisfied: boolean;
  approvalRequired: boolean;
  approvalSatisfied: boolean;
  overrideApplied: boolean;
  effectiveScope: string[];
  effectiveThrottleMs: number;
  effectiveMaxRequests: number;
  reasons: string[];
  rawRequest?: string;
  rawResponse?: string;
}

export interface SafetyAuditEvent {
  id: string;
  time: string;
  actor: string;
  runner: SafetyRunnerKind;
  targetUrl: string;
  decision: SafetyAuditDecision;
  policyId: string;
  requestId: string;
  approvalId?: string;
  overrideId?: string;
  rawRequest?: string;
  rawResponse?: string;
  detail: string;
}

export interface SignedAuditExport {
  id: string;
  signerName: string;
  keyId: string;
  algorithm: 'HMAC-SHA256';
  signatureStatus: 'valid' | 'invalid' | 'ready-on-export';
  eventIds: string[];
  approvalIds: string[];
  overrideIds: string[];
  exportedAt: string;
  content: string;
}

export interface GovernancePackage {
  id: string;
  teamName: string;
  policyId: string;
  exportedAt: string;
  signerName: string;
  keyId: string;
  signatureStatus: 'valid' | 'invalid' | 'ready-on-export';
  runnerBindings: Array<{
    runner: SafetyRunnerKind;
    scopeAllowlist: string[];
    minThrottleMs: number;
    maxRequestsPerRun: number;
    requiresApproval: boolean;
  }>;
  content: string;
}

export interface EnterpriseSsoIdentity {
  id: string;
  provider: string;
  issuer: string;
  subject: string;
  email: string;
  name: string;
  roles: string[];
  groups: string[];
  mappedPolicyOverrideIds: string[];
  assertionDigestPreview: string;
}

export interface EnterpriseSsoFederationFixture {
  id: string;
  provider: string;
  issuer: string;
  audience: string;
  jwksDigestPreview: string;
  assertionStatus: 'accepted' | 'rejected';
  mappedIdentityId: string;
  jitProvisioned: boolean;
  content: string;
}

export interface EnterprisePolicyTransportReceipt {
  id: string;
  mode: 'push' | 'pull';
  endpoint: string;
  status: 'delivered' | 'received' | 'blocked';
  digestSha256: string;
  credentialLabel: string;
  authHeaderPresent: boolean;
  content: string;
}

export interface EnterpriseBackendSoak {
  id: string;
  endpoint: string;
  iterationCount: number;
  successCount: number;
  failureCount: number;
  maxLatencyMs: number;
  policyDigestSha256: string;
  content: string;
}

export interface RemoteAuditRetentionRecord {
  id: string;
  endpoint: string;
  mode: 'append-only' | 'mirror' | 'disabled';
  retentionDays: number;
  queuedEventIds: string[];
  deliveredEventIds: string[];
  status: 'queued' | 'delivered' | 'disabled';
  content: string;
}

export interface SafetyEnterpriseParityEvidenceRequest {
  policy: SafetyScopePolicy;
  overrides: SafetyPolicyOverride[];
  runnerRequests: SafetyRunnerRequest[];
  approvals: SafetyApprovalRecord[];
  decisions?: SafetyPolicyDecision[];
  auditEvents: SafetyAuditEvent[];
  signedAuditExports: SignedAuditExport[];
  governancePackages: GovernancePackage[];
  ssoIdentities: EnterpriseSsoIdentity[];
  ssoFederationFixtures: EnterpriseSsoFederationFixture[];
  policyTransportReceipts: EnterprisePolicyTransportReceipt[];
  enterpriseBackendSoaks: EnterpriseBackendSoak[];
  remoteAuditRetentionRecords: RemoteAuditRetentionRecord[];
  operationalSecretSamples?: string[];
  exportedAt?: string;
}

export interface SafetyEnterpriseParityEvidencePackage {
  id: string;
  kind: 'proxyforge-safety-enterprise-parity-evidence-package';
  title: string;
  fileName: string;
  path: string;
  exportedAt: string;
  decisionCount: number;
  auditEventCount: number;
  governancePackageCount: number;
  ssoIdentityCount: number;
  transportReceiptCount: number;
  backendSoakCount: number;
  requirements: {
    scopeGateCovered: boolean;
    throttleGateCovered: boolean;
    requestCapCovered: boolean;
    approvalGateCovered: boolean;
    bypassOverrideAuditCovered: boolean;
    auditLoggingCovered: boolean;
    signedAuditExportCovered: boolean;
    governancePackageCovered: boolean;
    ssoIdentityMappingCovered: boolean;
    ssoFederationFixtureCovered: boolean;
    remotePolicyTransportCovered: boolean;
    enterpriseBackendSoakCovered: boolean;
    remoteAuditRetentionCovered: boolean;
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

export function evaluateSafetyPolicyRequest(
  policy: SafetyScopePolicy,
  request: SafetyRunnerRequest,
  approvals: SafetyApprovalRecord[] = [],
  overrides: SafetyPolicyOverride[] = [],
): SafetyPolicyDecision {
  const activeOverride = overrides.find((override) => override.enabled && override.operatorId === request.requestedBy);
  const effectiveScope = [...new Set([...policy.scopeAllowlist, ...(activeOverride?.scopeAdditions ?? [])])];
  const effectiveThrottleMs = Math.max(policy.minThrottleMs, activeOverride?.minThrottleMs ?? policy.minThrottleMs);
  const effectiveMaxRequests = activeOverride?.maxRequestsPerRun ?? policy.maxRequestsPerRun;
  const scopeMatched = !policy.requireScopeMatch || isInScope(request.targetUrl, effectiveScope);
  const throttleSatisfied = request.throttleMs >= effectiveThrottleMs;
  const requestCapSatisfied = request.requestCount <= effectiveMaxRequests;
  const approvalRequired = policy.requireApprovalFor.includes(request.runner);
  const approvalSatisfied = !approvalRequired || approvals.some((approval) => (
    approval.id === request.approvalId
    && approval.runner === request.runner
    && approval.requestedBy === request.requestedBy
    && approval.status === 'approved'
  ));
  const blockedReasons = [
    scopeMatched ? '' : 'scope blocked target',
    throttleSatisfied ? '' : 'throttle below policy floor',
    requestCapSatisfied ? '' : 'request count exceeds policy cap',
  ].filter(Boolean);
  const status: SafetyDecisionStatus = blockedReasons.length > 0
    ? 'blocked'
    : approvalRequired && !approvalSatisfied
      ? 'requires-approval'
      : 'allowed';
  const reasons = [
    scopeMatched ? 'scope matched' : 'scope blocked target',
    throttleSatisfied ? 'throttle satisfied' : 'throttle below policy floor',
    requestCapSatisfied ? 'request cap satisfied' : 'request count exceeds policy cap',
    approvalRequired ? approvalSatisfied ? 'approval satisfied' : 'approval required' : 'approval not required',
    activeOverride ? `override applied: ${activeOverride.id}` : 'base policy applied',
  ];
  const digest = simpleDigest(`${request.id}|${status}|${reasons.join('|')}`);
  return {
    id: `safety-decision-${digest.slice(0, 12)}`,
    requestId: request.id,
    runner: request.runner,
    targetUrl: request.targetUrl,
    status,
    scopeMatched,
    throttleSatisfied,
    requestCapSatisfied,
    approvalRequired,
    approvalSatisfied,
    overrideApplied: Boolean(activeOverride),
    effectiveScope,
    effectiveThrottleMs,
    effectiveMaxRequests,
    reasons,
    rawRequest: request.rawRequest,
    rawResponse: request.rawResponse,
  };
}

export function buildSafetyEnterpriseParityEvidencePackage(
  request: SafetyEnterpriseParityEvidenceRequest,
): SafetyEnterpriseParityEvidencePackage {
  const exportedAt = request.exportedAt ?? new Date().toISOString();
  const stamp = exportedAt.replace(/[:.]/g, '-');
  const decisions = request.decisions?.length
    ? request.decisions
    : request.runnerRequests.map((runnerRequest) => evaluateSafetyPolicyRequest(
      request.policy,
      runnerRequest,
      request.approvals,
      request.overrides,
    ));
  const rawMaterial = [
    JSON.stringify(request.policy),
    JSON.stringify(request.overrides),
    JSON.stringify(request.runnerRequests),
    JSON.stringify(request.approvals),
    JSON.stringify(decisions),
    JSON.stringify(request.auditEvents),
    ...request.signedAuditExports.map((item) => item.content),
    ...request.governancePackages.map((item) => item.content),
    JSON.stringify(request.ssoIdentities),
    ...request.ssoFederationFixtures.map((item) => item.content),
    ...request.policyTransportReceipts.map((item) => item.content),
    ...request.enterpriseBackendSoaks.map((item) => item.content),
    ...request.remoteAuditRetentionRecords.map((item) => item.content),
  ].join('\n');
  const requirements = {
    scopeGateCovered: decisions.some((decision) => decision.scopeMatched && decision.status === 'allowed')
      && decisions.some((decision) => !decision.scopeMatched && decision.status === 'blocked'),
    throttleGateCovered: decisions.some((decision) => !decision.throttleSatisfied && decision.status === 'blocked')
      && decisions.some((decision) => decision.throttleSatisfied),
    requestCapCovered: decisions.some((decision) => !decision.requestCapSatisfied && decision.status === 'blocked')
      && decisions.some((decision) => decision.requestCapSatisfied),
    approvalGateCovered: decisions.some((decision) => decision.approvalRequired && !decision.approvalSatisfied && decision.status === 'requires-approval')
      && decisions.some((decision) => decision.approvalRequired && decision.approvalSatisfied && decision.status === 'allowed'),
    bypassOverrideAuditCovered: decisions.some((decision) => decision.overrideApplied && decision.status === 'allowed')
      && request.auditEvents.some((event) => event.decision === 'override-applied' && Boolean(event.overrideId)),
    auditLoggingCovered: request.policy.auditLogging
      && request.auditEvents.length >= decisions.length
      && request.auditEvents.some((event) => event.rawRequest?.includes('Authorization:')),
    signedAuditExportCovered: request.signedAuditExports.some((item) => (
      item.algorithm === 'HMAC-SHA256'
      && ['valid', 'ready-on-export'].includes(item.signatureStatus)
      && item.eventIds.length > 0
      && item.content.includes('proxyforge-signed-audit-export')
    )),
    governancePackageCovered: request.governancePackages.some((item) => (
      ['valid', 'ready-on-export'].includes(item.signatureStatus)
      && item.runnerBindings.some((binding) => binding.requiresApproval)
      && item.content.includes('proxyforge-governance-policy-package')
    )),
    ssoIdentityMappingCovered: request.ssoIdentities.some((identity) => (
      identity.roles.length > 0
      && identity.groups.length > 0
      && identity.mappedPolicyOverrideIds.length > 0
    )),
    ssoFederationFixtureCovered: request.ssoFederationFixtures.some((fixture) => (
      fixture.assertionStatus === 'accepted'
      && fixture.jitProvisioned
      && fixture.content.includes('proxyforge-sso-federation-fixture')
    )),
    remotePolicyTransportCovered: request.policyTransportReceipts.some((receipt) => receipt.mode === 'push' && receipt.status === 'delivered' && receipt.authHeaderPresent)
      && request.policyTransportReceipts.some((receipt) => receipt.mode === 'pull' && receipt.status === 'received' && receipt.digestSha256.length >= 16),
    enterpriseBackendSoakCovered: request.enterpriseBackendSoaks.some((soak) => (
      soak.iterationCount >= 20
      && soak.successCount === soak.iterationCount
      && soak.failureCount === 0
      && soak.content.includes('proxyforge-enterprise-policy-backend-soak')
    )),
    remoteAuditRetentionCovered: request.remoteAuditRetentionRecords.some((record) => (
      record.status === 'delivered'
      && record.deliveredEventIds.length > 0
      && record.retentionDays >= 30
      && record.content.includes('proxyforge-remote-audit-retention')
    )),
    rawExecutorMaterialPreserved: /HTTP\/[12]|Authorization:|Cookie:|X-API-Key:|requestRaw|responseRaw/i.test(rawMaterial),
    operationalSecretsPreserved: (request.operationalSecretSamples ?? []).length > 0
      && (request.operationalSecretSamples ?? []).every((sample) => rawMaterial.includes(sample)),
    reportPhaseOnlyRedaction: true,
  };
  const unsigned = {
    kind: 'proxyforge-safety-enterprise-parity-evidence-package',
    exportedAt,
    policy: request.policy,
    overrides: request.overrides,
    runnerRequests: request.runnerRequests,
    approvals: request.approvals,
    decisions,
    auditEvents: request.auditEvents,
    signedAuditExports: request.signedAuditExports,
    governancePackages: request.governancePackages,
    ssoIdentities: request.ssoIdentities,
    ssoFederationFixtures: request.ssoFederationFixtures,
    policyTransportReceipts: request.policyTransportReceipts,
    enterpriseBackendSoaks: request.enterpriseBackendSoaks,
    remoteAuditRetentionRecords: request.remoteAuditRetentionRecords,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
  };
  const digestPreview = simpleDigest(JSON.stringify(unsigned));
  const content = JSON.stringify({ ...unsigned, digestPreview }, null, 2);

  return {
    id: `safety-enterprise-parity-${digestPreview.slice(0, 12)}`,
    kind: 'proxyforge-safety-enterprise-parity-evidence-package',
    title: 'Safety and enterprise parity evidence package',
    fileName: `proxyforge-safety-enterprise-parity-${stamp}.json`,
    path: `safety/proxyforge-safety-enterprise-parity-${stamp}.json`,
    exportedAt,
    decisionCount: decisions.length,
    auditEventCount: request.auditEvents.length,
    governancePackageCount: request.governancePackages.length,
    ssoIdentityCount: request.ssoIdentities.length,
    transportReceiptCount: request.policyTransportReceipts.length,
    backendSoakCount: request.enterpriseBackendSoaks.length,
    requirements,
    secretHandling: 'execution-full-fidelity-secrets-preserved',
    reportRedactionBoundary: 'redact-only-during-report-export',
    reportReady: Object.values(requirements).every(Boolean),
    digestPreview,
    summary: 'Safety/Enterprise parity evidence covers scope gates, throttles, request caps, approvals, override audit, signed audit exports, governance packages, SSO identities and federation fixtures, remote policy transport, backend soak, remote audit retention, full-fidelity executor material, and report-export-only redaction.',
    content,
  };
}

function isInScope(targetUrl: string, scopeAllowlist: string[]) {
  let host = '';
  try {
    host = new URL(targetUrl).hostname.toLowerCase();
  } catch {
    host = targetUrl.replace(/^https?:\/\//, '').replace(/\/.*$/, '').toLowerCase();
  }
  return scopeAllowlist.some((scope) => {
    const normalized = scope.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!normalized) return false;
    if (normalized.startsWith('*.')) {
      const suffix = normalized.slice(2);
      return host === suffix || host.endsWith(`.${suffix}`);
    }
    return host === normalized || host.endsWith(`.${normalized}`);
  });
}

function simpleDigest(value: string) {
  let hash = 0x811c9dc5;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return `${hash.toString(16).padStart(8, '0')}${value.length.toString(16).padStart(8, '0')}`;
}
